"""
session_scanner.py
====================
세션/인증 취약점 자동 진단 도구 (진단 로직 + JSON 결과 저장까지 단일 파일로 처리)

sqli_scanner.py와 동일한 스키마를 사용합니다:
  vulnerability, status, risk, evidence, reason, recommendation,
  parameter, payload, confidence, tested_at

진단 항목 7개:
  1. check_cookie_flags        : 세션 쿠키 HttpOnly / Secure 속성 점검
  2. check_session_fixation    : 로그인 전/후 세션 ID가 재발급되는지 점검
  3. check_logout_invalidation : 로그아웃 후 이전 세션으로 재접근 가능한지 점검
  4. check_account_enumeration : 로그인 실패 메시지로 계정 존재 여부가 구분되는지 점검
  5. check_concurrent_login    : 같은 계정으로 세션 두 개를 동시에 로그인시켰을 때 둘 다 유효한지 점검
  6. check_cookie_expiry       : 세션 쿠키에 Max-Age/Expires가 설정돼 있는지 정적 점검 (참고용)
  7. check_idle_timeout        : [opt-in, --session-timeout-wait] 실제로 대기 후 세션 만료 여부 점검

실행 방법:
    python3 session_scanner.py 
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime
from typing import Optional

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


def _get_session_cookie(session: requests.Session, cookie_name: str):
    for c in session.cookies:
        if c.name == cookie_name:
            return c
    return None


# --------------------------------------------------------------------------- #
# 진단 로직
# --------------------------------------------------------------------------- #

def check_cookie_flags(session: requests.Session, login_url: str, id_param: str, pw_param: str,
                        valid_id: str, valid_pw: str, cookie_name: str = "PHPSESSID") -> dict:
    try:
        session.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability="세션 쿠키 보안 속성 (HttpOnly/Secure)",
            status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="로그인 요청 실패로 쿠키 확인 불가",
            recommendation="로그인 엔드포인트 확인 후 재점검 필요",
            parameter=cookie_name, payload=f"{id_param}={valid_id}, {pw_param}={valid_pw}",
            confidence="판단불가",
        )

    cookie = _get_session_cookie(session, cookie_name)
    if cookie is None:
        return make_result(
            vulnerability="세션 쿠키 보안 속성 (HttpOnly/Secure)",
            status="N/A", risk="중간",
            evidence=f"쿠키명 '{cookie_name}' 미발견",
            reason="설정한 세션 쿠키 이름이 실제 응답과 다를 수 있음",
            recommendation="실제 세션 쿠키 이름 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    missing = []
    if not cookie.has_nonstandard_attr("HttpOnly") and not cookie._rest.get("HttpOnly"):
        missing.append("HttpOnly")
    if not cookie.secure:
        missing.append("Secure")

    if missing:
        return make_result(
            vulnerability="세션 쿠키 보안 속성 (HttpOnly/Secure)",
            status="취약", risk="중간",
            evidence=f"세션 쿠키({cookie_name})에 {', '.join(missing)} 속성 미설정",
            reason="HttpOnly 미설정 시 XSS를 통한 세션 탈취 가능, Secure 미설정 시 평문(HTTP) 전송 중 탈취 가능",
            recommendation="세션 쿠키에 HttpOnly, Secure(HTTPS 환경) 속성 설정",
            parameter=cookie_name, payload=None, confidence="확정",
        )

    return make_result(
        vulnerability="세션 쿠키 보안 속성 (HttpOnly/Secure)",
        status="양호", risk="낮음",
        evidence=f"세션 쿠키({cookie_name})에 HttpOnly, Secure 속성 모두 설정됨",
        reason="쿠키 속성 점검 결과 문제 없음",
        recommendation="현재 상태 유지",
        parameter=cookie_name, payload=None, confidence="확정",
    )


def check_session_fixation(session: requests.Session, home_url: str, login_url: str, id_param: str,
                            pw_param: str, valid_id: str, valid_pw: str,
                            cookie_name: str = "PHPSESSID") -> dict:
    try:
        session.get(home_url, timeout=5)
        before = _get_session_cookie(session, cookie_name)
        before_val = before.value if before else None

        session.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
        after = _get_session_cookie(session, cookie_name)
        after_val = after.value if after else None
    except Exception as e:
        return make_result(
            vulnerability="세션 고정(Session Fixation)",
            status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="로그인 전/후 세션 값을 비교하는 중 오류 발생",
            recommendation="로그인 흐름 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    if before_val is None or after_val is None:
        return make_result(
            vulnerability="세션 고정(Session Fixation)",
            status="N/A", risk="중간",
            evidence=f"로그인 전 세션값={before_val}, 로그인 후 세션값={after_val}",
            reason="세션 쿠키를 확인할 수 없어 재발급 여부 판정 불가",
            recommendation="세션 쿠키 이름 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    if before_val == after_val:
        return make_result(
            vulnerability="세션 고정(Session Fixation)",
            status="취약", risk="중간",
            evidence=f"로그인 전/후 세션 ID 동일 (값: {before_val})",
            reason="로그인 성공 후에도 세션 ID가 재발급되지 않아, 공격자가 미리 심어둔 세션 ID를 피해자가 그대로 사용하게 되는 세션 고정 공격에 노출됨",
            recommendation="로그인 성공 시점에 반드시 새로운 세션 ID를 재발급(session regenerate)하도록 구현",
            parameter=cookie_name, payload=before_val, confidence="확정",
        )

    return make_result(
        vulnerability="세션 고정(Session Fixation)",
        status="양호", risk="낮음",
        evidence="로그인 전/후 세션 ID가 다르게 재발급됨",
        reason="세션 재발급이 정상적으로 이루어져 세션 고정 공격 불가",
        recommendation="현재 상태 유지",
        parameter=cookie_name, payload=None, confidence="확정",
    )


def check_logout_invalidation(session: requests.Session, login_url: str, logout_url: str, mypage_url: str,
                               id_param: str, pw_param: str, valid_id: str, valid_pw: str,
                               fail_indicator: str) -> dict:
    try:
        session.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
        session.get(logout_url, timeout=5)
        resp = session.get(mypage_url, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability="로그아웃 후 세션 무효화",
            status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="로그인-로그아웃-재접근 흐름 중 오류 발생",
            recommendation="관련 URL 확인 후 재점검 필요",
            parameter="session_cookie", payload=None, confidence="판단불가",
        )

    still_accessible = fail_indicator.lower() not in resp.text.lower()

    if still_accessible:
        return make_result(
            vulnerability="로그아웃 후 세션 무효화",
            status="취약", risk="높음",
            evidence=f"로그아웃 이후 동일 세션으로 마이페이지 재접근 시 정상 응답(status={resp.status_code}) 반환됨",
            reason="로그아웃 처리 시 서버 측 세션이 실제로 폐기되지 않아, 탈취된 세션이 로그아웃 이후에도 계속 유효함",
            recommendation="로그아웃 시 서버 측 세션 파기(session destroy) 및 클라이언트 쿠키 만료 처리",
            parameter="session_cookie", payload="로그아웃 후 재사용된 세션 쿠키", confidence="확정",
        )

    return make_result(
        vulnerability="로그아웃 후 세션 무효화",
        status="양호", risk="낮음",
        evidence=f"로그아웃 이후 동일 세션으로 재접근 시 '{fail_indicator}' 응답 확인",
        reason="로그아웃 시 세션이 정상적으로 무효화됨",
        recommendation="현재 상태 유지",
        parameter="session_cookie", payload=None, confidence="확정",
    )


def check_account_enumeration(session: requests.Session, login_url: str, id_param: str, pw_param: str,
                               valid_id: str, invalid_id: str = "no_such_user_9999") -> dict:
    try:
        resp_valid_id_wrong_pw = session.post(
            login_url, data={id_param: valid_id, pw_param: "wrong_pw_test"}, timeout=5
        )
        resp_invalid_id = session.post(
            login_url, data={id_param: invalid_id, pw_param: "wrong_pw_test"}, timeout=5
        )
    except Exception as e:
        return make_result(
            vulnerability="계정 존재 여부 노출 (Account Enumeration)",
            status="N/A", risk="낮음",
            evidence=f"요청 실패: {e}",
            reason="로그인 실패 응답 비교 중 오류 발생",
            recommendation="로그인 엔드포인트 확인 후 재점검 필요",
            parameter=id_param, payload=f"{valid_id} / {invalid_id}", confidence="판단불가",
        )

    if resp_valid_id_wrong_pw.text.strip() != resp_invalid_id.text.strip():
        return make_result(
            vulnerability="계정 존재 여부 노출 (Account Enumeration)",
            status="취약", risk="중간",
            evidence="존재하는 아이디+오답 비밀번호와 존재하지 않는 아이디의 로그인 실패 메시지가 서로 다름",
            reason="에러 메시지 차이로 공격자가 유효한 계정 아이디를 추정(brute-force 대상 확보)할 수 있음",
            recommendation="아이디/비밀번호 오류 메시지를 '아이디 또는 비밀번호가 올바르지 않습니다'로 통일",
            parameter=id_param, payload=f"{valid_id} / {invalid_id}", confidence="확정",
        )

    return make_result(
        vulnerability="계정 존재 여부 노출 (Account Enumeration)",
        status="양호", risk="낮음",
        evidence="존재하는 아이디와 존재하지 않는 아이디의 로그인 실패 메시지가 동일함",
        reason="에러 메시지로 계정 존재 여부를 구분할 수 없음",
        recommendation="현재 상태 유지",
        parameter=id_param, payload=f"{valid_id} / {invalid_id}", confidence="확정",
    )


def check_concurrent_login(base_url: str, login_url: str, mypage_url: str,
                            id_param: str, pw_param: str, valid_id: str, valid_pw: str) -> dict:
    """
    같은 계정으로 서로 다른 세션(브라우저 A/B에 해당) 두 개를 만들어 각각 로그인시킨 뒤,
    두 세션이 동시에 모두 유효한지 확인한다. 보통 "정책 문제"에 가까워 위험도는 낮음으로 잡되,
    탈취된 세션이 동시에 계속 쓰일 수 있다는 점에서 참고 항목으로 포함.
    """
    session_a = requests.Session()
    session_b = requests.Session()
    try:
        session_a.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
        session_b.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
        resp_a = session_a.get(mypage_url, timeout=5)
        resp_b = session_b.get(mypage_url, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability="동시 로그인 제한",
            status="N/A", risk="낮음",
            evidence=f"요청 실패: {e}",
            reason="두 세션의 로그인/접근 요청 중 오류 발생",
            recommendation="로그인 엔드포인트 확인 후 재점검 필요",
            parameter="session_cookie", payload=None, confidence="판단불가",
        )

    a_ok = resp_a.status_code == 200 and "로그인" not in resp_a.text
    b_ok = resp_b.status_code == 200 and "로그인" not in resp_b.text

    if a_ok and b_ok:
        return make_result(
            vulnerability="동시 로그인 제한",
            status="취약", risk="낮음",
            evidence="같은 계정으로 로그인한 두 개의 세션이 동시에 모두 유효한 상태로 마이페이지 접근 가능",
            reason="동시 로그인 제한이 없어, 계정 정보나 세션이 탈취됐을 때 정상 사용자가 이를 인지하기 더 어려움",
            recommendation="계정당 활성 세션 수 제한 또는 새 로그인 시 기존 세션 자동 만료 정책 적용 검토",
            parameter="session_cookie", payload=None, confidence="확정",
        )

    return make_result(
        vulnerability="동시 로그인 제한",
        status="양호", risk="낮음",
        evidence="두 번째 세션 로그인 시 기존 세션이 무효화되어 동시에는 하나의 세션만 유효함",
        reason="계정당 단일 세션 정책이 적용되어 있는 것으로 확인됨",
        recommendation="현재 상태 유지",
        parameter="session_cookie", payload=None, confidence="확정",
    )


def check_cookie_expiry(session: requests.Session, login_url: str, id_param: str, pw_param: str,
                         valid_id: str, valid_pw: str, cookie_name: str = "PHPSESSID") -> dict:
    """
    실제 타임아웃 시간만큼 기다리지 않고, 세션 쿠키에 Max-Age/Expires가 설정돼 있는지만
    정적으로 확인한다. 둘 다 없으면 "브라우저를 닫을 때까지" 또는 그 이상으로 세션이
    무기한 유지될 가능성이 있다는 뜻이라 참고 항목으로 포함 (실제 서버 측 만료 로직까지는 확인 불가).
    """
    try:
        session.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability="세션 쿠키 만료 시간 설정 (참고용, 실제 타임아웃 미검증)",
            status="N/A", risk="낮음",
            evidence=f"요청 실패: {e}",
            reason="로그인 요청 실패로 쿠키 확인 불가",
            recommendation="로그인 엔드포인트 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    cookie = _get_session_cookie(session, cookie_name)
    if cookie is None:
        return make_result(
            vulnerability="세션 쿠키 만료 시간 설정 (참고용, 실제 타임아웃 미검증)",
            status="N/A", risk="낮음",
            evidence=f"쿠키명 '{cookie_name}' 미발견",
            reason="설정한 세션 쿠키 이름이 실제 응답과 다를 수 있음",
            recommendation="실제 세션 쿠키 이름 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    has_expiry = cookie.expires is not None

    if not has_expiry:
        return make_result(
            vulnerability="세션 쿠키 만료 시간 설정 (참고용, 실제 타임아웃 미검증)",
            status="취약", risk="낮음",
            evidence=f"세션 쿠키({cookie_name})에 Max-Age/Expires가 설정되어 있지 않음 (세션 쿠키, 브라우저 종료 시까지 유지)",
            reason="쿠키 자체의 만료 시간이 없어 클라이언트 측에서는 세션이 무기한 유지될 수 있음. 단, 서버 측에서 별도로 idle timeout을 두는지는 이 진단만으로 확정할 수 없음",
            recommendation="세션 유휴시간(idle timeout)을 서버 측에서 강제하고, 필요 시 쿠키에도 적절한 Max-Age를 설정",
            parameter=cookie_name, payload=None, confidence="추정",  # 서버 측 idle timeout 여부는 미검증
        )

    return make_result(
        vulnerability="세션 쿠키 만료 시간 설정 (참고용, 실제 타임아웃 미검증)",
        status="양호", risk="낮음",
        evidence=f"세션 쿠키({cookie_name})에 만료 시간이 설정되어 있음",
        reason="쿠키에 만료 시간이 명시되어 있어 무기한 유지되지는 않음",
        recommendation="실제 서버 측 idle timeout 정책도 별도로 확인 권장",
        parameter=cookie_name, payload=None, confidence="추정",
    )


def check_idle_timeout(base_url: str, login_url: str, mypage_url: str,
                        id_param: str, pw_param: str, valid_id: str, valid_pw: str,
                        wait_seconds: int) -> dict:
    """
    [opt-in, --session-timeout-wait 초 만큼 실제로 대기] 로그인 후 지정한 시간만큼
    기다렸다가 같은 세션으로 마이페이지에 접근해 세션이 만료됐는지 실제로 확인한다.
    대기 시간이 스캔 전체 시간에 그대로 더해지므로 기본값은 비활성(0초=스킵).
    """
    if wait_seconds <= 0:
        return make_result(
            vulnerability="세션 유휴 타임아웃 (idle timeout)",
            status="N/A", risk="낮음",
            evidence="--session-timeout-wait 옵션이 지정되지 않아 실행하지 않음",
            reason="실제 타임아웃 시간만큼 대기해야 확인 가능한 항목이라 기본적으로 건너뜀",
            recommendation="--session-timeout-wait <초> 옵션으로 실제 정책 만료 시간(예: 1800)만큼 지정해 재점검 권장",
            parameter="session_cookie", payload=None, confidence="판단불가",
        )

    session = requests.Session()
    try:
        session.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
        time.sleep(wait_seconds)
        resp = session.get(mypage_url, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability="세션 유휴 타임아웃 (idle timeout)",
            status="N/A", risk="낮음",
            evidence=f"요청 실패: {e}",
            reason="로그인-대기-재접근 흐름 중 오류 발생",
            recommendation="관련 URL 확인 후 재점검 필요",
            parameter="session_cookie", payload=f"{wait_seconds}초 대기", confidence="판단불가",
        )

    still_accessible = resp.status_code == 200 and "로그인" not in resp.text

    if still_accessible:
        return make_result(
            vulnerability="세션 유휴 타임아웃 (idle timeout)",
            status="취약", risk="중간",
            evidence=f"{wait_seconds}초 동안 요청 없이 대기한 뒤에도 동일 세션으로 마이페이지 정상 접근됨",
            reason="지정한 대기 시간 동안 세션이 만료되지 않아, 자리를 비운 사용자의 세션이 계속 유효한 상태로 남음",
            recommendation="서버 측에 유휴시간 기반 세션 만료(idle timeout)를 설정",
            parameter="session_cookie", payload=f"{wait_seconds}초 대기", confidence="확정",
        )

    return make_result(
        vulnerability="세션 유휴 타임아웃 (idle timeout)",
        status="양호", risk="낮음",
        evidence=f"{wait_seconds}초 대기 후 동일 세션으로 재접근 시 로그인 필요 상태로 전환됨",
        reason="지정한 대기 시간 내에 세션이 정상적으로 만료됨",
        recommendation="현재 상태 유지",
        parameter="session_cookie", payload=f"{wait_seconds}초 대기", confidence="확정",
    )


def run_all(base_url: str, login_path: str, logout_path: str, mypage_path: str,
            id_param: str, pw_param: str, valid_id: str, valid_pw: str,
            logout_fail_indicator: str, cookie_name: str,
            session_timeout_wait: int = 0) -> list:
    base_url = base_url.rstrip("/")
    login_url = base_url + login_path
    logout_url = base_url + logout_path
    mypage_url = base_url + mypage_path
    home_url = base_url + "/"

    results = []

    s1 = requests.Session()
    results.append(check_cookie_flags(s1, login_url, id_param, pw_param, valid_id, valid_pw, cookie_name))

    s2 = requests.Session()
    results.append(check_session_fixation(s2, home_url, login_url, id_param, pw_param, valid_id, valid_pw, cookie_name))

    s3 = requests.Session()
    results.append(check_logout_invalidation(s3, login_url, logout_url, mypage_url, id_param, pw_param,
                                              valid_id, valid_pw, logout_fail_indicator))

    s4 = requests.Session()
    results.append(check_account_enumeration(s4, login_url, id_param, pw_param, valid_id))

    results.append(check_concurrent_login(base_url, login_url, mypage_url, id_param, pw_param, valid_id, valid_pw))

    s6 = requests.Session()
    results.append(check_cookie_expiry(s6, login_url, id_param, pw_param, valid_id, valid_pw, cookie_name))

    results.append(check_idle_timeout(base_url, login_url, mypage_url, id_param, pw_param,
                                       valid_id, valid_pw, session_timeout_wait))

    return results


# --------------------------------------------------------------------------- #
# CLI 진입점
# --------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(description="세션/인증 취약점 자동 진단 도구")
    parser.add_argument("--base-url", required=True,
                         help="진단 대상 base URL (필수). 예: http://localhost:8081")
    parser.add_argument("--login-path", default="/auth/login.php")
    parser.add_argument("--logout-path", default="/auth/logout.php")
    parser.add_argument("--mypage-path", default="/inquiry/my.php")
    parser.add_argument("--id-param", default="id")
    parser.add_argument("--pw-param", default="pw")
    parser.add_argument("--valid-id", default="test999")
    parser.add_argument("--valid-pw", default="test999")
    parser.add_argument("--logout-fail-indicator", default="로그인이 필요합니다",
                         help="세션 무효화 시 응답에 포함되는 문자열 (예: '로그인 해주세요')")
    parser.add_argument("--cookie-name", default="PHPSESSID")
    parser.add_argument("--session-timeout-wait", type=int, default=0,
                         help="[opt-in] 실제 idle timeout을 확인하기 위해 로그인 후 대기할 시간(초). "
                              "0(기본값)이면 이 항목은 건너뜀. 예: 정책상 30분이면 1800")
    parser.add_argument("--output", default="session_scan_result.json")
    args = parser.parse_args()

    print(f"🎯 진단 대상: {args.base_url}")

    if args.session_timeout_wait > 0:
        print(f"⏳ --session-timeout-wait 옵션으로 {args.session_timeout_wait}초 대기 후 확인합니다. 스캔이 그만큼 오래 걸립니다.")

    results = run_all(
        base_url=args.base_url,
        login_path=args.login_path,
        logout_path=args.logout_path,
        mypage_path=args.mypage_path,
        id_param=args.id_param,
        pw_param=args.pw_param,
        valid_id=args.valid_id,
        valid_pw=args.valid_pw,
        logout_fail_indicator=args.logout_fail_indicator,
        cookie_name=args.cookie_name,
        session_timeout_wait=args.session_timeout_wait,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"총 {len(results)}개 항목 진단 완료 -> {args.output} 저장")
    for r in results:
        print(f"- [{r['status']}/{r['risk']}/{r['confidence']}] {r['vulnerability']}")


if __name__ == "__main__":
    main()
