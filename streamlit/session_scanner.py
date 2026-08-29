"""
session_scanner.py
====================
세션/인증 취약점 자동 진단 도구
(진단 로직 + 생성형 AI 판정 + JSON 결과 저장까지 단일 파일)

sqli_scanner.py와 동일한 설계 원칙 + 스키마:
  - 상태 비교(로그인 전/후 세션ID, 쿠키 속성, 재접근 결과 등)는 코드가 직접 관찰한다.
  - 그 관찰 결과를 생성형 AI(OpenAI GPT)에 넘겨 status/risk/confidence/reason/recommendation을
    최종 판정한다. API 키가 없거나 호출이 실패하면 안전하게 N/A로 폴백한다.

진단 항목 7개:
  1. check_cookie_flags        : 세션 쿠키 HttpOnly / Secure 속성
  2. check_session_fixation    : 로그인 전/후 세션 ID 재발급 여부
  3. check_logout_invalidation : 로그아웃 후 이전 세션 재접근 가능 여부
  4. check_account_enumeration : 로그인 실패 메시지로 계정 존재 여부 구분 가능한지
  5. check_concurrent_login    : 같은 계정 세션 2개 동시 로그인 시 둘 다 유효한지
  6. check_cookie_expiry       : 세션 쿠키에 Max-Age/Expires 존재 여부 (참고용)
  7. check_idle_timeout        : [opt-in, --session-timeout-wait] 실제 대기 후 세션 만료 여부

"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from datetime import datetime
from typing import Optional

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
# 생성형 AI 판정 헬퍼 (sqli_scanner.py와 동일한 로직)
# --------------------------------------------------------------------------- #

AI_SYSTEM_PROMPT = (
    "당신은 웹 애플리케이션 보안 진단 결과를 판정하는 보조 도구입니다. "
    "제공된 '관찰된 사실(raw observation)'에 근거해서만 판정하고, 사실에 없는 내용을 "
    "추측하거나 지어내지 않습니다. "
    "특히 evidence 필드를 작성할 때는 관찰된 사실에 있는 모든 수치(대기 시간, 세션ID 값, "
    "상태코드 등)와 문자열(쿠키 이름, 응답 메시지 등)을 정확한 값 그대로 포함해야 합니다. "
    "'매우 심각한 지연', '오랫동안' 같은 정성적 표현으로 수치를 대체하지 마세요. "
    "예를 들어 관찰된 사실에 '30초 대기'가 있으면 evidence에도 반드시 '30초'라는 숫자를 "
    "그대로 써야 합니다. "
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
    if client is None:
        return make_result(
            vulnerability=vulnerability, status="N/A", risk="중간",
            evidence=technical_evidence,
            reason="OPENAI_API_KEY가 설정되지 않아(또는 openai 패키지 미설치) AI 판정을 수행할 수 없음",
            recommendation="'.env' 파일에 OPENAI_API_KEY를 설정하거나 --openai-api-key 옵션 지정 후 재실행 필요",
            parameter=parameter, payload=payload, confidence="판단불가",
        )

    user_prompt = f"""다음은 웹 세션/인증 취약점 자동 진단 중 실제로 수집된 관찰 결과(raw observation)입니다.
이 사실만 근거로 판정하세요. 사실에 없는 내용을 지어내지 마세요.

취약점명: {vulnerability}
관련 파라미터: {parameter}
관련 값/입력: {payload}
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
- 관찰된 사실이 명확한 취약점 증거(세션 미재발급, 무효화 실패, 속성 미설정 등 직접 관찰)면 status=취약, confidence=확정
- 간접적 근거만 있으면 confidence=추정
- 판단할 근거 자체가 부족하거나 요청이 실패했으면 status=N/A, confidence=판단불가
- evidence의 모든 수치(초, 상태코드 등)는 관찰된 사실에 있는 값 그대로 표기 (정성적 표현으로 대체 금지)
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


def _get_session_cookie(session: requests.Session, cookie_name: str):
    for c in session.cookies:
        if c.name == cookie_name:
            return c
    return None


# --------------------------------------------------------------------------- #
# 진단 로직 (관찰만 코드가, 판정은 AI가)
# --------------------------------------------------------------------------- #

def check_cookie_flags(client, session: requests.Session, login_url: str, id_param: str, pw_param: str,
                        valid_id: str, valid_pw: str, cookie_name: str = "PHPSESSID",
                        model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "세션 쿠키 보안 속성 (HttpOnly/Secure)"
    try:
        session.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="로그인 요청 실패로 쿠키 확인 불가",
            recommendation="로그인 엔드포인트 확인 후 재점검 필요",
            parameter=cookie_name, payload=f"{id_param}={valid_id}, {pw_param}={valid_pw}",
            confidence="판단불가",
        )

    cookie = _get_session_cookie(session, cookie_name)
    if cookie is None:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
            evidence=f"쿠키명 '{cookie_name}' 미발견",
            reason="설정한 세션 쿠키 이름이 실제 응답과 다를 수 있음",
            recommendation="실제 세션 쿠키 이름 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    has_httponly = bool(cookie.has_nonstandard_attr("HttpOnly") or cookie._rest.get("HttpOnly"))
    has_secure = bool(cookie.secure)
    evidence = f"세션 쿠키({cookie_name}) 속성 관찰 결과 - HttpOnly: {has_httponly}, Secure: {has_secure}"
    return ai_judge(client, vuln_name, evidence, cookie_name, None, model=model)


def check_session_fixation(client, session: requests.Session, home_url: str, login_url: str, id_param: str,
                            pw_param: str, valid_id: str, valid_pw: str,
                            cookie_name: str = "PHPSESSID", model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "세션 고정(Session Fixation)"
    try:
        session.get(home_url, timeout=5)
        before = _get_session_cookie(session, cookie_name)
        before_val = before.value if before else None

        session.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
        after = _get_session_cookie(session, cookie_name)
        after_val = after.value if after else None
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="로그인 전/후 세션 값을 비교하는 중 오류 발생",
            recommendation="로그인 흐름 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    if before_val is None or after_val is None:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
            evidence=f"로그인 전 세션값={before_val}, 로그인 후 세션값={after_val}",
            reason="세션 쿠키를 확인할 수 없어 재발급 여부 판정 불가",
            recommendation="세션 쿠키 이름 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    same = before_val == after_val
    evidence = f"로그인 전 세션ID={before_val}, 로그인 후 세션ID={after_val}, 동일 여부={same}"
    return ai_judge(client, vuln_name, evidence, cookie_name, before_val if same else None, model=model)


def check_logout_invalidation(client, session: requests.Session, login_url: str, logout_url: str, mypage_url: str,
                               id_param: str, pw_param: str, valid_id: str, valid_pw: str,
                               fail_indicator: str, model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "로그아웃 후 세션 무효화"
    try:
        session.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
        session.get(logout_url, timeout=5)
        resp = session.get(mypage_url, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="중간",
            evidence=f"요청 실패: {e}",
            reason="로그인-로그아웃-재접근 흐름 중 오류 발생",
            recommendation="관련 URL 확인 후 재점검 필요",
            parameter="session_cookie", payload=None, confidence="판단불가",
        )

    still_accessible = fail_indicator.lower() not in resp.text.lower()
    evidence = f"로그아웃 후 동일 세션으로 마이페이지 재접근 시 status={resp.status_code}, 무효화 지표('{fail_indicator}') 응답에 포함 여부={not still_accessible}"
    return ai_judge(client, vuln_name, evidence, "session_cookie",
                     "로그아웃 후 재사용된 세션 쿠키" if still_accessible else None, model=model)


def check_account_enumeration(client, session: requests.Session, login_url: str, id_param: str, pw_param: str,
                               valid_id: str, invalid_id: str = "no_such_user_9999",
                               model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "계정 존재 여부 노출 (Account Enumeration)"
    try:
        resp_valid_id_wrong_pw = session.post(
            login_url, data={id_param: valid_id, pw_param: "wrong_pw_test"}, timeout=5
        )
        resp_invalid_id = session.post(
            login_url, data={id_param: invalid_id, pw_param: "wrong_pw_test"}, timeout=5
        )
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="낮음",
            evidence=f"요청 실패: {e}",
            reason="로그인 실패 응답 비교 중 오류 발생",
            recommendation="로그인 엔드포인트 확인 후 재점검 필요",
            parameter=id_param, payload=f"{valid_id} / {invalid_id}", confidence="판단불가",
        )

    same_message = resp_valid_id_wrong_pw.text.strip() == resp_invalid_id.text.strip()
    evidence = (f"존재하는 아이디+오답 응답과 존재하지 않는 아이디 응답의 메시지 동일 여부={same_message} "
                f"(존재 아이디 응답 일부: {resp_valid_id_wrong_pw.text.strip()[:100]!r}, "
                f"미존재 아이디 응답 일부: {resp_invalid_id.text.strip()[:100]!r})")
    return ai_judge(client, vuln_name, evidence, id_param, f"{valid_id} / {invalid_id}", model=model)


def check_concurrent_login(client, base_url: str, login_url: str, mypage_url: str,
                            id_param: str, pw_param: str, valid_id: str, valid_pw: str,
                            model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "동시 로그인 제한"
    session_a = requests.Session()
    session_b = requests.Session()
    try:
        session_a.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
        session_b.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
        resp_a = session_a.get(mypage_url, timeout=5)
        resp_b = session_b.get(mypage_url, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="낮음",
            evidence=f"요청 실패: {e}",
            reason="두 세션의 로그인/접근 요청 중 오류 발생",
            recommendation="로그인 엔드포인트 확인 후 재점검 필요",
            parameter="session_cookie", payload=None, confidence="판단불가",
        )

    a_ok = resp_a.status_code == 200 and "로그인" not in resp_a.text
    b_ok = resp_b.status_code == 200 and "로그인" not in resp_b.text
    evidence = f"세션 A 접근 가능={a_ok}, 세션 B 접근 가능={b_ok} (같은 계정으로 각각 로그인 후 마이페이지 접근 시도)"
    return ai_judge(client, vuln_name, evidence, "session_cookie", None, model=model)


def check_cookie_expiry(client, session: requests.Session, login_url: str, id_param: str, pw_param: str,
                         valid_id: str, valid_pw: str, cookie_name: str = "PHPSESSID",
                         model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "세션 쿠키 만료 시간 설정 (참고용, 실제 타임아웃 미검증)"
    try:
        session.post(login_url, data={id_param: valid_id, pw_param: valid_pw}, timeout=5)
    except Exception as e:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="낮음",
            evidence=f"요청 실패: {e}",
            reason="로그인 요청 실패로 쿠키 확인 불가",
            recommendation="로그인 엔드포인트 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    cookie = _get_session_cookie(session, cookie_name)
    if cookie is None:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="낮음",
            evidence=f"쿠키명 '{cookie_name}' 미발견",
            reason="설정한 세션 쿠키 이름이 실제 응답과 다를 수 있음",
            recommendation="실제 세션 쿠키 이름 확인 후 재점검 필요",
            parameter=cookie_name, payload=None, confidence="판단불가",
        )

    has_expiry = cookie.expires is not None
    evidence = f"세션 쿠키({cookie_name})에 Max-Age/Expires 설정 여부={has_expiry}"
    return ai_judge(client, vuln_name, evidence, cookie_name, None, model=model)


def check_idle_timeout(client, base_url: str, login_url: str, mypage_url: str,
                        id_param: str, pw_param: str, valid_id: str, valid_pw: str,
                        wait_seconds: int, model: str = DEFAULT_AI_MODEL) -> dict:
    vuln_name = "세션 유휴 타임아웃 (idle timeout)"
    if wait_seconds <= 0:
        return make_result(
            vulnerability=vuln_name, status="N/A", risk="낮음",
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
            vulnerability=vuln_name, status="N/A", risk="낮음",
            evidence=f"요청 실패: {e}",
            reason="로그인-대기-재접근 흐름 중 오류 발생",
            recommendation="관련 URL 확인 후 재점검 필요",
            parameter="session_cookie", payload=f"{wait_seconds}초 대기", confidence="판단불가",
        )

    still_accessible = resp.status_code == 200 and "로그인" not in resp.text
    evidence = f"{wait_seconds}초 대기 후 동일 세션으로 마이페이지 재접근 시 status={resp.status_code}, 여전히 접근 가능={still_accessible}"
    return ai_judge(client, vuln_name, evidence, "session_cookie", f"{wait_seconds}초 대기", model=model)


def run_all(client, base_url: str, login_path: str, logout_path: str, mypage_path: str,
            id_param: str, pw_param: str, valid_id: str, valid_pw: str,
            logout_fail_indicator: str, cookie_name: str,
            session_timeout_wait: int = 0, model: str = DEFAULT_AI_MODEL) -> list:
    base_url = base_url.rstrip("/")
    login_url = base_url + login_path
    logout_url = base_url + logout_path
    mypage_url = base_url + mypage_path
    home_url = base_url + "/"

    results = []

    s1 = requests.Session()
    results.append(check_cookie_flags(client, s1, login_url, id_param, pw_param, valid_id, valid_pw, cookie_name, model))

    s2 = requests.Session()
    results.append(check_session_fixation(client, s2, home_url, login_url, id_param, pw_param, valid_id, valid_pw, cookie_name, model))

    s3 = requests.Session()
    results.append(check_logout_invalidation(client, s3, login_url, logout_url, mypage_url, id_param, pw_param,
                                              valid_id, valid_pw, logout_fail_indicator, model))

    s4 = requests.Session()
    results.append(check_account_enumeration(client, s4, login_url, id_param, pw_param, valid_id, model=model))

    results.append(check_concurrent_login(client, base_url, login_url, mypage_url, id_param, pw_param, valid_id, valid_pw, model=model))

    s6 = requests.Session()
    results.append(check_cookie_expiry(client, s6, login_url, id_param, pw_param, valid_id, valid_pw, cookie_name, model))

    results.append(check_idle_timeout(client, base_url, login_url, mypage_url, id_param, pw_param,
                                       valid_id, valid_pw, session_timeout_wait, model))

    return results


def main():
    parser = argparse.ArgumentParser(description="세션/인증 취약점 자동 진단 도구 (AI 판정)")
    parser.add_argument("--base-url", default="http://localhost:8081")
    parser.add_argument("--login-path", default="/auth/login.php")
    parser.add_argument("--logout-path", default="/auth/logout.php")
    parser.add_argument("--mypage-path", default="/inquiry/my.php")
    parser.add_argument("--id-param", default="id")
    parser.add_argument("--pw-param", default="pw")
    parser.add_argument("--valid-id", default="test999")
    parser.add_argument("--valid-pw", default="test999")
    parser.add_argument("--logout-fail-indicator", default="로그인이 필요합니다",
                         help="세션 무효화 시 응답에 포함되는 문자열")
    parser.add_argument("--cookie-name", default="PHPSESSID")
    parser.add_argument("--session-timeout-wait", type=int, default=0,
                         help="[opt-in] 실제 idle timeout을 확인하기 위해 로그인 후 대기할 시간(초). "
                              "0(기본값)이면 이 항목은 건너뜀. 예: 정책상 30분이면 1800")
    parser.add_argument("--openai-api-key", default=None,
                         help="OpenAI API 키. 생략 시 환경변수 OPENAI_API_KEY 사용")
    parser.add_argument("--ai-model", default=DEFAULT_AI_MODEL)
    parser.add_argument("--output", default="session_scan_result.json")
    args = parser.parse_args()

    if args.session_timeout_wait > 0:
        print(f"⏳ --session-timeout-wait 옵션으로 {args.session_timeout_wait}초 대기 후 확인합니다. 스캔이 그만큼 오래 걸립니다.")

    client, client_error = get_openai_client(args.openai_api_key)
    if client is None:
        print(f"⚠️  AI 판정을 사용할 수 없어 모든 판정이 N/A로 처리됩니다. 원인: {client_error}")
    else:
        print(f"🤖 AI 판정 모델: {args.ai_model}")

    results = run_all(
        client=client,
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
        model=args.ai_model,
    )

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)

    print(f"총 {len(results)}개 항목 진단 완료 -> {args.output} 저장")
    for r in results:
        print(f"- [{r['status']}/{r['risk']}/{r['confidence']}] {r['vulnerability']}")


if __name__ == "__main__":
    main()
