import argparse
import html
import json
import os
import re
import secrets
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from html.parser import HTMLParser
from urllib.parse import parse_qsl, quote, urlencode, urldefrag, urljoin, urlparse, urlunparse

import requests
from playwright.sync_api import sync_playwright


TIMEOUT = 5
BASE_URL = "http://localhost:8081/"
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PAGES = 30
LOGIN_ID = "user05"
LOGIN_PW = "user05"
AI_ANALYSIS_ENABLED = True
AI_MODEL = "gpt-5"
AI_TIMEOUT = 90
AI_MAX_ITEMS = 20
# Reflected/Stored는 TEST_CASES에 정의된 대표 페이로드 전체를 사용한다.
MAX_DOM_PAYLOADS_PER_TARGET = None
# DOM은 페이지 수까지 곱해지므로 선별 페이지 수를 제한한다.
MAX_DOM_PAGES = 5
# Reflected는 probe가 명확히 HTML Entity Encoding 된 지점의 브라우저 검증만 생략해 시간을 줄인다.
SKIP_SAFE_REFLECTED_TARGETS = True
# 삭제 기능이 없는 민원 게시판에 남는 Stored XSS 진단 글의 전체 개수를 제한한다.
MAX_STORED_SUBMISSIONS = None
DANGEROUS_PATH_WORDS = (
    "logout", "delete", "remove", "drop", "reset", "withdraw", "payment",
    "pay", "admin", "destroy",
)
COMMON_PATHS = (
    "/", "/search", "/search.php", "/board", "/board.php", "/board/list.php",
    "/board/write", "/board/write.php", "/write", "/write.php", "/post",
    "/post.php", "/comment", "/comment.php", "/qna", "/qna.php", "/profile",
    "/profile.php", "/contact", "/contact.php", "/dom", "/dom.php",
)

TEST_CASES = [
    # HTML attribute context (for example: <input value="USER_INPUT">)
    ("double_quote_attr_svg", '\"><svg onload', '\"><svg onload=alert("{token}")>'),
    ("double_quote_attr_img", '\"><img onerror', '\"><img src=x onerror=alert("{token}")>'),
    ("single_quote_attr_svg", "'><svg onload", "'><svg onload=alert(\"{token}\")>"),
    ("script_tag", "<script>", '<script>alert("{token}")</script>'),
    ("img_onerror", "onerror=", '<img src=x onerror=alert("{token}")>'),
    ("svg_onload", "<svg onload", '<svg onload=alert("{token}")></svg>'),
    ("body_onload", "<body onload", '<body onload=alert("{token}")>'),
    ("input_onfocus", "onfocus=", '<input autofocus onfocus=alert("{token}")>'),
    ("details_ontoggle", "ontoggle=", '<details open ontoggle=alert("{token}")>'),
    ("iframe_srcdoc", "<iframe srcdoc", '<iframe srcdoc="<script>alert(\'{token}\')</script>"></iframe>'),
]

DOM_CASES = [
    ("img_onerror", '<img src=x onerror=alert("{token}")>'),
    ("svg_onload", '<svg onload=alert("{token}")></svg>'),
    ("input_onfocus", '<input autofocus onfocus=alert("{token}")>'),
]

DOM_QUERY_PARAMETERS = ("keyword", "q")
DOM_SOURCE_HINTS = ("URLSearchParams", "location.search", "location.hash", "window.name", "postMessage")
DOM_SINK_HINTS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(")


def limited_cases(cases, limit):
    return cases if limit is None else cases[:limit]


def truncate_text(text, limit):
    text = str(text or "")
    return text if len(text) <= limit else text[:limit] + "...(truncated)"


def load_env_file(path=".env"):
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8-sig") as file:
        for line in file:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, value = stripped.split("=", 1)
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and key not in os.environ:
                os.environ[key] = value
    return True


def normalize_openai_api_key_env():
    if os.getenv("OPENAI_API_KEY"):
        return "OPENAI_API_KEY"
    for alias in ("OPENAI_KEY", "OPENAI_APIKEY", "OPEN_API_KEY", "API_KEY"):
        value = os.getenv(alias)
        if value:
            os.environ["OPENAI_API_KEY"] = value
            return alias
    return ""


def response_output_text(response_data):
    if response_data.get("output_text"):
        return response_data["output_text"]
    chunks = []
    for item in response_data.get("output", []):
        for content in item.get("content", []):
            text = content.get("text") or content.get("output_text")
            if text:
                chunks.append(text)
    return "\n".join(chunks)


def parse_ai_json(text):
    if not text:
        return {}
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", cleaned, re.DOTALL)
        if not match:
            return {}
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return {}


def raw_fact_text(scan_type, facts):
    compact = ", ".join(f"{key}={value}" for key, value in facts.items())
    return f"AI 분석 전 원시 진단 데이터({scan_type}): {compact}"


def ai_pending_text(field_name):
    return f"AI가 원시 진단 데이터를 기반으로 {field_name}을 생성해야 함"


def call_openai_json(instructions, payload):
    if not AI_ANALYSIS_ENABLED:
        return {}, "disabled"
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return {}, "missing_api_key"

    request_body = {
        "model": os.getenv("OPENAI_MODEL", AI_MODEL),
        "instructions": instructions,
        "input": json.dumps(payload, ensure_ascii=False),
        "store": False,
        "text": {
            "format": {
                "type": "json_schema",
                "name": "xss_ai_report_enhancement",
                "schema": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "summary": {"type": "string"},
                        "reflected_xss": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "status": {"type": "string", "enum": ["취약", "양호", "N/A"]},
                                "risk": {"type": "string", "enum": ["높음", "중간", "낮음"]},
                                "evidence": {"type": "string"},
                                "reason": {"type": "string"},
                                "recommendation": {"type": "string"},
                                "confidence": {"type": "string", "enum": ["확정", "미확정", "판단불가"]},
                            },
                            "required": ["status", "risk", "evidence", "reason", "recommendation", "confidence"],
                        },
                        "stored_xss": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "status": {"type": "string", "enum": ["취약", "양호", "N/A"]},
                                "risk": {"type": "string", "enum": ["높음", "중간", "낮음"]},
                                "evidence": {"type": "string"},
                                "reason": {"type": "string"},
                                "recommendation": {"type": "string"},
                                "confidence": {"type": "string", "enum": ["확정", "미확정", "판단불가"]},
                            },
                            "required": ["status", "risk", "evidence", "reason", "recommendation", "confidence"],
                        },
                        "dom_xss": {
                            "type": "object",
                            "additionalProperties": False,
                            "properties": {
                                "status": {"type": "string", "enum": ["취약", "양호", "N/A"]},
                                "risk": {"type": "string", "enum": ["높음", "중간", "낮음"]},
                                "evidence": {"type": "string"},
                                "reason": {"type": "string"},
                                "recommendation": {"type": "string"},
                                "confidence": {"type": "string", "enum": ["확정", "미확정", "판단불가"]},
                            },
                            "required": ["status", "risk", "evidence", "reason", "recommendation", "confidence"],
                        },
                    },
                    "required": ["summary", "reflected_xss", "stored_xss", "dom_xss"],
                },
                "strict": True,
            }
        },
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(request_body, ensure_ascii=False).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=AI_TIMEOUT) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
        return {}, f"api_error:{error.__class__.__name__}"
    parsed = parse_ai_json(response_output_text(response_data))
    return parsed, "ok" if parsed else "parse_failed"


def snippet_around(text, needle, radius=220):
    index = text.find(needle)
    if index < 0:
        return ""
    start = max(0, index - radius)
    end = min(len(text), index + len(needle) + radius)
    return " ".join(text[start:end].split())


def build_ai_scan_context(pages, forms, reflected_targets):
    page_summaries = []
    dom_hints = []
    for url, body in sorted(pages.items())[:AI_MAX_ITEMS]:
        source_hits = [hint for hint in DOM_SOURCE_HINTS if hint in body]
        sink_hits = [hint for hint in DOM_SINK_HINTS if hint in body]
        page_summaries.append({
            "url": url,
            "has_dom_source": bool(source_hits),
            "has_dom_sink": bool(sink_hits),
        })
        if source_hits or sink_hits:
            hint = (source_hits + sink_hits)[0]
            dom_hints.append({
                "url": url,
                "sources": source_hits,
                "sinks": sink_hits,
                "snippet": truncate_text(snippet_around(body, hint), 700),
            })

    form_summaries = []
    for form in forms[:AI_MAX_ITEMS]:
        form_summaries.append({
            "page_url": form.page_url,
            "action_url": form.action_url,
            "method": form.method,
            "fields": [{"name": field.name, "type": field.field_type} for field in form.fields],
        })

    reflected_summaries = [
        {"url": target.url, "parameter": target.parameter, "source": target.source}
        for target in reflected_targets[:AI_MAX_ITEMS]
    ]
    return {
        "scanner_scope": "XSS automated diagnosis for reflected_xss, stored_xss, dom_xss",
        "payload_count": len(TEST_CASES),
        "dom_payload_count": len(DOM_CASES),
        "page_count": len(pages),
        "form_count": len(forms),
        "reflected_candidate_count": len(reflected_targets),
        "pages": page_summaries,
        "forms": form_summaries,
        "reflected_candidates": reflected_summaries,
        "dom_code_hints": dom_hints[:AI_MAX_ITEMS],
    }


def result_for_ai_verdict(scan_results):
    hidden_fields = {"payload", "tested_at"}
    sanitized = {}
    for vuln_key, result_item in scan_results.items():
        if not isinstance(result_item, dict):
            continue
        sanitized[vuln_key] = {
            key: value
            for key, value in result_item.items()
            if key not in hidden_fields
        }
    return sanitized


def clean_ai_evidence_text(text):
    cleaned = re.sub(r"\b(parameter|payload|tested_at)\s*:\s*[^.。]*[.。]?", "", text, flags=re.IGNORECASE)
    cleaned = re.sub(r"https?://\S+", "[별도 필드 참조]", cleaned)
    cleaned = cleaned.replace("제출", "전송")
    return " ".join(cleaned.split())


def enhance_result_with_ai(final_result, ai_context):
    instructions = """
너는 웹 취약점 자동 진단 결과를 최종 판정하는 보안 분석 AI다.
입력으로 Python 스캐너가 실제 브라우저 alert 실행까지 검증한 XSS 결과와 크롤링 요약이 제공된다.
기존 deterministic_result의 문장을 그대로 반복하지 말고, 같은 사실을 더 간결하고 구체적인 새 문장으로 재작성하라.
parameter, payload, tested_at 값은 실제 증거이므로 절대 바꾸지 말아라.
evidence 문장에는 URL, 파라미터명, payload 문자열, token, tested_at 값을 절대 포함하지 말아라.
URL, 파라미터, payload는 JSON의 별도 필드에 이미 있으므로 evidence에서는 테스트 수, 성공 수, 실행 여부, 오류 수만 요약하라.
evidence는 반드시 "발견/검증 지점 수 + 사용 payload 수 + 총 테스트 횟수 + 성공 횟수 + 오류 수"를 포함하라.
Reflected 예시 형식: "GET 입력 지점 N개, payload M개, 총 T회 검증, alert 성공 S회, 실행 지점 P개, 브라우저 오류 E건."
Stored 예시 형식: "POST 저장 지점 N개, payload M개, 총 T회 전송, 저장 반영 R회, alert 성공 S회, 브라우저 오류 E건."
DOM 예시 형식: "DOM 후보 페이지 N개, 입력 경로 K개, payload M개, 총 T회 검증, alert 성공 S회, 실행 지점 P개, 브라우저 오류 E건."
Stored XSS evidence에서는 "제출"이라는 표현을 쓰지 말고 "전송", "검증", "저장 반영", "실행 확인" 같은 표현만 사용하라.
status, risk, confidence는 deterministic_result의 원시 증거를 근거로 최종 판단하라.
alert 실행이 1회 이상 확인된 경우 원칙적으로 status는 "취약", confidence는 "확정"으로 판단하라.
브라우저 오류 때문에 실행 여부를 확인하지 못한 경우 status는 "N/A", confidence는 "미확정" 또는 "판단불가"로 판단하라.
실행 증거가 없고 오류도 없으면 status는 "양호", confidence는 "미확정"으로 판단하라.
risk는 실제 JavaScript 실행이 확인된 XSS는 "높음", 저장 반영만 있고 실행이 없으면 "중간", 실행·반영 증거가 없으면 "낮음"으로 판단하라.
문체는 기계 도구 출력처럼 짧은 명사형으로 작성하라.
"확인하였다", "판단하였다", "적용하라", "조치하라", "하십시오" 같은 서술형/명령형 표현을 쓰지 말아라.
권장 표현 예시: "검증 대상 N개, payload M개, 총 T회, 성공 S회, 오류 E건", "출력 인코딩 누락", "CSP 적용 필요", "위험 DOM Sink 제거 필요".
각 항목은 한국어로 작성하고, evidence는 확인된 횟수/지점/실행 여부를 보존하며 2문장 이내로 써라.
reason과 recommendation도 각각 2문장 이내의 명사형 구문으로 써라.
마크다운 없이 아래 JSON 형식만 반환하라.
{
  "summary": "AI가 최종 판정한 진단 요약 한 문장",
  "reflected_xss": {"status": "취약|양호|N/A", "risk": "높음|중간|낮음", "evidence": "...", "reason": "...", "recommendation": "...", "confidence": "확정|미확정|판단불가"},
  "stored_xss": {"status": "취약|양호|N/A", "risk": "높음|중간|낮음", "evidence": "...", "reason": "...", "recommendation": "...", "confidence": "확정|미확정|판단불가"},
  "dom_xss": {"status": "취약|양호|N/A", "risk": "높음|중간|낮음", "evidence": "...", "reason": "...", "recommendation": "...", "confidence": "확정|미확정|판단불가"}
}
"""
    ai_payload = {
        "scan_context": ai_context,
        "deterministic_result": result_for_ai_verdict(final_result.get("xss_scan_result", {})),
    }
    ai_result, status = call_openai_json(instructions, ai_payload)
    meta = {
        "enabled": AI_ANALYSIS_ENABLED,
        "used": False,
        "model": os.getenv("OPENAI_MODEL", AI_MODEL),
        "status": status,
        "summary": ai_result.get("summary", "") if isinstance(ai_result, dict) else "",
    }
    if not isinstance(ai_result, dict):
        return meta

    updated = 0
    for vuln_key, current in final_result.get("xss_scan_result", {}).items():
        ai_texts = ai_result.get(vuln_key)
        if not isinstance(current, dict) or not isinstance(ai_texts, dict):
            continue
        for field in ("status", "risk", "evidence", "reason", "recommendation", "confidence"):
            value = ai_texts.get(field)
            if isinstance(value, str) and value.strip():
                if field == "evidence":
                    value = clean_ai_evidence_text(value)
                current[field] = value.strip()
                updated += 1
    meta["used"] = updated > 0
    meta["updated_fields"] = updated
    return meta


def dom_priority(page_item):
    url, body = page_item
    score = 0
    if any(hint in body for hint in DOM_SOURCE_HINTS):
        score += 2
    if any(hint in body for hint in DOM_SINK_HINTS):
        score += 3
    return (-score, url)


@dataclass(frozen=True)
class InputField:
    name: str
    value: str = ""
    field_type: str = "text"
    checked: bool = False


@dataclass
class FormTarget:
    page_url: str
    action_url: str
    method: str
    fields: list[InputField] = field(default_factory=list)


@dataclass(frozen=True)
class ReflectedTarget:
    url: str
    parameter: str
    base_params: tuple[tuple[str, str], ...]
    source: str


class PageParser(HTMLParser):
    def __init__(self, page_url):
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.links = set()
        self.forms = []
        self.current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.add(urljoin(self.page_url, attrs["href"]))
            return
        if tag == "form":
            action = attrs.get("action") or self.page_url
            self.current_form = FormTarget(
                page_url=self.page_url,
                action_url=urljoin(self.page_url, action),
                method=(attrs.get("method") or "GET").upper(),
            )
            return
        if self.current_form and tag in {"input", "textarea", "select"}:
            name = attrs.get("name")
            if not name:
                return
            field_type = (attrs.get("type") or tag).lower()
            if field_type in {"submit", "button", "reset", "image", "file", "password"}:
                return
            self.current_form.fields.append(InputField(name, attrs.get("value", ""), field_type, "checked" in attrs))

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None


def make_token(prefix):
    return f"{prefix}_{secrets.token_hex(8)}"


def make_probe(prefix):
    token = make_token(prefix)
    return token, f'{token}<>"\'&/`'


def normalize_url(url):
    parsed = urlparse(urldefrag(url).url)
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def same_origin(url, base):
    target, origin = urlparse(url), urlparse(base)
    return target.scheme in {"http", "https"} and (target.scheme, target.netloc) == (origin.scheme, origin.netloc)


def dangerous_url(url):
    path = urlparse(url).path.lower()
    return any(word in path for word in DANGEROUS_PATH_WORDS)


def enqueue(queue, seen_queue, url, depth, base_url):
    url = normalize_url(url)
    if same_origin(url, base_url) and url not in seen_queue and not dangerous_url(url):
        seen_queue.add(url)
        queue.append((url, depth))


def origin_root(base_url):
    parsed = urlparse(base_url)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", ""))


def common_path_urls(base_url):
    root = origin_root(base_url)
    return [urljoin(root, path.lstrip("/")) for path in COMMON_PATHS]


def sitemap_urls(session, base_url):
    sitemap_url = urljoin(origin_root(base_url), "sitemap.xml")
    try:
        response = session.get(sitemap_url, timeout=TIMEOUT)
        response.raise_for_status()
        root = ET.fromstring(response.content)
    except (requests.RequestException, ET.ParseError):
        return []
    urls = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] == "loc" and element.text:
            url = normalize_url(element.text.strip())
            if same_origin(url, base_url) and not dangerous_url(url):
                urls.append(url)
    return urls


def allowed_post(url, allowlist):
    path = urlparse(url).path
    return any(path == item or path.startswith(item.rstrip("/") + "/") for item in allowlist)


def reflection_state(response_text, token, probe):
    if token not in response_text:
        return "미반영"
    if probe in response_text:
        return "원문 반영"
    escaped_variants = {
        html.escape(probe, quote=True),
        html.escape(probe, quote=False),
        probe.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;").replace("'", "&#39;"),
    }
    if any(value in response_text for value in escaped_variants):
        return "HTML Entity Encoding"
    return "변형 반영"


def result(vulnerability, parameter, status, risk, evidence, reason, recommendation, payload, confidence):
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


def unavailable(vulnerability, parameter, evidence, reason, recommendation):
    return result(vulnerability, parameter, "N/A", "낮음", evidence, reason, recommendation, "", "판단불가")


def cookies_for_playwright(session, target_url):
    parsed = urlparse(target_url)
    cookies = []
    for cookie in session.cookies:
        domain = cookie.domain.lstrip(".") if cookie.domain else parsed.hostname
        playwright_cookie = {
            "name": cookie.name,
            "value": cookie.value,
        }
        if domain in {"localhost", "localhost.local"}:
            playwright_cookie["url"] = f"{parsed.scheme}://{parsed.netloc}"
        else:
            playwright_cookie["domain"] = domain
            playwright_cookie["path"] = cookie.path or "/"
        cookies.append(playwright_cookie)
    return cookies


def browser_executes(browser, session, target_url, token, before_navigation=None,
                     after_navigation=None, wait_until="domcontentloaded",
                     timeout=3000, wait_ms=200):
    executed = False
    context = None

    def handle_dialog(dialog):
        nonlocal executed
        if dialog.type == "alert" and dialog.message == token:
            executed = True
        dialog.dismiss()

    try:
        context = browser.new_context()
        cookies = cookies_for_playwright(session, target_url)
        if cookies:
            context.add_cookies(cookies)
        page = context.new_page()
        page.on("dialog", handle_dialog)
        if before_navigation:
            page.goto("about:blank")
            before_navigation(page)
        page.goto(target_url, wait_until=wait_until, timeout=timeout)
        if after_navigation:
            page.wait_for_timeout(300)
            after_navigation(page)
        page.wait_for_timeout(wait_ms)
        try:
            page.keyboard.press("Tab")
            page.wait_for_timeout(150)
        except Exception:
            pass
    except Exception:
        return "error"
    finally:
        if context:
            try:
                context.close()
            except Exception:
                pass
    return "executed" if executed else "not_executed"


def build_url(url, params):
    parsed = urlparse(url)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", urlencode(params), ""))


def fetch_page(session, url):
    response = session.get(url, timeout=TIMEOUT)
    response.raise_for_status()
    ctype = response.headers.get("content-type", "")
    if "text/html" not in ctype and ctype:
        return response.url, ""
    return response.url, response.text


def login(session, base_url, login_url, login_id, login_pw, id_field, pw_field):
    if not login_id and not login_pw:
        return {"enabled": False, "ok": True, "evidence": "로그인 옵션 미사용"}
    if not login_id or not login_pw:
        return {"enabled": True, "ok": False, "evidence": "로그인 ID 또는 비밀번호 옵션 누락"}

    target_url = urljoin(origin_root(base_url), login_url)
    try:
        response = session.post(
            target_url,
            data={id_field: login_id, pw_field: login_pw},
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        response.raise_for_status()
    except requests.RequestException as error:
        return {"enabled": True, "ok": False, "evidence": f"로그인 요청 실패({type(error).__name__})"}

    # PHP session_start() creates a cookie even when authentication fails, so a
    # cookie alone is not proof of login.  This application exposes the logout
    # link only to authenticated users; verify that server-side state instead.
    try:
        verification = session.get(origin_root(base_url), timeout=TIMEOUT)
        authenticated = "/auth/logout.php" in verification.text
    except requests.RequestException:
        authenticated = False

    if authenticated:
        return {
            "enabled": True,
            "ok": True,
            "evidence": f"user05 세션 확인 완료(로그아웃 링크 확인), 최종 URL: {response.url}",
        }
    return {
        "enabled": True,
        "ok": False,
        "evidence": "로그인 POST 후 인증 사용자 전용 로그아웃 링크가 확인되지 않음",
    }


def register_account(session, base_url, register_url, login_id, login_pw, name,
                     id_field, pw_field, name_field):
    if not login_id or not login_pw:
        return {"enabled": False, "ok": False, "evidence": "회원가입 ID 또는 비밀번호 옵션 누락"}

    target_url = urljoin(origin_root(base_url), register_url)
    try:
        response = session.post(
            target_url,
            data={id_field: login_id, pw_field: login_pw, name_field: name},
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        response.raise_for_status()
    except requests.RequestException as error:
        return {"enabled": True, "ok": False, "evidence": f"회원가입 요청 실패({type(error).__name__})"}

    return {"enabled": True, "ok": True, "evidence": f"회원가입 요청 완료, 최종 URL: {response.url}"}


def authenticate(session, args):
    login_result = login(
        session, args.base_url, args.login_url, LOGIN_ID, LOGIN_PW,
        args.login_id_field, args.login_pw_field,
    )
    if login_result["ok"] or not args.register_if_needed:
        return {"login": login_result, "register": {"enabled": False, "ok": True, "evidence": "자동 회원가입 미사용"}}

    register_result = register_account(
        session, args.base_url, args.register_url, LOGIN_ID, LOGIN_PW,
        args.register_name, args.login_id_field, args.login_pw_field, args.register_name_field,
    )
    if not register_result["ok"]:
        return {"login": login_result, "register": register_result}

    session.cookies.clear()
    retry_login = login(
        session, args.base_url, args.login_url, LOGIN_ID, LOGIN_PW,
        args.login_id_field, args.login_pw_field,
    )
    return {"login": retry_login, "register": register_result, "initial_login": login_result}


def crawl(session, base_url, max_depth, max_pages):
    base_url = normalize_url(base_url)
    seen = set()
    queue, seen_queue = [], set()
    for url in [base_url, *sitemap_urls(session, base_url), *common_path_urls(base_url)]:
        enqueue(queue, seen_queue, url, 0, base_url)
    pages = {}
    forms = []

    while queue and len(pages) < max_pages:
        url, depth = queue.pop(0)
        url = normalize_url(url)
        if url in seen or not same_origin(url, base_url) or dangerous_url(url):
            continue
        seen.add(url)
        try:
            final_url, body = fetch_page(session, url)
        except requests.RequestException:
            continue
        if not body:
            continue
        final_url = normalize_url(final_url)
        pages[final_url] = body

        parser = PageParser(final_url)
        parser.feed(body)
        forms.extend(parser.forms)
        if depth >= max_depth:
            continue
        for form in parser.forms:
            enqueue(queue, seen_queue, form.action_url, depth + 1, base_url)
        for link in sorted(parser.links):
            enqueue(queue, seen_queue, link, depth + 1, base_url)

    return pages, forms


def links_from_html(page_url, body):
    parser = PageParser(page_url)
    parser.feed(body)
    return {normalize_url(link) for link in parser.links}


def view_priority(url):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query, keep_blank_values=True))
    try:
        numeric_id = int(params.get("id", "0"))
    except ValueError:
        numeric_id = 0
    return ("detail" not in parsed.path.lower(), -numeric_id, url)


def candidate_view_urls(session, base_url, known_pages, response=None):
    urls = set(known_pages)
    if response is not None and "text/html" in response.headers.get("content-type", ""):
        urls.add(normalize_url(response.url))
        urls.update(
            link for link in links_from_html(response.url, response.text)
            if same_origin(link, base_url) and not dangerous_url(link)
        )

    for page_url in list(urls):
        try:
            final_url, body = fetch_page(session, page_url)
        except requests.RequestException:
            continue
        urls.add(normalize_url(final_url))
        urls.update(
            link for link in links_from_html(final_url, body)
            if same_origin(link, base_url) and not dangerous_url(link)
        )
    return sorted(urls, key=view_priority)[:20]


def reflected_targets_from(pages, forms):
    targets = {}
    for url in pages:
        parsed = urlparse(url)
        for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
            clean_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
            params = tuple(parse_qsl(parsed.query, keep_blank_values=True))
            targets[(clean_url, name)] = ReflectedTarget(clean_url, name, params, "URL query")

    for form in forms:
        if form.method != "GET" or dangerous_url(form.action_url):
            continue
        params = tuple((field.name, field.value) for field in form.fields)
        for field in form.fields:
            targets[(form.action_url, field.name)] = ReflectedTarget(
                form.action_url, field.name, params, f"GET form on {form.page_url}"
            )
    return list(targets.values())


def form_data(form, target_field, value):
    data = []
    seen = set()
    for field in form.fields:
        if field.field_type in {"radio", "checkbox"} and field.name != target_field and not field.checked:
            continue
        if field.name in seen and field.name != target_field:
            continue
        data.append((field.name, value if field.name == target_field else field.value))
        seen.add(field.name)
    return data


def stored_target_fields(form):
    fields = [
        field for field in form.fields
        if field.field_type not in {"hidden", "radio", "checkbox"}
    ]
    return sorted(fields, key=lambda field: field.field_type != "textarea")


def finalize_report(vulnerability, status, risk, evidence, reason, recommendation,
                    successful, default_payloads, confidence, parameters):
    parameter_text = "; ".join(parameters) if isinstance(parameters, list) else parameters
    payloads = "; ".join(item["payload"] for item in successful) if successful else default_payloads
    return result(
        vulnerability, parameter_text, status, risk, evidence, reason,
        recommendation, payloads, confidence,
    )


def scan_reflected_xss(browser, session, targets):
    vulnerability = "크로스 사이트 스크립팅 (Reflected XSS)"
    recommendation = ai_pending_text("Reflected XSS 조치 권고")
    test_cases = TEST_CASES
    if not targets:
        return unavailable(
            vulnerability, "N/A",
            raw_fact_text("reflected_xss", {"candidate_count": 0}),
            ai_pending_text("Reflected XSS 미진단 사유"),
            recommendation,
        )

    reflected_states, successful, browser_errors, total_tests = [], [], 0, 0
    for target in targets:
        probe_token, probe = make_probe("RXSS_PROBE")
        reflected_state = "확인 실패"
        try:
            response = session.get(target.url, params={**dict(target.base_params), target.parameter: probe}, timeout=TIMEOUT)
            reflected_state = reflection_state(response.text, probe_token, probe)
            reflected_states.append(reflected_state)
        except requests.RequestException:
            reflected_states.append("확인 실패")
        if SKIP_SAFE_REFLECTED_TARGETS and reflected_state == "HTML Entity Encoding":
            continue

        for _, _, template in test_cases:
            total_tests += 1
            token = make_token("RXSS")
            payload = template.format(token=token)
            try:
                response = session.get(target.url, params={**dict(target.base_params), target.parameter: payload}, timeout=TIMEOUT)
            except requests.RequestException:
                continue
            execution = browser_executes(browser, session, response.url, token)
            if execution == "executed":
                successful.append({"where": f"{target.url}::{target.parameter}", "payload": payload})
            elif execution == "error":
                browser_errors += 1

    parameters = sorted({item["where"] for item in successful}) or sorted({f"{target.url}::{target.parameter}" for target in targets})
    total = total_tests
    state_counts = Counter(reflected_states)
    reflection = ", ".join(
        f"{state} {state_counts[state]}개"
        for state in ("원문 반영", "변형 반영", "HTML Entity Encoding", "미반영", "확인 실패")
        if state_counts[state]
    )
    if successful:
        status, risk, confidence = "취약", "높음", "확정"
    elif browser_errors:
        status, risk, confidence = "N/A", "낮음", "미확정"
    else:
        status, risk, confidence = "양호", "낮음", "미확정"
    evidence = raw_fact_text("reflected_xss", {
        "candidate_count": len(targets),
        "payload_count": len(test_cases),
        "total_tests": total,
        "executed_count": len(successful),
        "executed_points": len(parameters) if successful else 0,
        "reflection_probe": reflection or "none",
        "browser_errors": browser_errors,
    })
    reason = ai_pending_text("Reflected XSS 판정 사유")
    return finalize_report(
        vulnerability, status, risk, evidence, reason, recommendation, successful,
        "; ".join(signature for _, signature, _ in test_cases), confidence, parameters,
    )


def scan_stored_xss(browser, session, forms, pages, allow_posts, cleanup_url):
    vulnerability = "크로스 사이트 스크립팅 (Stored XSS)"
    recommendation = ai_pending_text("Stored XSS 조치 권고")
    test_cases = TEST_CASES
    max_stored_submissions = MAX_STORED_SUBMISSIONS or len(test_cases)
    post_forms = [form for form in forms if form.method == "POST" and not dangerous_url(form.action_url) and allowed_post(form.action_url, allow_posts)]
    if not post_forms:
        return unavailable(
            vulnerability, "N/A",
            raw_fact_text("stored_xss", {"allowed_post_form_count": 0, "allow_post": ";".join(allow_posts)}),
            ai_pending_text("Stored XSS 미진단 사유"),
            recommendation,
        )

    view_urls = sorted(set(pages) | {form.page_url for form in post_forms})
    cleanup_evidence = "cleanup_url_not_configured"
    created_tokens, successful, stored_count, browser_errors, total_tests = [], [], 0, 0, 0
    for form in post_forms:
        if total_tests >= max_stored_submissions:
            break
        for field in stored_target_fields(form):
            if total_tests >= max_stored_submissions:
                break

            for _, _, template in test_cases:
                if total_tests >= max_stored_submissions:
                    break
                total_tests += 1
                token = make_token("SXSS")
                created_tokens.append(token)
                payload = template.format(token=token)
                try:
                    response = session.post(form.action_url, data=form_data(form, field.name, payload), timeout=TIMEOUT, allow_redirects=True)
                    view_urls = candidate_view_urls(session, form.page_url, view_urls, response)
                except requests.RequestException:
                    continue

                found_url = None
                for view_url in view_urls:
                    try:
                        response = session.get(view_url, timeout=TIMEOUT)
                    except requests.RequestException:
                        continue
                    if token in response.text:
                        found_url, stored_count = response.url, stored_count + 1
                        break
                if not found_url:
                    continue
                execution = browser_executes(browser, session, found_url, token)
                if execution == "executed":
                    successful.append({"where": f"{form.action_url}::{field.name}", "payload": payload})
                elif execution == "error":
                    browser_errors += 1

    if cleanup_url and created_tokens:
        try:
            response = session.post(cleanup_url, data=[("token", token) for token in created_tokens], timeout=TIMEOUT)
            cleanup_evidence = "cleanup_requested_ok" if response.ok else "cleanup_requested_failed"
        except requests.RequestException:
            cleanup_evidence = "cleanup_requested_failed"

    parameters = sorted({item["where"] for item in successful}) or sorted(
        {f"{form.action_url}::{field.name}" for form in post_forms for field in stored_target_fields(form)}
    )
    total = total_tests
    stored_scope = "limited_submissions" if max_stored_submissions < len(test_cases) else "all_payloads_per_target"
    if successful:
        status, risk, confidence = "취약", "높음", "확정"
    elif browser_errors:
        status, risk, confidence = "N/A", "낮음", "미확정"
    elif stored_count:
        status, risk, confidence = "양호", "중간", "미확정"
    else:
        status, risk, confidence = "양호", "낮음", "미확정"
    evidence = raw_fact_text("stored_xss", {
        "allowed_post_form_count": len(post_forms),
        "target_field_count": len(parameters),
        "payload_count": len(test_cases),
        "submission_limit": max_stored_submissions,
        "total_tests": total,
        "stored_reflection_count": stored_count,
        "executed_count": len(successful),
        "browser_errors": browser_errors,
        "cleanup": cleanup_evidence,
        "scope": stored_scope,
    })
    reason = ai_pending_text("Stored XSS 판정 사유")
    return finalize_report(
        vulnerability, status, risk, evidence, reason, recommendation, successful,
        "; ".join(signature for _, signature, _ in test_cases), confidence, parameters,
    )


def scan_dom_xss(browser, session, pages):
    vulnerability = "크로스 사이트 스크립팅 (DOM-based XSS)"
    recommendation = ai_pending_text("DOM-based XSS 조치 권고")
    dom_cases = limited_cases(DOM_CASES, MAX_DOM_PAYLOADS_PER_TARGET)
    if not pages:
        return unavailable(
            vulnerability, "DOM Source",
            raw_fact_text("dom_xss", {"page_count": 0}),
            ai_pending_text("DOM-based XSS 미진단 사유"),
            recommendation,
        )

    successful, browser_errors, total = [], 0, 0
    target_pages = [url for url, _ in sorted(pages.items(), key=dom_priority)[:MAX_DOM_PAGES]]
    sources = (
        *[f"location.search:{name}" for name in DOM_QUERY_PARAMETERS],
        "location.hash",
        "window.name",
        "postMessage",
    )
    for page_url in target_pages:
        base_url = urldefrag(page_url).url
        for _, template in dom_cases:
            for source in sources:
                total += 1
                token = make_token("DOMXSS")
                payload = template.format(token=token)
                if source.startswith("location.search:"):
                    query_name = source.split(":", 1)[1]
                    execution = browser_executes(browser, session, build_url(base_url, [(query_name, payload)]), token)
                elif source == "location.hash":
                    execution = browser_executes(browser, session, f"{base_url}#{quote(payload, safe='')}", token)
                elif source == "window.name":
                    execution = browser_executes(browser, session, base_url, token, before_navigation=lambda page, value=payload: page.evaluate("value => { window.name = value; }", value))
                else:
                    execution = browser_executes(browser, session, base_url, token, after_navigation=lambda page, value=payload: page.evaluate("value => window.postMessage(value, '*')", value))
                if execution == "executed":
                    successful.append({"where": f"{base_url}::{source}", "payload": payload})
                elif execution == "error":
                    browser_errors += 1

    source_text = "location.search(keyword/q), location.hash, window.name, postMessage"
    parameters = sorted({item["where"] for item in successful}) or source_text
    if successful:
        status, risk, confidence = "취약", "높음", "확정"
    elif browser_errors:
        status, risk, confidence = "N/A", "낮음", "미확정"
    else:
        status, risk, confidence = "양호", "낮음", "미확정"
    evidence = raw_fact_text("dom_xss", {
        "target_page_count": len(target_pages),
        "source_count": len(sources),
        "payload_count": len(dom_cases),
        "total_tests": total,
        "executed_count": len(successful),
        "executed_points": len(parameters) if successful else 0,
        "sources": source_text,
        "browser_errors": browser_errors,
    })
    reason = ai_pending_text("DOM-based XSS 판정 사유")
    return finalize_report(
        vulnerability, status, risk, evidence, reason, recommendation, successful,
        "; ".join(name for name, _ in dom_cases), confidence, parameters,
    )
def browser_start_failure(error, meta=None):
    evidence = f"Playwright Chromium 시작 실패({type(error).__name__}: {error})로 브라우저 기반 진단을 수행하지 못함"
    targets = {
        "reflected_xss": ("크로스 사이트 스크립팅 (Reflected XSS)", "N/A"),
        "stored_xss": ("크로스 사이트 스크립팅 (Stored XSS)", "N/A"),
        "dom_xss": ("크로스 사이트 스크립팅 (DOM-based XSS)", "DOM Source"),
    }
    return {
        "meta": meta or {},
        "xss_scan_result": {
            key: unavailable(vuln, param, evidence, ai_pending_text("브라우저 실패 사유"), ai_pending_text("브라우저 환경 조치 권고"))
            for key, (vuln, param) in targets.items()
        },
    }
def output_filename():
    timestamp = datetime.now().strftime("%H%M%S")
    for suffix in ["", *[f"_{number:02d}" for number in range(1, 100)]]:
        path = f"xss_ai_verdict_result_{timestamp}{suffix}.json"
        try:
            with open(path, "x", encoding="utf-8"):
                return path
        except FileExistsError:
            continue
    raise RuntimeError(f"결과 파일명 생성 실패: xss_ai_verdict_result_{timestamp}_*.json")


def build_parser():
    parser = argparse.ArgumentParser(description="Base URL 하나를 기준으로 같은 출처 페이지와 폼을 크롤링해 XSS를 진단합니다.")
    parser.add_argument("base_url", nargs="?", default=BASE_URL, help=f"기본값: {BASE_URL}")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH, help="링크 크롤링 깊이")
    parser.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES, help="최대 크롤링 페이지 수")
    parser.add_argument(
        "--scan",
        action="append",
        choices=["reflected", "stored", "dom"],
        default=[],
        help="실행할 XSS 진단 유형. 여러 번 지정 가능. 미지정 시 전체 실행",
    )
    parser.add_argument(
        "--allow-post",
        action="append",
        default=["/src/inquiry/create.php"],
        help="Stored XSS 테스트를 허용할 POST action 경로. 예: --allow-post /src/inquiry/create.php",
    )
    parser.add_argument("--cleanup-url", default="", help="진단 후 token 파라미터로 테스트 데이터를 삭제할 URL. 예: http://127.0.0.1:5000/board/cleanup")
    parser.add_argument("--login-url", default="/auth/login.php", help="로그인 처리 URL. 기본값: /auth/login.php")
    parser.add_argument("--login-id-field", default="id", help="로그인 ID input name. 기본값: id")
    parser.add_argument("--login-pw-field", default="pw", help="로그인 비밀번호 input name. 기본값: pw")
    parser.add_argument("--register-if-needed", action="store_true", help="로그인 실패 시 동일 계정 정보로 회원가입 후 다시 로그인")
    parser.add_argument("--register-url", default="/auth/register.php", help="회원가입 처리 URL. 기본값: /auth/register.php")
    parser.add_argument("--register-name", default="XSS Tester", help="자동 회원가입 시 사용할 이름")
    parser.add_argument("--register-name-field", default="name", help="회원가입 이름 input name. 기본값: name")
    parser.add_argument("--headed", action="store_true", help="진단 브라우저 창을 표시")
    return parser

def main():
    env_loaded = load_env_file()
    env_loaded = load_env_file(os.path.join(os.path.dirname(__file__), ".env")) or env_loaded
    api_key_source = normalize_openai_api_key_env()
    args = build_parser().parse_args()
    session = requests.Session()
    auth_result = authenticate(session, args)
    pages, forms = crawl(session, args.base_url, args.max_depth, args.max_pages)
    reflected_targets = reflected_targets_from(pages, forms)
    ai_context = build_ai_scan_context(pages, forms, reflected_targets)
    meta = {
        "base_url": args.base_url,
        "auth": auth_result,
        "crawled_pages": len(pages),
        "discovered_forms": len(forms),
        "ai": {
            "enabled": AI_ANALYSIS_ENABLED,
            "mode": "ai_final_verdict",
            "env_loaded": env_loaded,
            "api_key_available": bool(os.getenv("OPENAI_API_KEY")),
            "api_key_source": api_key_source,
            "model": os.getenv("OPENAI_MODEL", AI_MODEL),
            "used": False,
            "status": "not_run",
            "selection_policy": {
                "diagnosis_flow": "Python deterministic scanner가 발견 후보와 전체 payload 조합을 검증",
                "ai_role": "AI가 raw evidence 기반으로 status, risk, confidence, evidence, reason, recommendation 최종 생성",
                "evidence_format": "지점 수, payload 수, 총 테스트 횟수, 성공 횟수, 오류 수 중심의 기계형 요약",
            },
        },
    }

    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=not args.headed)
        except Exception as error:
            final_result = browser_start_failure(error, meta)
        else:
            try:
                scan_types = set(args.scan or ["reflected", "stored", "dom"])
                scan_results = {}
                if "reflected" in scan_types:
                    scan_results["reflected_xss"] = scan_reflected_xss(browser, session, reflected_targets)
                if "stored" in scan_types:
                    scan_results["stored_xss"] = scan_stored_xss(browser, session, forms, pages, args.allow_post, args.cleanup_url)
                if "dom" in scan_types:
                    scan_results["dom_xss"] = scan_dom_xss(browser, session, pages)
                final_result = {
                    "meta": meta,
                    "xss_scan_result": scan_results,
                }
                final_result["meta"]["ai"].update(enhance_result_with_ai(final_result, ai_context))
            finally:
                browser.close()

    output_path = output_filename()
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(final_result, file, ensure_ascii=False, indent=4)
    print(f"Saved scan result: {output_path}")


if __name__ == "__main__":
    main()
