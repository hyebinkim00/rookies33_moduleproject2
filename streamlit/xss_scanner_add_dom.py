import argparse
import html
import json
import secrets
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
# BASE_URL = "http://127.0.0.1:5000"
DEFAULT_MAX_DEPTH = 2
DEFAULT_MAX_PAGES = 30
LOGIN_ID = "user05"
LOGIN_PW = "user05"
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


def payload_text(successful, default_payloads):
    payloads = [item["payload"] for item in successful]
    return "; ".join(payloads) if payloads else default_payloads


def finalize_report(vulnerability, status, risk, evidence, reason, recommendation,
                    successful, default_payloads, confidence, parameters):
    parameter_text = "; ".join(parameters) if isinstance(parameters, list) else parameters
    return result(
        vulnerability, parameter_text, status, risk, evidence, reason,
        recommendation, payload_text(successful, default_payloads), confidence,
    )


def scan_reflected_xss(browser, session, targets):
    vulnerability = "크로스 사이트 스크립팅 (Reflected XSS)"
    recommendation = "검색어, 필터, 조회 파라미터 등 URL 기반 입력값을 HTML 본문·속성·스크립트 등 출력 위치에 맞게 인코딩할 것. 추가로 CSP를 적용해 스크립트 실행 가능성을 낮추고, 공통 출력 함수 또는 템플릿 자동 이스케이프 적용 여부를 점검할 것"
    test_cases = TEST_CASES
    if not targets:
        return unavailable(
            vulnerability, "N/A",
            "크롤링된 페이지에서 GET 파라미터 또는 GET 폼 입력값을 찾지 못해 Reflected XSS 자동 진단을 수행하지 못함",
            "반사형 XSS는 URL 파라미터 또는 GET 폼 입력이 응답에 즉시 반영되는 지점에서 주로 발생하나, 현재 크롤링 범위에서는 해당 후보가 확인되지 않음",
            "검색, 조회, 필터, 정렬 등 URL 기반 입력 기능을 점검 범위에 포함하고, 발견된 입력값은 출력 컨텍스트에 맞게 인코딩할 것",
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
        evidence = (
            f"크롤링으로 발견한 GET 입력 후보 {len(targets)}개에 대표 XSS 페이로드 {len(test_cases)}개를 각각 전송한 결과, "
            f"총 {total}회 중 "
            f"{len(successful)}회가 실제 브라우저에서 실행됐고 실행 확인 지점은 {len(parameters)}개임. "
            f"사전 반영 점검 결과는 {reflection}. 각 경고창 메시지가 테스트 고유 식별자와 일치함. "
            f"브라우저 진단 오류 {browser_errors}건"
        )
        reason = "GET 입력값이 응답 페이지에 실행 가능한 HTML/스크립트 컨텍스트로 반영되었고, 브라우저에서 고유 식별자 alert 실행까지 확인됨. 단순 문자열 반영이 아니라 사용자 입력이 JavaScript 실행으로 이어져 Reflected XSS 취약점으로 판단함"
    elif browser_errors:
        status, risk, confidence = "N/A", "낮음", "미확정"
        evidence = (
            f"크롤링으로 발견한 GET 입력 지점 {len(targets)}개를 진단했으나 브라우저 검증 오류가 "
            f"{browser_errors}건 발생해 JavaScript 실행 여부를 확정하지 못함. {reflection}"
        )
        reason = "요청 대상은 확인됐으나 브라우저 자동화 단계에서 오류가 발생해 payload 실행 여부를 검증하지 못함. 네트워크 지연, 인증 세션, 브라우저 실행 환경을 확인한 뒤 재진단이 필요함"
    else:
        status, risk, confidence = "양호", "낮음", "미확정"
        evidence = (
            f"크롤링으로 발견한 GET 입력 후보 {len(targets)}개에 대표 XSS 페이로드 {len(test_cases)}개를 각각 전송했으나 "
            f"총 {total}회 모두 "
            f"브라우저 alert 실행은 확인되지 않음. 사전 반영 점검 결과는 {reflection}"
        )
        reason = "발견된 GET 입력 지점에 대표 XSS payload를 주입했으나 브라우저에서 실행 증거가 확인되지 않음. 현재 범위에서는 Reflected XSS가 재현되지 않았지만, 테스트하지 않은 파라미터와 출력 컨텍스트는 별도 검토가 필요함"
    return finalize_report(
        vulnerability, status, risk, evidence, reason, recommendation, successful,
        "; ".join(signature for _, signature, _ in test_cases), confidence, parameters,
    )


def scan_stored_xss(browser, session, forms, pages, allow_posts, cleanup_url):
    vulnerability = "크로스 사이트 스크립팅 (Stored XSS)"
    recommendation = "게시글, 댓글, 문의 내용 등 저장 데이터는 조회·수정·관리자 화면 모두에서 출력 위치에 맞게 인코딩할 것. 기존 저장 데이터에 악성 스크립트가 남아 있는지 점검하고, CSP와 입력 검증을 보조 통제로 적용할 것"
    test_cases = TEST_CASES
    max_stored_submissions = MAX_STORED_SUBMISSIONS or len(test_cases)
    post_forms = [form for form in forms if form.method == "POST" and not dangerous_url(form.action_url) and allowed_post(form.action_url, allow_posts)]
    if not post_forms:
        return unavailable(
            vulnerability, "N/A",
            "크롤링된 POST 폼 중 사용자가 허용한 저장형 테스트 대상이 없어 Stored XSS 자동 진단을 수행하지 않음",
            "저장형 XSS 진단은 실제 데이터 생성이 발생할 수 있어 현재 설정에서는 --allow-post로 허용된 경로만 테스트 대상으로 사용함",
            "게시글, 댓글, 문의 등록 등 저장성 POST action을 확인한 뒤 실습 환경에서 --allow-post로 명시하고, 삭제 기능이 있으면 --cleanup-url을 함께 지정할 것",
        )

    view_urls = sorted(set(pages) | {form.page_url for form in post_forms})
    cleanup_evidence = "cleanup URL이 지정되지 않아 테스트 데이터가 서비스에 남아 있을 수 있음"
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
            cleanup_evidence = "진단 데이터 삭제 요청 완료" if response.ok else "진단 데이터 삭제 요청 실패"
        except requests.RequestException:
            cleanup_evidence = "진단 데이터 삭제 요청 실패"

    parameters = sorted({item["where"] for item in successful}) or sorted(
        {f"{form.action_url}::{field.name}" for form in post_forms for field in stored_target_fields(form)}
    )
    total = total_tests
    stored_scope = (
        f"허용된 POST 저장 입력 지점 {len(parameters)}개에 대표 XSS 페이로드 {len(test_cases)}개 중 "
        f"{max_stored_submissions}회까지 전송한 결과"
        if max_stored_submissions < len(test_cases)
        else f"허용된 POST 저장 입력 지점 {len(parameters)}개에 대표 XSS 페이로드 {len(test_cases)}개를 각각 전송한 결과"
    )
    if successful:
        status, risk, confidence = "취약", "높음", "확정"
        evidence = (
            f"{stored_scope}, 총 {total}회 중 "
            f"{stored_count}개가 조회 가능한 페이지에 유지됐고 {len(successful)}개가 실제 브라우저에서 실행됨. "
            f"각 경고창 메시지가 테스트 고유 식별자와 일치함. 브라우저 진단 오류 {browser_errors}건. {cleanup_evidence}"
        )
        reason = "POST 입력값이 서버에 저장된 뒤 조회 페이지에서 실행 가능한 HTML/스크립트로 렌더링되었고, 재조회 시 브라우저 alert 실행까지 확인됨. 저장 데이터 출력 구간에 적절한 HTML 이스케이프가 적용되지 않아 Stored XSS 취약점으로 판단함"
    elif browser_errors:
        status, risk, confidence = "N/A", "낮음", "미확정"
        evidence = (
            f"사용자가 허용한 POST 저장 입력 지점에서 {stored_count}개 페이로드의 저장 반영은 확인됐으나 "
            f"브라우저 검증 오류 {browser_errors}건으로 실행 여부를 확정하지 못함. {cleanup_evidence}"
        )
        reason = "payload가 저장 또는 반영된 정황은 있으나 브라우저 자동화 오류로 실제 실행 여부를 확정하지 못함. 인증 세션, 조회 URL 접근성, 브라우저 실행 환경을 확인한 뒤 재진단이 필요함"
    elif stored_count:
        status, risk, confidence = "양호", "중간", "미확정"
        evidence = (
            f"총 {total}개 Stored XSS 페이로드 중 {stored_count}개가 조회 페이지에 유지됐지만 실제 브라우저에서 "
            f"고유 식별자가 포함된 경고창 실행은 확인되지 않음. {cleanup_evidence}"
        )
        reason = "payload 식별자가 조회 페이지에 남아 저장 반영은 확인됐지만, 브라우저에서 JavaScript 실행은 확인되지 않음. 출력 인코딩이나 필터링으로 실행이 차단됐을 가능성이 있으나, 저장 데이터가 HTML에 노출되는 지점은 계속 점검이 필요함"
    else:
        status, risk, confidence = "양호", "낮음", "미확정"
        evidence = (
            f"{stored_scope}, 총 {total}회 모두 저장 반영 및 "
            f"브라우저 실행 증거는 확인되지 않음. {cleanup_evidence}"
        )
        reason = "허용된 POST 저장 지점에 payload를 전송했으나 조회 가능한 페이지에서 저장 반영과 실행 증거가 확인되지 않음. 현재 범위에서는 Stored XSS가 재현되지 않았지만, 다른 조회 화면이나 관리자 화면에 저장값이 출력될 수 있는지 추가 확인이 필요함"
    return finalize_report(
        vulnerability, status, risk, evidence, reason, recommendation, successful,
        "; ".join(signature for _, signature, _ in test_cases), confidence, parameters,
    )


def scan_dom_xss(browser, session, pages):
    vulnerability = "크로스 사이트 스크립팅 (DOM-based XSS)"
    recommendation = "location.search, location.hash, window.name, postMessage 등 브라우저 입력값을 innerHTML, document.write, eval 같은 위험 DOM Sink에 직접 전달하지 말 것. 화면 출력은 textContent, setAttribute의 안전한 사용, 검증된 sanitizer로 처리하고 CSP를 보조 통제로 적용할 것"
    dom_cases = limited_cases(DOM_CASES, MAX_DOM_PAYLOADS_PER_TARGET)
    if not pages:
        return unavailable(
            vulnerability, "DOM Source",
            "크롤링된 HTML 페이지가 없어 DOM-based XSS 자동 진단을 수행하지 못함",
            "DOM XSS는 브라우저가 HTML과 JavaScript를 실행해야 검증할 수 있으나 현재 접근 가능한 HTML 페이지가 없음",
            "진단 대상 URL, 인증 상태, 크롤링 범위를 확인하고 클라이언트 JavaScript가 포함된 화면을 점검 범위에 포함할 것",
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
        evidence = (
            f"선별한 HTML 페이지 {len(target_pages)}개에서 {source_text} 경로로 "
            f"DOM XSS 테스트 {total}회를 수행한 결과, {len(successful)}개가 클라이언트 JavaScript에 의해 실행됨. "
            f"각 경고창 메시지가 테스트 고유 식별자와 일치함. 브라우저 진단 오류 {browser_errors}건"
        )
        reason = "클라이언트 JavaScript가 location.search, location.hash, window.name, postMessage 등 사용자 제어 DOM Source 값을 실행 가능한 DOM Sink로 전달했고, 브라우저에서 alert 실행이 확인됨. 서버 응답 반영이 아니라 브라우저 내부 DOM 처리 과정에서 발생한 DOM-based XSS로 판단함"
    elif browser_errors:
        status, risk, confidence = "N/A", "낮음", "미확정"
        evidence = (
            f"선별한 HTML 페이지 {len(target_pages)}개에 총 {total}개 DOM XSS 테스트를 수행했으나 브라우저 검증 오류 "
            f"{browser_errors}건으로 실행 여부를 확정하지 못함"
        )
        reason = "DOM 입력 주입 대상 페이지는 확인됐으나 브라우저 자동화 오류로 클라이언트 실행 여부를 확정하지 못함. 동적 로딩 시간, 스크립트 오류, 브라우저 실행 환경을 확인한 뒤 재진단이 필요함"
    else:
        status, risk, confidence = "양호", "낮음", "미확정"
        evidence = (
            f"선별한 HTML 페이지 {len(target_pages)}개에서 {source_text} 경로로 "
            f"DOM XSS 테스트 {total}회를 수행했으나 브라우저 alert 실행은 확인되지 않음. "
            "현재 범위에서는 사용자 제어 DOM Source가 위험 DOM Sink로 연결되는 실행 흐름이 재현되지 않음"
        )
        reason = "location.search, location.hash, window.name, postMessage 기반 입력을 주입했으나 브라우저에서 alert 실행은 확인되지 않음. 현재 범위에서는 사용자 제어 DOM Source가 위험 DOM Sink로 이어지는 흐름이 재현되지 않았으며, 클라이언트 기능이 제한적인 서비스 구조일 가능성이 있음"
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
            key: unavailable(vuln, param, evidence, "브라우저 실행 환경 오류로 진단을 완료하지 못함", "Playwright 및 Chromium 설치·실행 상태를 확인할 것")
            for key, (vuln, param) in targets.items()
        },
    }
def output_filename():
    timestamp = datetime.now().strftime("%H%M%S")
    for suffix in ["", *[f"_{number:02d}" for number in range(1, 100)]]:
        path = f"xss_scan_result_{timestamp}{suffix}.json"
        try:
            with open(path, "x", encoding="utf-8"):
                return path
        except FileExistsError:
            continue
    raise RuntimeError(f"결과 파일명 생성 실패: xss_scan_result_{timestamp}_*.json")


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
    args = build_parser().parse_args()
    session = requests.Session()
    auth_result = authenticate(session, args)
    pages, forms = crawl(session, args.base_url, args.max_depth, args.max_pages)
    reflected_targets = reflected_targets_from(pages, forms)
    meta = {
        "base_url": args.base_url,
        "auth": auth_result,
        "crawled_pages": len(pages),
        "discovered_forms": len(forms),
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
            finally:
                browser.close()

    output_path = output_filename()
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(final_result, file, ensure_ascii=False, indent=4)
    print(f"Saved scan result: {output_path}")


if __name__ == "__main__":
    main()
