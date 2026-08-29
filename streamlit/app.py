import json
import os
import hashlib
import re
import base64
from urllib.parse import urljoin, urlsplit
from html import unescape

import altair as alt
import pandas as pd
import streamlit as st
import requests
import streamlit.components.v1 as components

from datetime import datetime
from html import escape
from ai_analyzer import analyze_results, ask_security_question
from hf_analyzer import analyze_sqli
from pdf_report import generate_pdf_report
from xlsx_report import generate_xlsx_report


# Streamlit 기본 설정
st.set_page_config(
    page_title="AI 기반 공공 민원포털 취약점 자동 진단 시스템",
    layout="wide"
)


st.markdown(
    """
    <style>
    /* 전체 화면 기본 간격 */
    .block-container {
        padding-top: 2.1rem;
        padding-bottom: 2.5rem;
    }

    /* 메인 타이틀 */
    h1 {
        letter-spacing: -0.02em;
        line-height: 1.15;
    }


    /* 보안 뉴스 티커 */
    .security-ticker {
        position: relative;
        overflow: hidden;

        margin: 0.2rem 0 1.0rem 0;
        height: 48px;

        border: 1px solid rgba(148, 163, 184, 0.16);
        border-radius: 10px;

        background:
            linear-gradient(
                90deg,
                rgba(17, 24, 39, 0.95),
                rgba(15, 23, 42, 0.96)
            );

        box-shadow:
            inset 0 1px 0 rgba(255, 255, 255, 0.02);
    }

    .security-ticker::before {
        content: "Security Warning!!";
        position: absolute;
        z-index: 3;
        left: 0;
        top: 0;

        display: flex;
        align-items: center;

        height: 100%;
        padding: 0 14px;

        background:
            linear-gradient(
                135deg,
                rgba(220, 38, 38, 0.95),
                rgba(185, 28, 28, 0.95)
            );

        color: #FFFFFF;

        font-size: 17px;
        font-weight: 800;
        letter-spacing: 0.8px;
    }

    .ticker-track {
        display: inline-flex;
        align-items: center;

        min-width: max-content;
        height: 100%;

        padding-left: 135px;

        animation: tickerMove 54s linear infinite;
    }

    .ticker-track:hover {
        animation-play-state: paused;
    }

    .ticker-item {
        display: inline-flex;
        align-items: center;

        margin-right: 42px;

        color: #E5E7EB;

        font-size: 21px;
        font-weight: 650;

        white-space: nowrap;
    }

    .ticker-dot {
        display: inline-block;

        width: 7px;
        height: 7px;

        margin-right: 9px;

        border-radius: 50%;

        background: #F87171;

        box-shadow:
            0 0 8px rgba(248, 113, 113, 0.65);
    }

    .ticker-item strong {
        color: #FFFFFF;
        margin-right: 5px;
    }

    @keyframes tickerMove {
        from {
            transform: translateX(0);
        }

        to {
            transform: translateX(-50%);
        }
    }

    /* 제목 아래 은은한 포인트 라인 */
    .ui-accent-line {
        height: 2px;
        margin: 0.25rem 0 0.95rem 0;
        border-radius: 999px;
        background:
            linear-gradient(
                90deg,
                rgba(59, 130, 246, 0.95) 0%,
                rgba(96, 165, 250, 0.55) 28%,
                rgba(59, 130, 246, 0.16) 60%,
                transparent 100%
            );
        background-size: 180% 100%;
        animation: accentFlow 4.8s ease-in-out infinite alternate;
    }

    @keyframes accentFlow {
        from {
            background-position: 0% 50%;
        }
        to {
            background-position: 100% 50%;
        }
    }

    /* metric 카드 */
    div[data-testid="stMetric"] {
        position: relative;
        overflow: hidden;

        min-height: 108px;
        padding: 1rem 1.05rem;

        border: 1px solid rgba(148, 163, 184, 0.15);
        border-radius: 14px;

        background:
            linear-gradient(
                145deg,
                rgba(255, 255, 255, 0.035),
                rgba(255, 255, 255, 0.012)
            );

        box-shadow:
            inset 0 1px 0 rgba(255, 255, 255, 0.025);

        transition:
            transform 0.20s ease,
            border-color 0.20s ease,
            box-shadow 0.20s ease,
            background 0.20s ease;
    }

    div[data-testid="stMetric"]::before {
        content: "";
        position: absolute;
        top: 0;
        left: -55%;

        width: 38%;
        height: 100%;

        background:
            linear-gradient(
                90deg,
                transparent,
                rgba(96, 165, 250, 0.07),
                transparent
            );

        transform: skewX(-16deg);
        transition: left 0.55s ease;
        pointer-events: none;
    }

    div[data-testid="stMetric"]:hover {
        transform: translateY(-3px);

        border-color: rgba(96, 165, 250, 0.48);

        background:
            linear-gradient(
                145deg,
                rgba(37, 99, 235, 0.09),
                rgba(255, 255, 255, 0.018)
            );

        box-shadow:
            0 10px 30px rgba(0, 0, 0, 0.18),
            0 0 20px rgba(59, 130, 246, 0.10);
    }

    div[data-testid="stMetric"]:hover::before {
        left: 125%;
    }

    div[data-testid="stMetricLabel"] {
        color: #A9B7CA;
        font-weight: 650;
    }

    div[data-testid="stMetricValue"] {
        color: #F8FAFC;
        font-weight: 750;
    }

    /* expander */
    div[data-testid="stExpander"] {
        border-radius: 12px;
        overflow: hidden;

        border: 1px solid rgba(148, 163, 184, 0.14);

        transition:
            border-color 0.20s ease,
            box-shadow 0.20s ease,
            transform 0.20s ease;
    }

    div[data-testid="stExpander"]:hover {
        border-color: rgba(96, 165, 250, 0.36);

        box-shadow:
            0 8px 26px rgba(0, 0, 0, 0.14),
            0 0 18px rgba(59, 130, 246, 0.06);
    }

    /* 일반 버튼 */
    div[data-testid="stButton"] button {
        transition:
            transform 0.18s ease,
            border-color 0.18s ease,
            box-shadow 0.18s ease,
            background 0.18s ease;
    }

    div[data-testid="stButton"] button:hover {
        transform: translateY(-1px);
        border-color: rgba(96, 165, 250, 0.62);
        box-shadow: 0 0 16px rgba(59, 130, 246, 0.13);
    }

    /* 다운로드 버튼 */
    div[data-testid="stDownloadButton"] button {
        transition:
            transform 0.18s ease,
            border-color 0.18s ease,
            box-shadow 0.18s ease;
    }

    div[data-testid="stDownloadButton"] button:hover {
        transform: translateY(-1px);
        border-color: rgba(96, 165, 250, 0.62);
        box-shadow: 0 0 16px rgba(59, 130, 246, 0.13);
    }

    /* dataframe 외곽 */
    div[data-testid="stDataFrame"] {
        border-radius: 12px;
        overflow: hidden;
    }

    /* 상세 대시보드 도넛 차트 자체를 컨테이너 정중앙에 고정 */
    div[data-testid="stVegaLiteChart"] {
        display: flex;
        justify-content: center;
        width: 100%;
    }

    div[data-testid="stVegaLiteChart"] > div {
        margin-left: auto !important;
        margin-right: auto !important;
    }


    /* 구분선 */
    hr {
        border-color: rgba(148, 163, 184, 0.13) !important;
    }

    /* 모바일에서는 과한 이동 효과 완화 */
    @media (max-width: 900px) {
        div[data-testid="stMetric"]:hover,
        div[data-testid="stButton"] button:hover,
        div[data-testid="stDownloadButton"] button:hover {
            transform: none;
        }
    }
    </style>
    """,
    unsafe_allow_html=True
)



# 실시간 자동진단 Agent/API 연결
# 통합 API 시작: POST /api/v1/scan/all
# 진행/결과 조회: GET /api/v1/scan/all/{group_id}
DEFAULT_SCANNER_API_URL = "http://127.0.0.1:8001/api/v1/scan/all"


def _portal_origin(target_url):
    """입력 URL에서 포털의 scheme://host:port/ 루트 주소를 만듭니다."""
    parsed = urlsplit(str(target_url).strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("진단 대상 URL에서 포털 주소를 확인할 수 없습니다.")
    return f"{parsed.scheme}://{parsed.netloc}/"


def discover_latest_inquiry_attachments(target_url, max_details=12):
    """
    공개 민원 목록에서 최근 글을 순서대로 확인해,
    첨부파일이 존재하는 가장 최근 민원의 파일을 가져옵니다.

    detail.php는 로그인 세션이 필요하므로,
    포털 테스트 계정(user05/user05)으로 세션을 만든 뒤 상세 페이지를 조회합니다.

    중요:
    - 통합 스캐너 실행 전에 호출해야 Stored XSS 테스트 글보다
      사용자가 직전에 등록한 실제 민원을 우선 확인할 수 있습니다.
    - create.php는 수정하지 않습니다.
    """
    portal_root = _portal_origin(target_url)
    list_url = urljoin(portal_root, "inquiry/list.php")
    login_url = urljoin(portal_root, "auth/login.php")

    session = requests.Session()

    # 현재 포털 seed/XSS 진단 환경의 기본 테스트 계정
    login_response = session.post(
        login_url,
        data={
            "id": "user05",
            "pw": "user05"
        },
        timeout=15,
        allow_redirects=True
    )
    login_response.raise_for_status()

    # 로그인 실패 문구가 그대로 남아 있으면 인증 실패로 처리
    if "아이디 또는 비밀번호가 틀렸습니다." in login_response.text:
        raise ValueError(
            "민원 상세 조회용 테스트 계정(user05/user05) 로그인에 실패했습니다."
        )

    list_response = session.get(
        list_url,
        timeout=15
    )
    list_response.raise_for_status()

    detail_ids = re.findall(
        r'/inquiry/detail\.php\?id=(\d+)',
        list_response.text,
        flags=re.IGNORECASE
    )

    # 중복 제거 + 화면에 표시된 최신 순서 유지
    detail_ids = list(dict.fromkeys(detail_ids))

    for inquiry_id in detail_ids[:max_details]:
        detail_url = urljoin(
            portal_root,
            f"inquiry/detail.php?id={inquiry_id}"
        )

        detail_response = session.get(
            detail_url,
            timeout=15
        )

        # 인증이 필요한 상세 페이지이므로 401은 별도 메시지로 처리
        if detail_response.status_code == 401:
            raise ValueError(
                "민원 상세 페이지 인증에 실패했습니다. "
                "user05/user05 테스트 계정 상태를 확인해주세요."
            )

        detail_response.raise_for_status()

        # detail.php의 첨부파일 링크:
        # <a href="/uploads/파일명">원본파일명</a>
        attachment_matches = re.findall(
            r'<a[^>]+href=["\']([^"\']*?/uploads/[^"\']+)["\'][^>]*>'
            r'\s*(.*?)\s*</a>',
            detail_response.text,
            flags=re.IGNORECASE | re.DOTALL
        )

        if not attachment_matches:
            continue

        attachments = []

        for href, label in attachment_matches:
            clean_href = unescape(href).strip()
            clean_label = unescape(
                re.sub(r"<[^>]+>", "", label)
            ).strip()

            file_url = urljoin(
                portal_root,
                clean_href
            )

            if not clean_label:
                clean_label = os.path.basename(
                    urlsplit(file_url).path
                )

            file_response = session.get(
                file_url,
                timeout=30
            )
            file_response.raise_for_status()

            attachments.append(
                {
                    "inquiry_id": inquiry_id,
                    "detail_url": detail_url,
                    "file_url": file_url,
                    "filename": clean_label,
                    "content": file_response.content
                }
            )

        if attachments:
            return attachments

    return []


def analyze_actual_uploaded_files(
    scanner_api_url,
    target_url,
    attachments
):
    """
    통합 API에 이미 구현된 FileFormatNameAnalyzer 전용 엔드포인트를 호출해
    실제 업로드 파일 자체를 정적 분석합니다.

    기존 /api/v1/scan/all 및 create.php 블랙박스 9건 진단은 그대로 둡니다.
    """
    api_root = str(scanner_api_url).strip()

    marker = "/api/v1/scan/all"
    if marker in api_root:
        api_root = api_root.split(marker, 1)[0]

    analyze_url = (
        api_root.rstrip("/")
        + "/api/v1/analyze/file-upload/trigger"
    )

    reports = []

    for attachment in attachments:
        encoded_content = base64.b64encode(
            attachment["content"]
        ).decode("ascii")

        response = requests.post(
            analyze_url,
            json={
                "target_url": attachment["file_url"],
                "filename": attachment["filename"],
                "content_base64": encoded_content
            },
            timeout=60
        )
        response.raise_for_status()

        payload = response.json()
        result_payload = (
            payload.get("result", {})
            if isinstance(payload, dict)
            else {}
        )

        raw_items = result_payload.get(
            "results",
            []
        )

        normalized_items = []

        for item in raw_items:
            if not isinstance(item, dict):
                continue

            item_copy = item.copy()
            item_copy["source_type"] = "실제 업로드 파일 진단"
            item_copy["source_file"] = attachment["filename"]

            normalized_items.append(
                item_copy
            )

        reports.append(
            {
                "filename": attachment["filename"],
                "file_url": attachment["file_url"],
                "detail_url": attachment["detail_url"],
                "inquiry_id": attachment["inquiry_id"],
                "results": normalized_items,
                "has_vulnerability": any(
                    item.get("status") == "취약"
                    for item in normalized_items
                )
            }
        )

    return reports


def _extract_unified_result_items(payload):
    """
    통합 API의 스캐너별 result 구조에서
    실제 취약점 결과 객체만 재귀적으로 추출합니다.

    지원 예:
    - {"results": [...]}
    - {"xss_scan_result": {...}}
    - 파일업로드 결과 {"results": [...]}
    """
    extracted = []

    if isinstance(payload, list):
        for value in payload:
            extracted.extend(
                _extract_unified_result_items(
                    value
                )
            )
        return extracted

    if not isinstance(payload, dict):
        return extracted

    # 실제 진단 결과 객체
    if (
        "vulnerability" in payload
        and "status" in payload
    ):
        return [
            payload.copy()
        ]

    # 메타데이터는 제외하고 내부 결과만 재귀 탐색
    for key, value in payload.items():
        if key in {
            "meta",
            "enabled",
            "errors"
        }:
            continue

        if isinstance(
            value,
            (dict, list)
        ):
            extracted.extend(
                _extract_unified_result_items(
                    value
                )
            )

    return extracted


def fetch_realtime_scan_results(
    api_url,
    target_url
):
    """
    통합 자동진단 API를 실행한 뒤 group_id를 받아
    GET /api/v1/scan/all/{group_id}를 폴링하고,
    파일업로드 / SQLi / 세션 / XSS 결과를 하나의 배열로 반환합니다.
    """
    import time

    start_response = requests.post(
        api_url,
        json={
            "base_url": target_url,
            "confirm_authorized": True
        },
        timeout=30
    )

    start_response.raise_for_status()

    start_payload = (
        start_response.json()
    )

    group_id = (
        start_payload.get(
            "group_id"
        )
        if isinstance(
            start_payload,
            dict
        )
        else None
    )

    if not group_id:
        raise ValueError(
            "통합 API 응답에서 group_id를 "
            "찾을 수 없습니다."
        )

    status_url = (
        f"{api_url.rstrip('/')}/"
        f"{group_id}"
    )

    started_at = time.time()
    poll_timeout = 300
    poll_interval = 1.0

    final_payload = None

    while True:

        status_response = requests.get(
            status_url,
            timeout=30
        )

        status_response.raise_for_status()

        current_payload = (
            status_response.json()
        )

        overall_status = str(
            current_payload.get(
                "overall_status",
                ""
            )
        ).strip().lower()

        if overall_status in {
            "done",
            "partial_error"
        }:
            final_payload = (
                current_payload
            )
            break

        if (
            time.time()
            - started_at
            > poll_timeout
        ):
            raise requests.exceptions.Timeout(
                "통합 자동진단 결과 대기 시간이 "
                "초과되었습니다."
            )

        time.sleep(
            poll_interval
        )

    jobs = final_payload.get(
        "jobs",
        {}
    )

    if not isinstance(
        jobs,
        dict
    ):
        raise ValueError(
            "통합 API 응답에서 jobs 객체를 "
            "찾을 수 없습니다."
        )

    source_type_map = {
        "file_upload": "파일 업로드 진단",
        "sqli": "SQL Injection 진단",
        "session": "세션 관리 진단",
        "xss": "웹 XSS 진단"
    }

    combined_results = []
    job_errors = []

    for scanner_name in [
        "file_upload",
        "sqli",
        "session",
        "xss"
    ]:

        job = jobs.get(
            scanner_name
        )

        if not isinstance(
            job,
            dict
        ):
            continue

        job_status = str(
            job.get(
                "status",
                ""
            )
        ).strip().lower()

        if (
            job_status == "error"
            or job.get("error")
        ):
            job_errors.append(
                f"{scanner_name}: "
                f"{job.get('error') or '진단 오류'}"
            )
            continue

        job_result = job.get(
            "result"
        )

        items = (
            _extract_unified_result_items(
                job_result
            )
        )

        for item in items:

            item_copy = (
                item.copy()
            )

            item_copy.setdefault(
                "source_type",
                source_type_map.get(
                    scanner_name,
                    "실시간 자동진단"
                )
            )

            item_copy.setdefault(
                "source_file",
                job.get(
                    "target_url"
                )
                or target_url
            )

            combined_results.append(
                item_copy
            )

    if not combined_results:
        detail = (
            " / ".join(
                job_errors
            )
            if job_errors
            else "진단 결과 없음"
        )

        raise ValueError(
            "통합 자동진단 결과에서 "
            f"유효한 진단 항목을 찾지 못했습니다: {detail}"
        )

    return combined_results


# 자동 진단 결과는 로컬 JSON 파일이 아니라 통합 API 실시간 결과만 사용합니다.
# 이전 버전의 FILE_UPLOAD_RESULTS / XSS_RESULT_FILE / SQLI_RESULT_FILE /
# SESSION_RESULT_FILE 및 load_results() 의존성을 제거했습니다.
results = st.session_state.get(
    "realtime_scan_results",
    []
)

file_upload_data = []

result_data = {
    "filenames": [],
    "saved_at": [
        st.session_state.get(
            "realtime_scanned_at",
            datetime.now().isoformat()
        )
    ] if results else []
}


# 수동 진단 결과는 사용자가 업로드한 파일을 session_state에 저장해 사용합니다.
# 기존 manual_results.json 자동 로드는 제거하여,
# 실제 사용자 수동 진단 결과와 자동 진단 결과를 비교하는 흐름으로 통일합니다.
manual_results = st.session_state.get(
    "uploaded_manual_results",
    []
)

manual_upload_name = st.session_state.get(
    "manual_upload_name",
    ""
)



# 자동 진단 결과 검증
def validate_results(results):
    required_fields = [
        "vulnerability",
        "status",
        "risk",
        "evidence",
        "reason",
        "recommendation"
    ]

    valid_status = [
        "양호",
        "취약",
        "N/A"
    ]

    valid_risk = [
        "낮음",
        "중간",
        "높음"
    ]

    errors = []

    if not isinstance(results, list):
        return ["results 값은 배열 형식이어야 합니다."]

    for index, item in enumerate(results):

        if not isinstance(item, dict):
            errors.append(
                f"{index + 1}번째 결과가 객체 형식이 아닙니다."
            )
            continue

        for field in required_fields:
            if field not in item:
                errors.append(
                    f"{index + 1}번째 결과에 "
                    f"'{field}' 항목이 없습니다."
                )

        if (
            "status" in item
            and item["status"] not in valid_status
        ):
            errors.append(
                f"{index + 1}번째 결과의 status 값이 "
                f"올바르지 않습니다: {item['status']}"
            )

        if (
            "risk" in item
            and item["risk"] not in valid_risk
        ):
            errors.append(
                f"{index + 1}번째 결과의 risk 값이 "
                f"올바르지 않습니다: {item['risk']}"
            )

    return errors



# 수동 진단 결과 검증
def validate_manual_results(manual_results):
    required_fields = [
        "vulnerability",
        "status"
    ]

    valid_status = [
        "양호",
        "취약",
        "N/A"
    ]

    errors = []

    if not isinstance(manual_results, list):
        return ["수동 진단 결과는 배열 형식이어야 합니다."]

    for index, item in enumerate(manual_results):

        if not isinstance(item, dict):
            errors.append(
                f"{index + 1}번째 수동 진단 결과가 "
                "객체 형식이 아닙니다."
            )
            continue

        for field in required_fields:
            if field not in item:
                errors.append(
                    f"{index + 1}번째 수동 진단 결과에 "
                    f"'{field}' 항목이 없습니다."
                )

        if (
            "status" in item
            and item["status"] not in valid_status
        ):
            errors.append(
                f"{index + 1}번째 수동 진단 결과의 "
                f"status 값이 올바르지 않습니다: "
                f"{item['status']}"
            )

    # 동일 취약점의 여러 파라미터 점검을 허용합니다.
    # 예: 같은 SQL Injection 항목을 keyword, id, pw 등 여러 행으로 작성 가능
    return errors


def _normalize_manual_column_name(value):
    return re.sub(
        r"\s+",
        "",
        str(value).strip().lower()
    )


def _normalize_vulnerability_key(value):
    """
    수동/자동 결과의 취약점명을 비교할 때 표기 차이를 정규화합니다.

    예:
    - SQL Injection (Error-based)
    - SQL Injection - Error Based
    - SQL Injection (Error Based)

    위 표기들은 모두 동일한 비교 키로 처리합니다.
    기존 비교 로직은 유지하고, 취약점명 매칭에만 적용됩니다.
    """
    normalized = str(value or "").strip().lower()

    # 유니코드 대시/구분자를 일반 공백으로 통일합니다.
    normalized = normalized.replace("–", "-").replace("—", "-")

    # 괄호, 하이픈, 슬래시 등 표기용 문장부호 차이를 무시합니다.
    normalized = re.sub(
        r"[\(\)\[\]\{\}_\-:/]+",
        " ",
        normalized
    )

    # 일부 스캐너가 붙여 쓰는 대표 표현도 동일하게 취급합니다.
    normalized = re.sub(r"\berrorbased\b", "error based", normalized)
    normalized = re.sub(r"\bbooleanbased\b", "boolean based", normalized)
    normalized = re.sub(r"\btimebased\b", "time based", normalized)

    # 연속 공백 정리
    normalized = re.sub(r"\s+", " ", normalized).strip()

    # 수동진단의 Error-based 항목과 자동진단의
    # Error/Boolean-based 통합 항목을 동일한 비교 키로 매핑합니다.
    # 실제 스캐너 판정값/표시명 자체는 변경하지 않고 비교 키에만 적용합니다.
    if normalized == "sql injection error based":
        normalized = "sql injection error boolean based"

    return normalized


def _normalize_manual_records(records):
    """
    JSON/CSV/XLSX에서 읽은 레코드를 대시보드 공통 스키마로 변환합니다.

    필수:
      vulnerability / status

    선택:
      url / parameter / payload / reason / evidence
    """
    if not isinstance(records, list):
        raise ValueError(
            "수동 진단 결과는 배열(목록) 형식이어야 합니다."
        )

    normalized_records = []

    vulnerability_aliases = {
        "vulnerability",
        "취약점",
        "취약점명",
        "진단항목",
        "진단항목명"
    }

    status_aliases = {
        "status",
        "판정",
        "수동진단",
        "수동진단결과",
        "결과"
    }

    reason_aliases = {
        "reason",
        "근거",
        "판정근거",
        "수동진단근거",
        "비고"
    }

    url_aliases = {
        "url",
        "URL",
        "주소",
        "대상url",
        "대상URL",
        "점검url",
        "점검URL",
        "경로"
    }

    parameter_aliases = {
        "parameter",
        "파라미터",
        "대상파라미터",
        "진단파라미터"
    }

    payload_aliases = {
        "payload",
        "입력값",
        "테스트입력값",
        "테스트값",
        "페이로드"
    }

    evidence_aliases = {
        "evidence",
        "확인내용",
        "점검내용",
        "증적",
        "확인결과"
    }

    for row in records:
        if not isinstance(row, dict):
            continue

        normalized_key_map = {
            _normalize_manual_column_name(key): key
            for key in row.keys()
        }

        def find_value(alias_set):
            for alias in alias_set:
                normalized_alias = _normalize_manual_column_name(
                    alias
                )

                if normalized_alias in normalized_key_map:
                    original_key = normalized_key_map[
                        normalized_alias
                    ]
                    return row.get(original_key)

            return None

        vulnerability = find_value(
            vulnerability_aliases
        )
        status = find_value(
            status_aliases
        )
        reason = find_value(
            reason_aliases
        )
        url = find_value(
            url_aliases
        )
        parameter = find_value(
            parameter_aliases
        )
        payload = find_value(
            payload_aliases
        )
        evidence = find_value(
            evidence_aliases
        )

        item = {
            "vulnerability": (
                str(vulnerability).strip()
                if vulnerability is not None
                else ""
            ),
            "status": (
                str(status).strip()
                if status is not None
                else ""
            )
        }

        if reason is not None and str(reason).strip():
            item["reason"] = str(reason).strip()

        if url is not None and str(url).strip():
            item["url"] = str(url).strip()

        if parameter is not None and str(parameter).strip():
            item["parameter"] = str(parameter).strip()

        if payload is not None and str(payload).strip():
            item["payload"] = str(payload).strip()

        if evidence is not None and str(evidence).strip():
            item["evidence"] = str(evidence).strip()

        # 다운로드 양식은 취약점별로 여러 입력 슬롯을 미리 제공합니다.
        # 사용하지 않은 슬롯(판정/url/파라미터/입력값/근거/확인내용이 모두 비어 있음)은
        # 업로드 시 자동으로 무시합니다.
        has_manual_input = any(
            str(value).strip()
            for value in [
                status,
                url,
                parameter,
                payload,
                reason,
                evidence
            ]
            if value is not None
        )

        if not has_manual_input:
            continue

        normalized_records.append(
            item
        )

    return normalized_records


def parse_manual_upload(uploaded_file):
    """
    사용자가 업로드한 수동 진단 결과 파일을 읽습니다.

    지원 형식:
    - JSON
    - CSV
    - XLSX
    """
    file_name = uploaded_file.name
    extension = os.path.splitext(
        file_name
    )[1].lower()

    file_bytes = uploaded_file.getvalue()

    if extension == ".json":
        try:
            payload = json.loads(
                file_bytes.decode(
                    "utf-8-sig"
                )
            )
        except UnicodeDecodeError:
            payload = json.loads(
                file_bytes.decode(
                    "cp949"
                )
            )

        if isinstance(payload, list):
            records = payload

        elif isinstance(payload, dict):
            if isinstance(
                payload.get("results"),
                list
            ):
                records = payload["results"]

            elif isinstance(
                payload.get("manual_results"),
                list
            ):
                records = payload[
                    "manual_results"
                ]

            else:
                raise ValueError(
                    "JSON 파일에서 results 또는 manual_results 배열을 "
                    "찾을 수 없습니다."
                )

        else:
            raise ValueError(
                "JSON 최상위 형식은 배열 또는 객체여야 합니다."
            )

    elif extension == ".csv":
        from io import BytesIO

        try:
            dataframe = pd.read_csv(
                BytesIO(file_bytes),
                encoding="utf-8-sig",
                keep_default_na=False
            )
        except UnicodeDecodeError:
            dataframe = pd.read_csv(
                BytesIO(file_bytes),
                encoding="cp949",
                keep_default_na=False
            )

        records = dataframe.to_dict(
            "records"
        )

    elif extension == ".xlsx":
        from io import BytesIO

        dataframe = pd.read_excel(
            BytesIO(file_bytes),
            keep_default_na=False
        )

        records = dataframe.to_dict(
            "records"
        )

    else:
        raise ValueError(
            "지원하지 않는 파일 형식입니다. JSON, CSV, XLSX만 업로드할 수 있습니다."
        )

    normalized_records = (
        _normalize_manual_records(
            records
        )
    )

    errors = validate_manual_results(
        normalized_records
    )

    if errors:
        raise ValueError(
            "\\n".join(errors)
        )

    return normalized_records


def _aggregate_manual_results_for_comparison(manual_results):
    """
    동일 취약점이 여러 파라미터/입력 지점으로 작성된 경우
    취약점명 기준으로 묶어 자동 진단 1개 항목과 비교할 수 있게 집계합니다.

    판정 규칙:
    - 하나라도 '취약'이면 최종 '취약'
    - 모든 행이 '양호'이면 최종 '양호'
    - 그 외(양호+N/A, 전부 N/A 등)는 최종 'N/A'
    """
    grouped = {}
    order = []

    for item in manual_results:
        vulnerability = str(
            item.get("vulnerability", "")
        ).strip()

        if not vulnerability:
            continue

        key = _normalize_vulnerability_key(
            vulnerability
        )

        if key not in grouped:
            grouped[key] = []
            order.append(key)

        grouped[key].append(item)

    aggregated = {}

    for key in order:
        items = grouped[key]
        statuses = [
            str(item.get("status", "N/A")).strip()
            for item in items
        ]

        if "취약" in statuses:
            final_status = "취약"
        elif statuses and all(
            status == "양호"
            for status in statuses
        ):
            final_status = "양호"
        else:
            final_status = "N/A"

        base_item = items[0].copy()
        base_item["status"] = final_status
        base_item["_manual_items"] = items
        base_item["_manual_count"] = len(items)

        aggregated[key] = base_item

    return aggregated, order


def build_manual_comparison(
    auto_results,
    manual_results
):
    """
    수동 진단과 자동 진단을 취약점명 기준으로 비교합니다.

    동일 취약점이 여러 파라미터로 여러 행 작성되어도 허용하며,
    수동 결과를 취약점 단위로 집계한 뒤 자동 진단과 비교합니다.

    - 동일 판정: 일치
    - 서로 다른 판정: 불일치 + 이유 표시
    - 한쪽에만 존재: 비교 데이터 없음 + 이유 표시
    """
    if not manual_results:
        return pd.DataFrame(
            columns=[
                "취약점",
                "수동 진단",
                "자동 진단",
                "비교 결과",
                "비교 사유"
            ]
        )

    auto_map = {}
    auto_order = []

    for item in auto_results:
        vulnerability = str(
            item.get(
                "vulnerability",
                ""
            )
        ).strip()

        if not vulnerability:
            continue

        key = _normalize_vulnerability_key(
            vulnerability
        )

        auto_map[key] = item

        if key not in auto_order:
            auto_order.append(key)

    manual_map, manual_order = (
        _aggregate_manual_results_for_comparison(
            manual_results
        )
    )

    ordered_keys = []

    for key in auto_order + manual_order:
        if key not in ordered_keys:
            ordered_keys.append(key)

    comparison_rows = []

    for key in ordered_keys:
        auto_item = auto_map.get(key)
        manual_item = manual_map.get(key)

        if auto_item:
            vulnerability_name = auto_item.get(
                "vulnerability",
                "-"
            )
        else:
            vulnerability_name = manual_item.get(
                "vulnerability",
                "-"
            )

        manual_status = (
            manual_item.get(
                "status",
                "N/A"
            )
            if manual_item
            else "N/A"
        )

        auto_status = (
            auto_item.get(
                "status",
                "N/A"
            )
            if auto_item
            else "N/A"
        )

        manual_count = (
            manual_item.get("_manual_count", 1)
            if manual_item
            else 0
        )

        if manual_item and auto_item:
            count_note = (
                f" (수동 점검 {manual_count}개 입력 지점 집계)"
                if manual_count > 1
                else ""
            )

            if manual_status == auto_status:
                comparison_result = "일치"
                comparison_reason = (
                    f"수동 진단과 자동 진단이 모두 "
                    f"'{auto_status}'으로 동일하게 판정되었습니다."
                    f"{count_note}"
                )
            else:
                comparison_result = "불일치"
                comparison_reason = (
                    f"수동 진단은 '{manual_status}', "
                    f"자동 진단은 '{auto_status}'으로 판정되어 "
                    f"결과가 서로 다릅니다.{count_note}"
                )

        elif manual_item and not auto_item:
            comparison_result = "비교 데이터 없음"
            comparison_reason = (
                "수동 진단에는 존재하지만 자동 진단 결과에는 "
                "해당 취약점이 없어 직접 비교할 수 없습니다."
            )

        else:
            comparison_result = "비교 데이터 없음"
            comparison_reason = (
                "자동 진단에는 존재하지만 업로드한 수동 진단 결과에는 "
                "해당 취약점이 없어 직접 비교할 수 없습니다."
            )

        comparison_rows.append(
            {
                "취약점": vulnerability_name,
                "수동 진단": manual_status,
                "자동 진단": auto_status,
                "비교 결과": comparison_result,
                "비교 사유": comparison_reason
            }
        )

    return pd.DataFrame(
        comparison_rows
    )


# 데이터 검증 실행
validation_errors = validate_results(results)

if validation_errors:

    st.error(
        "진단 결과 데이터 형식에 문제가 있습니다."
    )

    for error in validation_errors:
        st.write(f"- {error}")

    st.stop()


manual_validation_errors = validate_manual_results(
    manual_results
)

if manual_validation_errors:

    st.warning(
        "수동 진단 결과 데이터 형식에 문제가 있습니다."
    )

    for error in manual_validation_errors:
        st.write(f"- {error}")



# 기본 정보
target_filenames = result_data.get(
    "filenames",
    []
)


def extract_extensions(filenames):
    extensions = []

    for filename in filenames:
        extension = os.path.splitext(filename)[1]

        if extension:
            extension = extension.lstrip(".").upper()
        else:
            extension = "알 수 없음"

        if extension not in extensions:
            extensions.append(extension)

    return extensions


target_extensions = extract_extensions(
    target_filenames
)

if target_extensions:
    target_filename = ", ".join(target_extensions)
else:
    target_filename = "알 수 없음"

if st.session_state.get(
    "realtime_scan_results"
):
    target_filename = (
        st.session_state.get(
            "realtime_target_url",
            "실시간 진단 대상"
        )
    )

has_vulnerability = (
    any(
        item.get("status") == "취약"
        for item in results
    )
    if results
    else None
)

saved_at_list = result_data.get(
    "saved_at",
    []
)

if isinstance(saved_at_list, list) and saved_at_list:
    saved_at = max(saved_at_list)
elif isinstance(saved_at_list, str) and saved_at_list:
    saved_at = saved_at_list
else:
    saved_at = "알 수 없음"


def format_datetime(value):
    if not value or value == "알 수 없음":
        return "알 수 없음"

    if not isinstance(value, str):
        return str(value)

    try:
        dt = datetime.fromisoformat(value)
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value


formatted_saved_at = format_datetime(saved_at)


# 파일 업로드 결과 집계
RISK_ORDER = {
    "낮음": 1,
    "중간": 2,
    "높음": 3
}


def aggregate_results(raw_results):
    grouped = {}
    aggregated = []
    
    for item in raw_results:

        if (
            item.get("source_type") == "파일 업로드 진단"
            and item.get("vulnerability")
            == "콘텐츠 패턴 진단: XSS (Cross-Site Scripting)"
        ):
            continue

        if item.get("source_type") == "파일 업로드 진단":
            grouped.setdefault(
                item["vulnerability"],
                []
            ).append(item)

        else:
            aggregated.append(
                item.copy()
            )

    for vulnerability, items in grouped.items():
        vulnerable_items = [
            item for item in items
            if item.get("status") == "취약"
        ]

        safe_items = [
            item for item in items
            if item.get("status") == "양호"
        ]

        na_items = [
            item for item in items
            if item.get("status") == "N/A"
        ]

        if vulnerable_items:
            final_status = "취약"
            risk_source = vulnerable_items
        elif len(safe_items) == len(items):
            final_status = "양호"
            risk_source = safe_items
        else:
            final_status = "N/A"
            risk_source = items

        final_risk = max(
            (
                item.get("risk", "낮음")
                for item in risk_source
            ),
            key=lambda value: RISK_ORDER.get(value, 0),
            default="낮음"
        )

        tested_files = list(dict.fromkeys(
            item.get("source_file", "알 수 없음")
            for item in items
        ))

        vulnerable_files = list(dict.fromkeys(
            item.get("source_file", "알 수 없음")
            for item in vulnerable_items
        ))

        # 파일 업로드 진단은 취약점명 기준으로 집계하되,
        # 각 스캐너가 반환한 원본 탐지 내용(evidence)과 판단 근거(reason)를
        # 버리지 않고 최종 상세 결과에 함께 보존합니다.
        summary_evidence = (
            f"총 {len(items)}개 파일 점검 / "
            f"취약 {len(vulnerable_items)}건 / "
            f"양호 {len(safe_items)}건 / "
            f"N/A {len(na_items)}건"
        )

        if final_status == "취약":
            detail_source_items = vulnerable_items
            summary_reason = (
                f"총 {len(items)}개 파일 중 "
                f"{len(vulnerable_items)}개 파일에서 "
                "해당 취약점이 탐지되어 취약으로 판정함"
            )

            recommendations = list(dict.fromkeys(
                item.get("recommendation", "")
                for item in vulnerable_items
                if item.get("recommendation")
            ))

            recommendation = " / ".join(recommendations)

        elif final_status == "양호":
            detail_source_items = safe_items or items
            summary_reason = (
                f"점검한 {len(items)}개 파일에서 "
                "해당 취약점이 탐지되지 않아 양호로 판정함"
            )

            recommendation = next(
                (
                    item.get("recommendation")
                    for item in items
                    if item.get("recommendation")
                ),
                "현재 상태 유지"
            )

        else:
            detail_source_items = items
            summary_reason = (
                "점검 결과만으로 양호 또는 취약을 "
                "일관되게 판정하기 어려워 N/A로 분류함"
            )

            recommendation = (
                "N/A 사유를 확인한 후 추가 점검 필요"
            )

        def _collect_detail_text(source_items, field_name):
            details = []

            for source_item in source_items:
                value = str(
                    source_item.get(field_name, "") or ""
                ).strip()

                if not value:
                    continue

                source_name = str(
                    source_item.get("source_file", "") or ""
                ).strip()

                # 여러 파일의 결과가 합쳐질 때 어떤 파일의 근거인지 식별 가능하게 표시
                if len(items) > 1 and source_name:
                    detail = f"[{source_name}] {value}"
                else:
                    detail = value

                if detail not in details:
                    details.append(detail)

            return details

        evidence_details = _collect_detail_text(
            detail_source_items,
            "evidence"
        )
        reason_details = _collect_detail_text(
            detail_source_items,
            "reason"
        )

        evidence = summary_evidence
        if evidence_details:
            evidence += "\n" + "\n".join(evidence_details)

        reason = summary_reason
        if reason_details:
            reason += "\n" + "\n".join(reason_details)

        payloads = list(dict.fromkeys(
            item.get("payload", "")
            for item in vulnerable_items
            if item.get("payload")
        ))

        tested_times = [
            item.get("tested_at")
            for item in items
            if item.get("tested_at")
        ]

        aggregated.append({
            "vulnerability": vulnerability,
            "status": final_status,
            "risk": final_risk,
            "evidence": evidence,
            "reason": reason,
            "recommendation": recommendation,
            "parameter": f"파일 {len(items)}개",
            "payload": "; ".join(payloads),
            "confidence": "확정",
            "tested_at": max(tested_times) if tested_times else "",
            "source_type": "파일 업로드 진단",
            "source_file": "다중 파일",
            "tested_count": len(items),
            "vulnerable_count": len(vulnerable_items),
            "tested_files": tested_files,
            "vulnerable_files": vulnerable_files
        })

    return aggregated


aggregated_results = aggregate_results(results)


# 통계 계산
total = len(aggregated_results)

vulnerable = sum(
    1
    for item in aggregated_results
    if item["status"] == "취약"
)

safe = sum(
    1
    for item in aggregated_results
    if item["status"] == "양호"
)

na = sum(
    1
    for item in aggregated_results
    if item["status"] == "N/A"
)


# 요약 DataFrame
# 최초 실행 시에는 아직 실시간 진단 결과가 없을 수 있으므로,
# 대시보드가 정상 렌더링되도록 공통 스키마의 빈 DataFrame을 사용합니다.
RESULT_COLUMNS = [
    "vulnerability",
    "status",
    "risk",
    "evidence",
    "reason",
    "recommendation",
    "parameter",
    "payload",
    "confidence",
    "tested_at",
    "source_type",
    "source_file"
]

df = pd.DataFrame(
    aggregated_results,
    columns=RESULT_COLUMNS
)

display_df = df[
    [
        "vulnerability",
        "status",
        "risk",
        "evidence"
    ]
].rename(
    columns={
        "vulnerability": "취약점",
        "status": "판정",
        "risk": "위험도",
        "evidence": "탐지 내용"
    }
)

summary_df = df[
    [
        "vulnerability",
        "status",
        "risk"
    ]
].rename(
    columns={
        "vulnerability": "취약점",
        "status": "판정",
        "risk": "위험도"
    }
)


# 대시보드 공통 판정/위험도 색상
STATUS_COLORS = {
    "취약": "#FF7B7B",
    "양호": "#7DD3FC",
    "N/A": "#CBD5E1"
}

RISK_COLORS = {
    "높음": "#FF7B7B",
    "중간": "#FBBF24",
    "낮음": "#7DD3FC"
}


def _status_cell_style(value):
    color = STATUS_COLORS.get(str(value))
    if not color:
        return ""
    return f"color: {color}; font-weight: 700;"


def _risk_cell_style(value):
    color = RISK_COLORS.get(str(value))
    if not color:
        return ""
    return f"color: {color}; font-weight: 700;"


def _comparison_cell_style(value):
    styles = {
        "일치": "color: #86EFAC; font-weight: 700;",
        "불일치": "color: #FF7B7B; font-weight: 700;",
        "비교 데이터 없음": "color: #CBD5E1; font-weight: 650;"
    }
    return styles.get(str(value), "")


def style_diagnosis_dataframe(dataframe):
    styled = dataframe.style

    if "판정" in dataframe.columns:
        styled = styled.map(
            _status_cell_style,
            subset=["판정"]
        )

    if "위험도" in dataframe.columns:
        styled = styled.map(
            _risk_cell_style,
            subset=["위험도"]
        )

    return styled


def style_comparison_dataframe(dataframe):
    styled = dataframe.style

    for column in [
        "수동 진단",
        "자동 진단"
    ]:
        if column in dataframe.columns:
            styled = styled.map(
                _status_cell_style,
                subset=[column]
            )

    if "비교 결과" in dataframe.columns:
        styled = styled.map(
            _comparison_cell_style,
            subset=["비교 결과"]
        )

    return styled



# 수동 진단 vs 자동 진단 비교
comparison_df = build_manual_comparison(
    aggregated_results,
    manual_results
)

comparison_data = (
    comparison_df.to_dict(
        "records"
    )
    if not comparison_df.empty
    else []
)



def build_security_ticker_items():
    items = []

    vulnerable_items = [
        item
        for item in aggregated_results
        if item.get("status") == "취약"
    ]

    for item in vulnerable_items[:6]:
        vulnerability = item.get(
            "vulnerability",
            "취약점"
        )

        risk = item.get(
            "risk",
            "-"
        )

        source_type = item.get(
            "source_type",
            ""
        )

        if source_type == "파일 업로드 진단":
            target = target_filename
        else:
            target = "WEB"

        items.append(
            f"{target} 대상에서 {vulnerability} 탐지 · 위험도 {risk}"
        )

    if not items:
        items.append(
            "현재 취약 판정 항목이 없습니다."
        )

    return items


ticker_items = build_security_ticker_items()


# 메인 화면
st.title(
    "AI 기반 공공 민원포털 취약점 자동 진단 시스템"
)

ticker_html = "".join(
    f"""
    <span class="ticker-item">
        <span class="ticker-dot"></span>
        <strong>알림</strong>
        {item}
    </span>
    """
    for item in (
        ticker_items
        + ticker_items
    )
)

components.html(
    f"""
    <style>
        html,
        body {{
            margin: 0;
            padding: 0;
            background: transparent;
            overflow: hidden;
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                "Noto Sans KR",
                Arial,
                sans-serif;
        }}

        .security-ticker {{
            position: relative;
            overflow: hidden;

            width: 100%;
            height: 48px;

            border: 1px solid rgba(148, 163, 184, 0.16);
            border-radius: 10px;

            background:
                linear-gradient(
                    90deg,
                    rgba(17, 24, 39, 0.98),
                    rgba(15, 23, 42, 0.98)
                );

            box-shadow:
                inset 0 1px 0 rgba(255, 255, 255, 0.02);
        }}

        .ticker-label {{
            position: absolute;
            z-index: 5;
            left: 0;
            top: 0;

            display: flex;
            align-items: center;
            justify-content: center;

            width: 175px;
            height: 100%;

            background:
                linear-gradient(
                    135deg,
                    rgba(220, 38, 38, 0.98),
                    rgba(185, 28, 28, 0.98)
                );

            color: #FFFFFF;
            font-size: 17px;
            font-weight: 800;
            letter-spacing: 0.5px;
            white-space: nowrap;

            box-shadow:
                10px 0 18px rgba(0, 0, 0, 0.22);
        }}

        .ticker-viewport {{
            position: absolute;
            left: 188px;
            right: 0;
            top: 0;
            height: 100%;
            overflow: hidden;
        }}

        .ticker-track {{
            display: inline-flex;
            align-items: center;

            min-width: max-content;
            height: 100%;

            padding-left: 16px;

            animation: tickerMove 54s linear infinite;
        }}

        .ticker-track:hover {{
            animation-play-state: paused;
        }}

        .ticker-item {{
            display: inline-flex;
            align-items: center;

            margin-right: 42px;

            color: #E5E7EB;
            font-size: 21px;
            font-weight: 650;
            white-space: nowrap;
        }}

        .ticker-dot {{
            display: inline-block;

            width: 7px;
            height: 7px;

            margin-right: 9px;

            border-radius: 50%;

            background: #F87171;

            box-shadow:
                0 0 8px rgba(248, 113, 113, 0.65);
        }}

        .ticker-item strong {{
            color: #FFFFFF;
            margin-right: 6px;
        }}

        @keyframes tickerMove {{
            from {{
                transform: translateX(0);
            }}

            to {{
                transform: translateX(-50%);
            }}
        }}
    </style>

    <div class="security-ticker">

        <div class="ticker-label">
            Security Warning!!
        </div>

        <div class="ticker-viewport">
            <div class="ticker-track">
                {ticker_html}
            </div>
        </div>

    </div>
    """,
    height=52,
    scrolling=False
)

st.markdown(
    '<div class="ui-accent-line"></div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <style>
    /* 제목 아래 실제 네비게이션 버튼 스타일 */
    div[data-testid="stSegmentedControl"] {
        margin-top: 0.15rem;
        margin-bottom: 1.15rem;
    }

    div[data-testid="stSegmentedControl"] > div {
        gap: 0.45rem;
        background: transparent !important;
        border: none !important;
    }

    /* 모든 메뉴 버튼 */
    div[data-testid="stSegmentedControl"] button {
        min-height: 40px !important;
        padding: 0.45rem 1.15rem !important;

        border: 1px solid rgba(148, 163, 184, 0.24) !important;
        border-radius: 10px !important;

        background: rgba(255, 255, 255, 0.025) !important;

        color: #D8E0EB !important;

        font-weight: 650 !important;

        transition:
            background 0.20s ease,
            border-color 0.20s ease,
            box-shadow 0.20s ease,
            transform 0.20s ease !important;
    }

    /* 비활성 버튼 hover */
    div[data-testid="stSegmentedControl"] button:hover {
        border-color: rgba(96, 165, 250, 0.45) !important;
        background: rgba(59, 130, 246, 0.06) !important;

        color: #FFFFFF !important;
    }

    /* 현재 선택된 버튼 */
    div[data-testid="stSegmentedControl"] button[aria-pressed="true"],
    div[data-testid="stSegmentedControl"] button[data-selected="true"] {
        border-color: rgba(96, 165, 250, 0.95) !important;

        background:
            linear-gradient(
                135deg,
                rgba(37, 99, 235, 0.24),
                rgba(30, 64, 175, 0.13)
            ) !important;

        color: #FFFFFF !important;

        font-weight: 750 !important;

        box-shadow:
            inset 0 0 0 1px rgba(147, 197, 253, 0.08),
            0 0 0 1px rgba(59, 130, 246, 0.08),
            0 0 15px rgba(59, 130, 246, 0.30),
            0 0 28px rgba(37, 99, 235, 0.14) !important;

        transform: translateY(-1px);
    }

    /* 선택 버튼 안쪽 텍스트 */
    div[data-testid="stSegmentedControl"] button[aria-pressed="true"] p,
    div[data-testid="stSegmentedControl"] button[data-selected="true"] p {
        color: #FFFFFF !important;
    }

    /* 버튼 내부 텍스트 */
    div[data-testid="stSegmentedControl"] button p {
        margin: 0 !important;
        color: inherit !important;
        font-weight: inherit !important;
    }

    /* 메뉴 바로 아래 구분선 */
    .dashboard-nav-divider {
        height: 1px;
        margin: -0.45rem 0 1.05rem 0;

        background:
            linear-gradient(
                90deg,
                rgba(59, 130, 246, 0.30),
                rgba(148, 163, 184, 0.10),
                transparent
            );
    }
    </style>
    """,
    unsafe_allow_html=True
)


selected_view = st.segmented_control(
    "대시보드 메뉴",
    [
        "실시간 자동진단 연결",
        "요약",
        "상세 대시보드",
        "수동 진단 비교",
        "AI 기반 종합 분석"
    ],
    default="실시간 자동진단 연결",
    selection_mode="single",
    label_visibility="collapsed",
    key="dashboard_view"
)

if selected_view is None:
    selected_view = "실시간 자동진단 연결"

st.markdown(
    '<div class="dashboard-nav-divider"></div>',
    unsafe_allow_html=True
)


# TAB 0 - 실시간 자동진단 연결
if selected_view == "실시간 자동진단 연결":

    st.subheader(
        "실시간 자동진단"
    )

    st.caption(
        "진단 대상 웹서비스 URL을 입력하면 자동진단 결과를 수신하여 "
        "대시보드에 반영합니다."
    )

    # 진단 대상/실행 영역 전용 스타일
    st.markdown(
        """
        <style>
        .scan-console-note {
            margin: 0.2rem 0 0.8rem 0;
            color: #94A3B8;
            font-size: 0.92rem;
            line-height: 1.55;
        }

        .scan-status-card {
            margin-top: 0.9rem;
            padding: 1rem 1.1rem;
            border: 1px solid rgba(148, 163, 184, 0.16);
            border-radius: 12px;
            background:
                linear-gradient(
                    145deg,
                    rgba(17, 24, 39, 0.82),
                    rgba(15, 23, 42, 0.62)
                );
        }

        .scan-status-head {
            display: flex;
            align-items: center;
            gap: 0.55rem;
            margin-bottom: 0.3rem;
            color: #E2E8F0;
            font-size: 0.92rem;
            font-weight: 750;
        }

        .scan-status-indicator {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #60A5FA;
            box-shadow: 0 0 9px rgba(96, 165, 250, 0.55);
        }

        .scan-status-title {
            color: #F8FAFC;
            font-size: 1.03rem;
            font-weight: 800;
        }

        .scan-status-desc {
            margin-top: 0.2rem;
            color: #94A3B8;
            font-size: 0.88rem;
        }

        .scan-complete-card {
            margin-top: 0.9rem;
            padding: 1rem 1.1rem;
            border: 1px solid rgba(34, 197, 94, 0.20);
            border-radius: 12px;
            background:
                linear-gradient(
                    145deg,
                    rgba(20, 83, 45, 0.14),
                    rgba(15, 23, 42, 0.66)
                );
        }

        .scan-complete-title {
            color: #DCFCE7;
            font-size: 1rem;
            font-weight: 800;
            margin-bottom: 0.25rem;
        }

        .scan-complete-meta {
            color: #A7F3D0;
            font-size: 0.9rem;
        }
.scan-info-card {
            position: relative;
            display: flex;
            align-items: stretch;
            margin: 0.65rem 0 0.2rem 0;
            overflow: hidden;
            border: 1px solid rgba(96, 165, 250, 0.18);
            border-radius: 14px;
            background: linear-gradient(
                135deg,
                rgba(30, 41, 59, 0.54),
                rgba(15, 23, 42, 0.34)
            );
            box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.025);
        }

        .scan-info-accent {
            width: 4px;
            flex: 0 0 4px;
            background: linear-gradient(180deg, #60A5FA, #2563EB);
            box-shadow: 0 0 14px rgba(96, 165, 250, 0.30);
        }

        .scan-info-content {
            padding: 0.78rem 1rem 0.82rem 1rem;
        }

        .scan-info-title {
            margin-bottom: 0.18rem;
            color: #EAF2FF;
            font-size: 0.92rem;
            font-weight: 800;
        }

        .scan-info-desc {
            color: #A9B7CA;
            font-size: 0.88rem;
            line-height: 1.55;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    with st.container(
        border=True
    ):

        # 2팀 API 주소는 내부 설정으로 고정하고
        # 사용자 화면에는 진단 대상 URL만 표시
        scanner_api_url = DEFAULT_SCANNER_API_URL

        realtime_target_url = st.text_input(
            "진단 대상 URL",
            value=st.session_state.get(
                "realtime_target_url",
                ""
            ),
            placeholder=(
                "http://localhost:8081"
            ),
            key="realtime_target_url_input",
            help=(
                "통합 진단 대상 웹서비스의 기본 URL을 입력합니다. "
                "예: http://localhost:8081"
            )
        )

        st.markdown(
            """
            <div class="scan-console-note">
                URL 하나로 주요 웹 취약점 진단 결과를 통합 수신합니다.
                아래 진단 항목을 선택하면 점검 내용을 확인할 수 있습니다.
            </div>
            """,
            unsafe_allow_html=True
        )

        # 주요 진단 항목 설명 UI
        # Streamlit 위젯 대신 브라우저 내부 HTML/CSS/JS로 처리하여
        # 항목을 누를 때 app.py 전체 rerun이 발생하지 않도록 합니다.
        components.html(
            """
            <style>
                html, body {
                    margin: 0;
                    padding: 0;
                    background: transparent;
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI",
                                 "Noto Sans KR", Arial, sans-serif;
                }

                .scan-tabs {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 0;
                    margin: 0;
                }

                .scan-tab {
                    min-height: 38px;
                    padding: 0.4rem 1rem;
                    border: 1px solid rgba(148, 163, 184, 0.30);
                    border-right-width: 0;
                    background: rgba(255, 255, 255, 0.02);
                    color: #E2E8F0;
                    font-size: 14px;
                    font-weight: 650;
                    cursor: pointer;
                    transition: background .16s ease, border-color .16s ease,
                                color .16s ease;
                }

                .scan-tab:first-child {
                    border-radius: 9px 0 0 9px;
                }

                .scan-tab:last-child {
                    border-right-width: 1px;
                    border-radius: 0 9px 9px 0;
                }

                .scan-tab:hover {
                    background: rgba(59, 130, 246, 0.07);
                    border-color: rgba(96, 165, 250, 0.50);
                    color: #FFFFFF;
                }

                .scan-tab.active {
                    border: 1px solid #EF4444;
                    background: rgba(127, 29, 29, 0.13);
                    color: #FF4B4B;
                }

                .scan-info-card-fast {
                    position: relative;
                    display: flex;
                    align-items: stretch;
                    margin-top: 24px;
                    overflow: hidden;
                    border: 1px solid rgba(96, 165, 250, 0.22);
                    border-radius: 14px;
                    background: linear-gradient(
                        135deg,
                        rgba(30, 41, 59, 0.54),
                        rgba(15, 23, 42, 0.34)
                    );
                    box-shadow: inset 0 1px 0 rgba(255,255,255,.025);
                }

                .scan-info-accent-fast {
                    width: 4px;
                    flex: 0 0 4px;
                    background: linear-gradient(180deg, #60A5FA, #2563EB);
                    box-shadow: 0 0 14px rgba(96,165,250,.30);
                }

                .scan-info-content-fast {
                    padding: .78rem 1rem .82rem 1rem;
                }

                .scan-info-title-fast {
                    margin-bottom: .18rem;
                    color: #EAF2FF;
                    font-size: .92rem;
                    font-weight: 800;
                }

                .scan-info-desc-fast {
                    color: #A9B7CA;
                    font-size: .88rem;
                    line-height: 1.55;
                }
            </style>

            <div class="scan-tabs">
                <button class="scan-tab active"
                        data-title="SQL Injection"
                        data-desc="입력값을 통해 비정상 SQL 구문이 실행될 수 있는지 점검합니다.">
                    SQL Injection
                </button>
                <button class="scan-tab"
                        data-title="XSS"
                        data-desc="사용자 입력이 브라우저에서 스크립트로 실행될 수 있는지 점검합니다.">
                    XSS
                </button>
                <button class="scan-tab"
                        data-title="세션 관리"
                        data-desc="세션·쿠키 설정과 인증 상태 관리가 안전하게 적용됐는지 점검합니다.">
                    세션 관리
                </button>
                <button class="scan-tab"
                        data-title="파일 업로드"
                        data-desc="위험한 파일 형식이나 우회 업로드가 허용되는지 점검합니다.">
                    파일 업로드
                </button>
            </div>

            <div class="scan-info-card-fast">
                <div class="scan-info-accent-fast"></div>
                <div class="scan-info-content-fast">
                    <div id="scanInfoTitle" class="scan-info-title-fast">
                        SQL Injection
                    </div>
                    <div id="scanInfoDesc" class="scan-info-desc-fast">
                        입력값을 통해 비정상 SQL 구문이 실행될 수 있는지 점검합니다.
                    </div>
                </div>
            </div>

            <script>
                const tabs = document.querySelectorAll(".scan-tab");
                const title = document.getElementById("scanInfoTitle");
                const desc = document.getElementById("scanInfoDesc");

                tabs.forEach((tab) => {
                    tab.addEventListener("click", () => {
                        tabs.forEach((item) => item.classList.remove("active"));
                        tab.classList.add("active");
                        title.textContent = tab.dataset.title;
                        desc.textContent = tab.dataset.desc;
                    });
                });
            </script>
            """,
            height=145,
            scrolling=False
        )

        st.markdown(
            "<div style='height:0.45rem'></div>",
            unsafe_allow_html=True
        )

        run_realtime_scan = st.button(
            "실시간 자동 진단 시작",
            key="run_realtime_scan",
            use_container_width=True,
            type="primary"
        )

        if run_realtime_scan:

            if not realtime_target_url.strip():

                st.warning(
                    "진단 대상 URL을 입력해주세요."
                )

            else:

                with st.spinner(
                    "통합 자동진단을 시작하고 결과를 수신하고 있습니다..."
                ):

                    try:

                        # --------------------------------------------------
                        # 실제 업로드 파일 진단
                        # --------------------------------------------------
                        # 기존 동작은 유지하면서, 통합 자동진단이 실행되는 동안
                        # 새 민원 첨부파일이 올라오면 약 3초 간격으로 확인해
                        # 새로 발견된 파일만 추가 분석합니다.
                        #
                        # 보고서 생성 / 기존 4종 스캐너 / create.php 진단 로직은
                        # 전혀 변경하지 않습니다.
                        actual_file_reports = []
                        actual_file_analysis_error = None
                        monitored_attachment_keys = set()

                        def _attachment_key(attachment):
                            return (
                                str(attachment.get("inquiry_id", "")),
                                str(attachment.get("filename", "")),
                                str(attachment.get("file_url", ""))
                            )

                        def _analyze_new_attachments(attachments):
                            if not attachments:
                                return None

                            new_attachments = [
                                attachment
                                for attachment in attachments
                                if _attachment_key(attachment)
                                not in monitored_attachment_keys
                            ]

                            if not new_attachments:
                                return None

                            try:
                                new_reports = (
                                    analyze_actual_uploaded_files(
                                        scanner_api_url.strip(),
                                        realtime_target_url.strip(),
                                        new_attachments
                                    )
                                )

                                actual_file_reports.extend(
                                    new_reports
                                )

                                for attachment in new_attachments:
                                    monitored_attachment_keys.add(
                                        _attachment_key(attachment)
                                    )

                                return None

                            except Exception as file_analysis_error:
                                # 실제 첨부파일 분석 실패가 기존 4종 통합 진단을
                                # 중단시키지 않도록 오류 문자열만 반환합니다.
                                return str(file_analysis_error)

                        # 진단 시작 시점에 이미 존재하는 가장 최근 첨부파일도
                        # 기존 방식대로 먼저 분석합니다.
                        try:
                            initial_attachments = (
                                discover_latest_inquiry_attachments(
                                    realtime_target_url.strip()
                                )
                            )

                            initial_error = _analyze_new_attachments(
                                initial_attachments
                            )

                            if initial_error:
                                actual_file_analysis_error = initial_error

                        except Exception as file_analysis_error:
                            actual_file_analysis_error = str(
                                file_analysis_error
                            )

                        # 통합 자동진단은 별도 작업으로 실행하고,
                        # 그 동안 메인 흐름에서 새 첨부파일을 주기적으로 확인합니다.
                        import time
                        from concurrent.futures import ThreadPoolExecutor

                        with ThreadPoolExecutor(
                            max_workers=1
                        ) as executor:

                            scan_future = executor.submit(
                                fetch_realtime_scan_results,
                                scanner_api_url.strip(),
                                realtime_target_url.strip()
                            )

                            while not scan_future.done():

                                time.sleep(3.0)

                                try:
                                    current_attachments = (
                                        discover_latest_inquiry_attachments(
                                            realtime_target_url.strip()
                                        )
                                    )

                                    monitor_error = _analyze_new_attachments(
                                        current_attachments
                                    )

                                    if monitor_error:
                                        actual_file_analysis_error = monitor_error

                                except Exception as monitor_exception:
                                    # 중간 모니터링 실패는 통합 진단 자체를
                                    # 실패 처리하지 않습니다.
                                    actual_file_analysis_error = str(
                                        monitor_exception
                                    )

                            # 통합 자동진단 결과 수신
                            realtime_results = scan_future.result()

                        # 진단이 끝나는 순간과 업로드 시점이 겹치는 경우를 위해
                        # 마지막으로 한 번 더 확인합니다.
                        try:
                            final_attachments = (
                                discover_latest_inquiry_attachments(
                                    realtime_target_url.strip()
                                )
                            )

                            final_error = _analyze_new_attachments(
                                final_attachments
                            )

                            if final_error:
                                actual_file_analysis_error = final_error

                        except Exception as final_monitor_exception:
                            actual_file_analysis_error = str(
                                final_monitor_exception
                            )

                        realtime_errors = (
                            validate_results(
                                realtime_results
                            )
                        )

                        if realtime_errors:

                            st.error(
                                "수신한 JSON Response 형식이 "
                                "현재 대시보드 규격과 일치하지 않습니다."
                            )

                            for error in realtime_errors:
                                st.write(
                                    f"- {error}"
                                )

                        else:

                            st.session_state[
                                "realtime_scan_results"
                            ] = realtime_results

                            st.session_state[
                                "realtime_target_url"
                            ] = realtime_target_url.strip()

                            st.session_state[
                                "realtime_scanned_at"
                            ] = datetime.now().isoformat()

                            st.session_state[
                                "realtime_uploaded_file_results"
                            ] = actual_file_reports

                            st.session_state[
                                "realtime_uploaded_file_error"
                            ] = actual_file_analysis_error

                            # 이전 진단 데이터 기반 분석/보고서는 제거
                            for state_key in [
                                "ai_analysis",
                                "security_question",
                                "security_answer",
                                "hf_result",
                                "generated_pdf",
                                "generated_xlsx"
                            ]:
                                st.session_state.pop(
                                    state_key,
                                    None
                                )

                            st.rerun()

                    except (
                        requests.exceptions.ConnectionError
                    ):

                        st.error(
                            "자동진단 API에 연결할 수 없습니다. "
                            "서버 실행 상태와 연결 주소를 확인해주세요."
                        )

                    except (
                        requests.exceptions.Timeout
                    ):

                        st.error(
                            "자동진단 요청 시간이 초과되었습니다."
                        )

                    except (
                        requests.exceptions.HTTPError
                    ) as e:

                        st.error(
                            "자동진단 API가 오류를 "
                            f"반환했습니다: {e}"
                        )

                    except ValueError as e:

                        st.error(
                            "JSON Response 처리 중 오류가 "
                            f"발생했습니다: {e}"
                        )

                    except Exception as e:

                        st.error(
                            "실시간 자동진단 중 오류가 "
                            f"발생했습니다: {e}"
                        )

    if st.session_state.get(
        "realtime_scan_results"
    ):

        received_count = len(
            st.session_state[
                "realtime_scan_results"
            ]
        )

        current_target = st.session_state.get(
            "realtime_target_url",
            "-"
        )

        st.markdown(
            f"""
            <div class="scan-complete-card">
                <div class="scan-complete-title">
                    ✓ 자동진단 결과 수신 완료
                </div>
                <div class="scan-complete-meta">
                    대상: {escape(str(current_target))}
                    &nbsp;&nbsp;·&nbsp;&nbsp;
                    수신 결과: {received_count}건
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        action_col1, action_col2 = st.columns(
            [3, 1]
        )

        with action_col1:
            st.caption(
                "상단의 요약 또는 상세 대시보드에서 진단 결과를 확인할 수 있습니다."
            )

        with action_col2:
            if st.button(
                "기존 결과로 전환",
                key="reset_realtime_scan",
                use_container_width=True
            ):
                for state_key in [
                    "realtime_scan_results",
                    "realtime_target_url",
                    "realtime_scanned_at",
                    "realtime_uploaded_file_results",
                    "realtime_uploaded_file_error",
                    "ai_analysis",
                    "security_question",
                    "security_answer",
                    "hf_result",
                    "generated_pdf",
                    "generated_xlsx"
                ]:
                    st.session_state.pop(
                        state_key,
                        None
                    )

                st.rerun()

    else:

        st.markdown(
            """
            <div class="scan-status-card">
                <div class="scan-status-head">
                    <span class="scan-status-indicator"></span>
                    시스템 상태
                </div>
                <div class="scan-status-title">
                    진단 대기
                </div>
                <div class="scan-status-desc">
                    진단 대상 URL을 입력한 뒤 자동진단을 시작하세요.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )


# TAB 1 - 요약
if selected_view == "요약":

    st.subheader("진단 개요")

    st.markdown(
        f"""
        **진단 대상:** {target_filename}  
        **진단 결과 저장 시각:** {formatted_saved_at}  
        **진단 방식:** Python 기반 자동 진단 및 AI 기반 결과 분석
        """
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "전체 진단",
        total
    )

    col2.metric(
        "취약",
        vulnerable
    )

    col3.metric(
        "양호",
        safe
    )

    col4.metric(
        "N/A",
        na
    )

    if has_vulnerability is True:

        st.error(
            "진단 결과 취약 항목이 확인되었습니다."
        )

    elif has_vulnerability is False:

        st.success(
            "진단 결과 취약 항목이 확인되지 않았습니다."
        )

    st.subheader(
        "진단 결과 요약"
    )

    # 진단 결과 요약 - 진단 유형별 그룹 표시
    summary_groups = []

    for source_type in df["source_type"].drop_duplicates():
        group_df = df[
            df["source_type"] == source_type
        ]

        summary_groups.append(
            (
                source_type,
                group_df
            )
        )

    summary_table_rows = []

    for source_type, group_df in summary_groups:
        group_count = len(group_df)

        for row_index, (_, row) in enumerate(
            group_df.iterrows()
        ):
            source_cell = ""

            if row_index == 0:
                source_cell = (
                    f'<td class="summary-group-cell" '
                    f'rowspan="{group_count}">'
                    f'<div class="summary-group-name">'
                    f'{escape(str(source_type))}'
                    f'</div>'
                    f'<div class="summary-group-count">'
                    f'{group_count}건'
                    f'</div>'
                    f'</td>'
                )

            status = str(row["status"])
            risk = str(row["risk"])

            status_class = {
                "취약": "status-vulnerable",
                "양호": "status-safe",
                "N/A": "status-na"
            }.get(
                status,
                ""
            )

            risk_class = {
                "높음": "risk-high",
                "중간": "risk-medium",
                "낮음": "risk-low"
            }.get(
                risk,
                ""
            )

            summary_table_rows.append(
                f"""
                <tr>
                    {source_cell}
                    <td class="summary-vulnerability">
                        {escape(str(row["vulnerability"]))}
                    </td>
                    <td class="{status_class}">
                        {escape(status)}
                    </td>
                    <td class="{risk_class}">
                        {escape(risk)}
                    </td>
                </tr>
                """
            )

    summary_table_html = "".join(
        summary_table_rows
    )

    summary_component_height = max(
        170,
        58 + (len(df) * 48)
    )

    components.html(
        f"""
        <style>
        html,
        body {{
            margin: 0;
            padding: 0;
            background: transparent;
            overflow: hidden;
            font-family:
                -apple-system,
                BlinkMacSystemFont,
                "Segoe UI",
                "Noto Sans KR",
                Arial,
                sans-serif;
        }}

        .summary-result-wrap {{
            width: 100%;
            overflow: hidden;
            border: 1px solid rgba(148, 163, 184, 0.16);
            border-radius: 12px;
            background: rgba(15, 18, 24, 0.34);
        }}

        .summary-result-table {{
            width: 100%;
            border-collapse: collapse;
            table-layout: fixed;
            color: #F8FAFC;
            font-size: 16px;
        }}

        .summary-result-table th {{
            padding: 10px 12px;
            text-align: left;
            color: #A9B7CA;
            font-weight: 650;
            background: rgba(255, 255, 255, 0.035);
            border-bottom: 1px solid rgba(148, 163, 184, 0.18);
            border-right: 1px solid rgba(148, 163, 184, 0.12);
        }}

        .summary-result-table th:last-child {{
            border-right: none;
        }}

        .summary-result-table td {{
            padding: 11px 13px;
            vertical-align: middle;
            border-bottom: 1px solid rgba(148, 163, 184, 0.13);
            border-right: 1px solid rgba(148, 163, 184, 0.10);
        }}

        .summary-result-table td:last-child {{
            border-right: none;
        }}

        .summary-result-table tr:last-child td {{
            border-bottom: none;
        }}

        .summary-result-table tbody tr:hover td:not(.summary-group-cell) {{
            background: rgba(59, 130, 246, 0.035);
        }}

        .summary-group-cell {{
            width: 17%;
            text-align: center;
            vertical-align: middle !important;
            background:
                linear-gradient(
                    145deg,
                    rgba(17, 24, 39, 0.94),
                    rgba(11, 18, 30, 0.97)
                );
            border-right: 1px solid rgba(100, 116, 139, 0.30) !important;
            box-shadow:
                inset -1px 0 0 rgba(255, 255, 255, 0.02);
        }}

        .summary-group-name {{
            color: #F1F5F9;
            font-size: 16px;
            font-weight: 800;
            line-height: 1.45;
        }}

        .summary-group-count {{
            display: inline-block;
            margin-top: 8px;
            padding: 3px 9px;
            border: 1px solid rgba(96, 165, 250, 0.28);
            border-radius: 999px;
            color: #BFDBFE;
            background: rgba(30, 41, 59, 0.72);
            font-size: 13px;
            font-weight: 750;
        }}

        .summary-vulnerability {{
            width: 57%;
            font-weight: 600;
        }}

        .status-vulnerable,
        .risk-high {{
            color: #FF7B7B;
            font-weight: 700;
        }}

        .status-safe,
        .risk-low {{
            color: #7DD3FC;
            font-weight: 700;
        }}

        .status-na {{
            color: #CBD5E1;
            font-weight: 700;
        }}

        .risk-medium {{
            color: #FBBF24;
            font-weight: 700;
        }}

        @media (max-width: 900px) {{
            .summary-result-table {{
                min-width: 760px;
            }}

            .summary-result-wrap {{
                overflow-x: auto;
            }}
        }}
        </style>

        <div class="summary-result-wrap">
            <table class="summary-result-table">
                <thead>
                    <tr>
                        <th style="width:17%;">진단 구분</th>
                        <th style="width:57%;">취약점</th>
                        <th style="width:13%;">판정</th>
                        <th style="width:13%;">위험도</th>
                    </tr>
                </thead>
                <tbody>
                    {summary_table_html}
                </tbody>
            </table>
        </div>
        """,
        height=summary_component_height,
        scrolling=False
    )



# TAB 2 - 상세 대시보드
if selected_view == "상세 대시보드":

    st.subheader(
        "1. 진단 결과 시각화"
    )

    # 두 그래프를 화면 좌/우 절반의 동일한 중심축에 직접 배치합니다.
    # 별도의 내부 중앙 컬럼을 제거해 제목 / 도넛 / 범례 중심을 완전히 일치시킵니다.
    col_status, col_risk = st.columns(2)

    with col_status:

        st.markdown(
            "<h4 style='text-align:center; margin-bottom:0.2rem;'>< 판정 분포 ></h4>",
            unsafe_allow_html=True
        )

        status_data = pd.DataFrame(
            {
                "판정": [
                    "취약",
                    "양호",
                    "N/A"
                ],
                "건수": [
                    vulnerable,
                    safe,
                    na
                ]
            }
        )

        status_chart = (
            alt.Chart(status_data)
            .mark_arc(
                innerRadius=66,
                outerRadius=104
            )
            .encode(
                theta=alt.Theta(
                    "건수:Q"
                ),
                color=alt.Color(
                    "판정:N",
                    scale=alt.Scale(
                        domain=[
                            "취약",
                            "양호",
                            "N/A"
                        ],
                        range=[
                            "#FF4B4B",
                            "#1F77B4",
                            "#64748B"
                        ]
                    ),
                    legend=None
                ),
                tooltip=[
                    alt.Tooltip(
                        "판정:N",
                        title="판정"
                    ),
                    alt.Tooltip(
                        "건수:Q",
                        title="건수"
                    )
                ]
            )
            .properties(
                height=224,
                padding={
                    "top": 4,
                    "left": 0,
                    "right": 0,
                    "bottom": 0
                }
            )
            .configure_view(
                stroke=None
            )
        )

        st.altair_chart(
            status_chart,
            use_container_width=True
        )

        st.markdown(
            """
            <div style="
                display:flex;
                justify-content:center;
                align-items:center;
                gap:12px;
                margin-top:-14px;
                margin-bottom:2px;
                font-size:13px;
            ">
                <span><span style="color:#FF4B4B;">●</span> 취약</span>
                <span><span style="color:#1F77B4;">●</span> 양호</span>
                <span><span style="color:#64748B;">●</span> N/A</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    with col_risk:

        st.markdown(
            "<h4 style='text-align:center; margin-bottom:0.2rem;'>< 위험도 분포 ></h4>",
            unsafe_allow_html=True
        )

        risk_counts = df[
            "risk"
        ].value_counts()

        risk_data = pd.DataFrame(
            {
                "위험도": [
                    "높음",
                    "중간",
                    "낮음"
                ],
                "건수": [
                    risk_counts.get(
                        "높음",
                        0
                    ),
                    risk_counts.get(
                        "중간",
                        0
                    ),
                    risk_counts.get(
                        "낮음",
                        0
                    )
                ]
            }
        )

        risk_chart = (
            alt.Chart(risk_data)
            .mark_arc(
                innerRadius=66,
                outerRadius=104
            )
            .encode(
                theta=alt.Theta(
                    "건수:Q"
                ),
                color=alt.Color(
                    "위험도:N",
                    scale=alt.Scale(
                        domain=[
                            "높음",
                            "중간",
                            "낮음"
                        ],
                        range=[
                            "#FF4B4B",
                            "#FFA726",
                            "#1F77B4"
                        ]
                    ),
                    legend=None
                ),
                tooltip=[
                    alt.Tooltip(
                        "위험도:N",
                        title="위험도"
                    ),
                    alt.Tooltip(
                        "건수:Q",
                        title="건수"
                    )
                ]
            )
            .properties(
                height=224,
                padding={
                    "top": 4,
                    "left": 0,
                    "right": 0,
                    "bottom": 0
                }
            )
            .configure_view(
                stroke=None
            )
        )

        st.altair_chart(
            risk_chart,
            use_container_width=True
        )

        st.markdown(
            """
            <div style="
                display:flex;
                justify-content:center;
                align-items:center;
                gap:12px;
                margin-top:-14px;
                margin-bottom:2px;
                font-size:13px;
            ">
                <span><span style="color:#FF4B4B;">●</span> 높음</span>
                <span><span style="color:#FFA726;">●</span> 중간</span>
                <span><span style="color:#1F77B4;">●</span> 낮음</span>
            </div>
            """,
            unsafe_allow_html=True
        )

    st.subheader(
        "2. 취약점 진단 결과"
    )

    st.dataframe(
        style_diagnosis_dataframe(
            display_df
        ),
        use_container_width=True,
        hide_index=True
    )

    st.subheader(
        "3. 파일 업로드 진단 상세 결과"
    )

    # ------------------------------------------------------------------
    # A. 기존 create.php 업로드 엔드포인트 진단
    #    기존 통합 스캐너 결과를 그대로 유지합니다.
    #    diag_xxx.php 같은 개별 payload 하위 목록은 화면에서 제거합니다.
    # ------------------------------------------------------------------
    file_upload_results = [
        item
        for item in results
        if (
            item.get("source_type") == "파일 업로드 진단"
            and item.get("vulnerability")
            != "콘텐츠 패턴 진단: XSS (Cross-Site Scripting)"
        )
    ]

    file_names = list(
        dict.fromkeys(
            item.get(
                "source_file",
                "알 수 없음"
            )
            for item in file_upload_results
        )
    )

    for file_name in file_names:

        file_items = [
            item
            for item in file_upload_results
            if item.get("source_file") == file_name
        ]

        file_vulnerable = sum(
            1
            for item in file_items
            if item.get("status") == "취약"
        )

        # create.php는 기존처럼 "취약 9건" 등의 요약과 표를 그대로 표시
        with st.expander(
            f"{file_name} · 취약 {file_vulnerable}건"
        ):
            endpoint_df = pd.DataFrame(
                [
                    {
                        "취약점": item.get(
                            "vulnerability",
                            "-"
                        ),
                        "판정": item.get(
                            "status",
                            "-"
                        ),
                        "위험도": item.get(
                            "risk",
                            "-"
                        ),
                        "탐지 내용": item.get(
                            "evidence",
                            "-"
                        )
                    }
                    for item in file_items
                ]
            )

            st.dataframe(
                style_diagnosis_dataframe(
                    endpoint_df
                ),
                use_container_width=True,
                hide_index=True
            )

    # ------------------------------------------------------------------
    # B. 실제 사용자가 업로드한 파일 자체 진단
    #    PDF/JPG/PNG 등 실제 파일명 기준으로 결과를 표시합니다.
    # ------------------------------------------------------------------
    actual_file_reports = st.session_state.get(
        "realtime_uploaded_file_results",
        []
    )

    actual_file_error = st.session_state.get(
        "realtime_uploaded_file_error"
    )

    if actual_file_reports:

        st.markdown(
            "#### 실제 업로드 파일 진단"
        )

        st.caption(
            "민원에 실제 첨부된 파일의 파일명·확장자·매직바이트·"
            "콘텐츠 패턴을 분석한 결과입니다."
        )

        for report in actual_file_reports:

            actual_filename = report.get(
                "filename",
                "알 수 없는 파일"
            )

            actual_items = report.get(
                "results",
                []
            )

            actual_vulnerable = sum(
                1
                for item in actual_items
                if item.get("status") == "취약"
            )

            st.markdown(
                f"##### 📎 {escape(str(actual_filename))} "
                f"· 취약 {actual_vulnerable}건"
            )

            if not actual_items:
                st.info(
                    "해당 파일의 정적 분석 결과가 없습니다."
                )
                continue

            # SQL Injection 상세 결과와 동일한 구성으로
            # 각 파일 진단 항목을 하나씩 펼쳐볼 수 있게 표시
            for item in actual_items:

                vulnerability_name = item.get(
                    "vulnerability",
                    "파일 진단 항목"
                )

                with st.expander(
                    vulnerability_name
                ):

                    status_value = str(
                        item.get(
                            "status",
                            "-"
                        )
                    )

                    risk_value = str(
                        item.get(
                            "risk",
                            "-"
                        )
                    )

                    status_color = STATUS_COLORS.get(
                        status_value,
                        "#E2E8F0"
                    )

                    risk_color = RISK_COLORS.get(
                        risk_value,
                        "#E2E8F0"
                    )

                    st.markdown(
                        f"**판정:** "
                        f"<span style='color:{status_color}; "
                        f"font-weight:700;'>"
                        f"{escape(status_value)}</span>",
                        unsafe_allow_html=True
                    )

                    st.markdown(
                        f"**위험도:** "
                        f"<span style='color:{risk_color}; "
                        f"font-weight:700;'>"
                        f"{escape(risk_value)}</span>",
                        unsafe_allow_html=True
                    )

                    if item.get("confidence"):
                        st.write(
                            f"**진단 확실성:** "
                            f"{item['confidence']}"
                        )

                    if item.get("parameter"):
                        st.write(
                            f"**진단 대상:** "
                            f"{item['parameter']}"
                        )

                    if item.get("payload"):
                        st.write(
                            f"**테스트 입력값:** "
                            f"`{item['payload']}`"
                        )

                    st.write(
                        f"**탐지 내용:** "
                        f"{item.get('evidence', '-')}"
                    )

                    st.write(
                        f"**판단 근거:** "
                        f"{item.get('reason', '-')}"
                    )

                    st.write(
                        f"**대응방안:** "
                        f"{item.get('recommendation', '-')}"
                    )

                    if item.get("tested_at"):
                        st.caption(
                            f"진단 시각: "
                            f"{item['tested_at']}"
                        )

    elif actual_file_error:

        st.warning(
            "실제 업로드 파일 자체 진단은 수행하지 못했습니다. "
            f"기존 create.php 엔드포인트 진단 결과는 정상 유지됩니다. "
            f"사유: {actual_file_error}"
        )

    elif st.session_state.get(
        "realtime_scan_results"
    ):

        st.info(
            "최근 공개 민원에서 실제 첨부파일을 찾지 못했습니다. "
            "파일을 첨부한 공개 민원을 등록한 뒤 실시간 진단을 다시 실행해주세요."
        )

    # 상세 결과 공통 렌더링 함수
    def render_web_detail_item(item):

        vulnerability_name = item.get(
            "vulnerability",
            "진단 결과"
        )

        detail_title_notes = {
            "세션 유휴 타임아웃 (idle timeout)":
                "실제 대기 시간이 필요한 검사로, 진단 시간 단축을 위해 기본 비활성화"
        }

        title_note = detail_title_notes.get(
            vulnerability_name,
            ""
        )

        expander_title = (
            f"{vulnerability_name} - {title_note}"
            if title_note
            else vulnerability_name
        )

        with st.expander(
            expander_title
        ):

            status_value = str(
                item.get(
                    "status",
                    "-"
                )
            )

            risk_value = str(
                item.get(
                    "risk",
                    "-"
                )
            )

            status_color = STATUS_COLORS.get(
                status_value,
                "#E2E8F0"
            )

            risk_color = RISK_COLORS.get(
                risk_value,
                "#E2E8F0"
            )

            st.markdown(
                f"**판정:** "
                f"<span style='color:{status_color}; "
                f"font-weight:700;'>"
                f"{escape(status_value)}</span>",
                unsafe_allow_html=True
            )

            st.markdown(
                f"**위험도:** "
                f"<span style='color:{risk_color}; "
                f"font-weight:700;'>"
                f"{escape(risk_value)}</span>",
                unsafe_allow_html=True
            )

            if item.get("confidence"):
                st.write(
                    f"**진단 확실성:** "
                    f"{item['confidence']}"
                )

            if item.get("parameter"):
                st.write(
                    f"**진단 대상:** "
                    f"{item['parameter']}"
                )

            if item.get("payload"):
                st.write(
                    f"**테스트 입력값:** "
                    f"`{item['payload']}`"
                )

            st.write(
                f"**탐지 내용:** "
                f"{item.get('evidence', '-')}"
            )

            st.write(
                f"**판단 근거:** "
                f"{item.get('reason', '-')}"
            )

            st.write(
                f"**대응방안:** "
                f"{item.get('recommendation', '-')}"
            )

            if item.get("tested_at"):
                st.caption(
                    f"진단 시각: "
                    f"{item['tested_at']}"
                )

    # SQL Injection 상세 결과
    st.subheader(
        "4. SQL Injection 진단 상세 결과"
    )

    sqli_detail_results = [
        item
        for item in results
        if item.get(
            "source_type"
        ) == "SQL Injection 진단"
    ]

    if sqli_detail_results:

        for item in sqli_detail_results:
            render_web_detail_item(
                item
            )

    else:

        st.info(
            "SQL Injection 진단 결과가 없습니다."
        )

    # 세션 관리 상세 결과
    st.subheader(
        "5. 세션 관리 진단 상세 결과"
    )

    session_detail_results = [
        item
        for item in results
        if item.get(
            "source_type"
        ) == "세션 관리 진단"
    ]

    if session_detail_results:

        for item in session_detail_results:
            render_web_detail_item(
                item
            )

    else:

        st.info(
            "세션 관리 진단 결과가 없습니다."
        )

    # XSS 및 기타 웹 취약점 상세 결과
    st.subheader(
        "6. 웹 취약점 상세 결과"
    )

    web_results = [
        item
        for item in results
        if item.get(
            "source_type"
        ) not in [
            "파일 업로드 진단",
            "SQL Injection 진단",
            "세션 관리 진단"
        ]
    ]

    if web_results:

        for item in web_results:
            render_web_detail_item(
                item
            )

    else:

        st.info(
            "기타 웹 취약점 진단 결과가 없습니다."
        )

# TAB 3 - 수동 진단 비교
if selected_view == "수동 진단 비교":

    st.subheader(
        "수동 진단 결과 업로드 및 자동 진단 비교"
    )

    st.caption(
        "직접 점검한 결과를 간단한 양식에 입력해 업로드하면 "
        "현재 자동 진단 결과와 항목별 판정 및 근거를 비교합니다."
    )

    # 수동 진단 탭 전용 UI
    st.markdown(
        """
        <style>
        .manual-guide {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 12px;
            margin: 0.35rem 0 1rem 0;
        }
        .manual-step {
            padding: 0.9rem 1rem;
            border: 1px solid rgba(96,165,250,.18);
            border-radius: 12px;
            background: linear-gradient(
                145deg,
                rgba(30,41,59,.38),
                rgba(15,23,42,.24)
            );
        }
        .manual-step-no {
            color: #60A5FA;
            font-size: .78rem;
            font-weight: 800;
            letter-spacing: .04em;
        }
        .manual-step-title {
            margin-top: .18rem;
            color: #F8FAFC;
            font-size: .96rem;
            font-weight: 800;
        }
        .manual-step-desc {
            margin-top: .3rem;
            color: #A9B7CA;
            font-size: .84rem;
            line-height: 1.55;
        }
        .manual-field-card {
            padding: .9rem 1rem;
            margin: .45rem 0 .9rem 0;
            border-left: 4px solid #60A5FA;
            border-radius: 10px;
            background: rgba(30,41,59,.28);
            color: #CBD5E1;
            line-height: 1.7;
            font-size: .9rem;
        }
        .manual-field-card b {
            color: #F8FAFC;
        }
        .manual-example {
            padding: .85rem 1rem;
            border: 1px solid rgba(148,163,184,.16);
            border-radius: 10px;
            background: rgba(2,6,23,.28);
            color: #CBD5E1;
            line-height: 1.65;
            font-size: .88rem;
        }
        @media (max-width: 900px) {
            .manual-guide {
                grid-template-columns: 1fr;
            }
        }
        </style>

        <div class="manual-guide">
            <div class="manual-step">
                <div class="manual-step-no">STEP 1</div>
                <div class="manual-step-title">양식 다운로드</div>
                <div class="manual-step-desc">
                    현재 자동진단 항목이 미리 입력된 XLSX 양식을 받습니다.
                </div>
            </div>
            <div class="manual-step">
                <div class="manual-step-no">STEP 2</div>
                <div class="manual-step-title">수동 점검 결과 입력</div>
                <div class="manual-step-desc">
                    판정과 함께 점검 URL·파라미터·입력값·근거를 필요한 만큼 기록합니다.
                </div>
            </div>
            <div class="manual-step">
                <div class="manual-step-no">STEP 3</div>
                <div class="manual-step-title">업로드 후 비교</div>
                <div class="manual-step-desc">
                    파일을 올리면 자동진단과 일치·불일치 및 양쪽 근거를 바로 확인합니다.
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # 현재 자동 진단 결과를 기준으로 사용자가 바로 작성할 수 있는 양식 생성
    template_payload = [
        {
            "vulnerability": item.get(
                "vulnerability",
                ""
            ),
            "status": "",
            "parameter": "",
            "payload": "",
            "reason": "",
            "evidence": ""
        }
        for item in aggregated_results
    ]


    from io import BytesIO

    template_xlsx_buffer = BytesIO()

    # 취약점 하나에 여러 파라미터가 나올 수 있으므로
    # 취약점별로 기본 3개의 입력 슬롯을 제공합니다.
    # 더 필요하면 사용자가 같은 취약점 행을 추가로 복사하면 됩니다.
    template_rows = []

    for item in aggregated_results:
        vulnerability_name = item.get(
            "vulnerability",
            ""
        )

        for slot_no in range(1, 4):
            template_rows.append(
                {
                    "취약점": vulnerability_name,
                    "점검 슬롯": slot_no,
                    "판정": "",
                    "url": "",
                    "파라미터": "",
                    "입력값": "",
                    "판정 근거": "",
                    "확인 내용": ""
                }
            )

    template_xlsx_df = pd.DataFrame(
        template_rows
    )

    with pd.ExcelWriter(
        template_xlsx_buffer,
        engine="openpyxl"
    ) as writer:
        template_xlsx_df.to_excel(
            writer,
            index=False,
            sheet_name="수동진단입력"
        )

        worksheet = writer.book[
            "수동진단입력"
        ]

        guide_sheet = writer.book.create_sheet(
            "작성안내"
        )
        guide_rows = [
            ["수동 진단 XLSX 작성 안내"],
            ["1", "취약점명은 기존 양식의 이름을 그대로 유지합니다."],
            ["2", "취약점별로 기본 3개의 점검 슬롯이 제공됩니다. 취약점명과 슬롯 번호를 제외한 입력 칸은 모두 빈칸으로 제공됩니다."],
            ["3", "사용한 슬롯에만 판정 / url / 파라미터 / 입력값 / 판정 근거 / 확인 내용을 작성합니다. 판정은 취약 / 양호 / N/A 중 하나를 입력합니다."],
            ["4", "예: SQL Injection (Error-based)을 /inquiry/list.php의 keyword와 /inquiry/detail.php의 id에서 점검했다면 각 슬롯에 URL과 파라미터를 따로 작성합니다."],
            ["5", "3개보다 더 많은 파라미터를 점검했다면 같은 취약점 행을 추가로 복사해 작성해도 됩니다."],
            ["6", "동일 취약점의 여러 행은 업로드 시 허용되며, 비교 화면에서는 취약점 단위로 자동 집계됩니다."],
            ["7", "여러 행 중 하나라도 취약이면 해당 취약점의 수동 최종 판정은 취약으로 집계됩니다."],
            ["8", "모든 작성 행이 양호이면 양호, 양호와 N/A가 섞이거나 전부 N/A이면 N/A로 집계됩니다."],
        ]

        for row in guide_rows:
            guide_sheet.append(row)

        guide_sheet.column_dimensions["A"].width = 8
        guide_sheet.column_dimensions["B"].width = 105
        guide_sheet["A1"].font = guide_sheet["A1"].font.copy(
            bold=True
        )

        for row in guide_sheet.iter_rows():
            for cell in row:
                cell.alignment = cell.alignment.copy(
                    vertical="top",
                    wrap_text=True
                )

        worksheet.freeze_panes = "A2"
        worksheet.auto_filter.ref = (
            worksheet.dimensions
        )

        widths = {
            "A": 46,
            "B": 11,
            "C": 12,
            "D": 30,
            "E": 24,
            "F": 38,
            "G": 58,
            "H": 48
        }

        for column, width in widths.items():
            worksheet.column_dimensions[
                column
            ].width = width

        for cell in worksheet[1]:
            cell.font = cell.font.copy(
                bold=True
            )
            cell.alignment = cell.alignment.copy(
                horizontal="center",
                vertical="center"
            )

        for row in worksheet.iter_rows(
            min_row=2
        ):
            for cell in row:
                cell.alignment = cell.alignment.copy(
                    vertical="top",
                    wrap_text=True
                )

    template_xlsx_buffer.seek(0)

    with st.expander(
        "무엇을 입력해야 하나요?",
        expanded=True
    ):
        st.markdown(
            """
            <div class="manual-field-card">
                <b>취약점</b> — 어떤 항목을 점검했는지 입력합니다.
                양식을 받으면 자동으로 채워져 있으므로 이름을 바꾸지 않는 것을 권장합니다.<br>
                <b>판정</b> — <code>취약</code>, <code>양호</code>, <code>N/A</code> 중 하나만 입력합니다.<br>
                <b>url</b> — 실제 수동 점검을 수행한 경로를 입력합니다.
                예: <code>/inquiry/list.php</code>, <code>/auth/login.php</code><br>
                <b>파라미터</b> — 실제 점검한 입력 지점입니다.
                예: <code>GET keyword</code>, <code>POST id</code>, <code>Cookie: PHPSESSID</code><br>
                <b>여러 파라미터 점검</b> — 다운로드 양식에는 취약점별로
                <b>3개의 점검 슬롯</b>이 미리 제공됩니다.
                파라미터별로 한 행씩 작성하고, 사용하지 않는 슬롯은 빈칸으로 두세요.
                3개를 초과하면 같은 취약점 행을 추가로 복사해도 됩니다.<br>
                <b>입력값</b> — 해당 파라미터에 넣어 확인한 테스트 문자열 또는 값입니다.
                민감정보는 넣지 마세요.<br>
                <b>판정 근거</b> — 왜 취약/양호로 판단했는지 한 문장으로 적습니다.<br>
                <b>확인 내용</b> — 응답코드, 화면 변화, 실행 여부 등 실제 확인한 현상을 적습니다.
            </div>

            <div class="manual-example">
                <b>입력 예시</b><br>
                취약점: SQL Injection (Error-based)<br>
                판정: 취약<br>
                url: /inquiry/list.php<br>
                파라미터: GET keyword<br>
                입력값: 테스트에 사용한 SQL 구문<br>
                판정 근거: 비정상 입력 시 DB 오류 메시지가 응답에 노출되어 취약으로 판단함<br>
                확인 내용: HTTP 500 응답 및 DB 관련 오류 문자열 확인
            </div>
            """,
            unsafe_allow_html=True
        )

        st.caption(
            "url·파라미터·입력값·판정 근거·확인 내용은 선택 항목입니다. "
            "취약점별로 기본 3개의 입력 슬롯이 제공되며 사용하지 않는 슬롯은 빈칸으로 두면 업로드 시 자동 제외됩니다. "
            "비교 시 작성된 동일 취약점의 여러 행은 자동으로 하나의 취약점 판정으로 집계됩니다."
        )

    st.download_button(
        "수동 진단 XLSX 양식 다운로드",
        data=template_xlsx_buffer.getvalue(),
        file_name="manual_diagnosis_template.xlsx",
        mime=(
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet"
        ),
        use_container_width=True
    )

    st.markdown(
        """
        <div style="
            margin:1rem 0 .55rem 0;
            padding:.8rem 1rem;
            border:1px solid rgba(148,163,184,.14);
            border-radius:10px;
            background:rgba(15,23,42,.28);
            color:#CBD5E1;
            font-size:.88rem;
            line-height:1.6;
        ">
            <b style="color:#F8FAFC;">작성 후 업로드</b><br>
            내려받은 XLSX의 기존 취약점명은 유지하고,
            사용한 점검 슬롯에만 판정·url·파라미터·입력값·근거를 작성한 뒤 업로드하세요.<br>
            취약점별 기본 3개 슬롯이 제공되며, 사용하지 않는 슬롯은 빈칸으로 두면 됩니다.
            3개를 초과하는 경우에만 해당 취약점 행을 추가로 복사하세요.
        </div>
        """,
        unsafe_allow_html=True
    )

    uploaded_manual_file = st.file_uploader(
        "수동 진단 XLSX 파일",
        type=["xlsx"],
        key="manual_result_uploader",
        help=(
            "필수: 취약점, 판정 / "
            "선택: url, 파라미터, 입력값, 판정 근거, 확인 내용"
        )
    )

    # 새 파일이 업로드된 경우 1회만 파싱 후 session_state에 저장
    if uploaded_manual_file is not None:

        upload_bytes = (
            uploaded_manual_file.getvalue()
        )

        upload_hash = hashlib.sha256(
            upload_bytes
        ).hexdigest()

        if (
            st.session_state.get(
                "manual_upload_hash"
            )
            != upload_hash
        ):

            try:
                parsed_manual_results = (
                    parse_manual_upload(
                        uploaded_manual_file
                    )
                )

                st.session_state[
                    "uploaded_manual_results"
                ] = parsed_manual_results

                st.session_state[
                    "manual_upload_name"
                ] = uploaded_manual_file.name

                st.session_state[
                    "manual_upload_hash"
                ] = upload_hash

                # 수동 결과가 바뀌면 비교 내용이 달라지므로
                # 기존 XLSX 결과보고서는 다시 생성하도록 초기화
                st.session_state.pop(
                    "generated_xlsx",
                    None
                )

                st.rerun()

            except Exception as e:
                st.error(
                    "수동 진단 결과 파일을 처리할 수 없습니다."
                )

                error_lines = str(e).splitlines()

                for error_line in error_lines:
                    if error_line.strip():
                        st.write(
                            f"- {error_line}"
                        )

    manual_results = st.session_state.get(
        "uploaded_manual_results",
        []
    )

    manual_upload_name = (
        st.session_state.get(
            "manual_upload_name",
            ""
        )
    )

    if manual_results:

        st.success(
            f"수동 진단 결과를 불러왔습니다: "
            f"{manual_upload_name} "
            f"({len(manual_results)}건)"
        )

        # 현재 업로드 결과를 기준으로 즉시 재계산
        current_comparison_df = (
            build_manual_comparison(
                aggregated_results,
                manual_results
            )
        )

        matched_count = int(
            (
                current_comparison_df[
                    "비교 결과"
                ]
                == "일치"
            ).sum()
        )

        mismatch_count = int(
            (
                current_comparison_df[
                    "비교 결과"
                ]
                == "불일치"
            ).sum()
        )

        no_data_count = int(
            (
                current_comparison_df[
                    "비교 결과"
                ]
                == "비교 데이터 없음"
            ).sum()
        )

        comparable_count = (
            matched_count
            + mismatch_count
        )

        match_rate = (
            matched_count
            / comparable_count
            * 100
            if comparable_count
            else 0
        )

        metric1, metric2, metric3, metric4 = (
            st.columns(4)
        )

        metric1.metric(
            "비교 가능",
            comparable_count
        )

        metric2.metric(
            "일치",
            matched_count
        )

        metric3.metric(
            "불일치",
            mismatch_count
        )

        metric4.metric(
            "일치율",
            f"{match_rate:.1f}%"
        )

        if no_data_count:
            st.info(
                f"비교 데이터 없음: {no_data_count}건"
            )

        # 수동-자동 비교 시각화
        st.subheader(
            "비교 시각화"
        )

        chart_col1, chart_col2 = st.columns(
            2,
            gap="large"
        )

        with chart_col1:
            st.caption(
                "수동 진단과 자동 진단의 판정 일치 여부"
            )

            agreement_chart_df = pd.DataFrame(
                {
                    "비교 결과": [
                        "일치",
                        "불일치"
                    ],
                    "건수": [
                        matched_count,
                        mismatch_count
                    ]
                }
            )

            # 기본 Altair 범례를 제거하고 차트 아래에 직접 중앙 정렬합니다.
            agreement_chart = (
                alt.Chart(
                    agreement_chart_df
                )
                .mark_arc(
                    innerRadius=58,
                    outerRadius=92
                )
                .encode(
                    theta=alt.Theta(
                        "건수:Q"
                    ),
                    color=alt.Color(
                        "비교 결과:N",
                        scale=alt.Scale(
                            domain=[
                                "일치",
                                "불일치"
                            ],
                            range=[
                                "#38BDF8",
                                "#FF6B6B"
                            ]
                        ),
                        legend=None
                    ),
                    tooltip=[
                        alt.Tooltip(
                            "비교 결과:N",
                            title="비교 결과"
                        ),
                        alt.Tooltip(
                            "건수:Q",
                            title="건수"
                        )
                    ]
                )
                .properties(
                    height=245,
                    padding={
                        "top": 4,
                        "left": 0,
                        "right": 0,
                        "bottom": 0
                    }
                )
                .configure_view(
                    stroke=None
                )
            )

            st.altair_chart(
                agreement_chart,
                use_container_width=True
            )

            st.markdown(
                """
                <div style="
                    display:flex;
                    justify-content:center;
                    align-items:center;
                    gap:16px;
                    margin-top:-8px;
                    margin-bottom:4px;
                    width:100%;
                    font-size:14px;
                ">
                    <span>
                        <span style="color:#38BDF8;">●</span>
                        일치
                    </span>
                    <span>
                        <span style="color:#FF6B6B;">●</span>
                        불일치
                    </span>
                </div>
                """,
                unsafe_allow_html=True
            )

        with chart_col2:
            st.caption(
                "수동 진단과 자동 진단의 판정 분포"
            )

            manual_status_counts = (
                current_comparison_df[
                    "수동 진단"
                ]
                .value_counts()
                .to_dict()
            )

            auto_status_counts = (
                current_comparison_df[
                    "자동 진단"
                ]
                .value_counts()
                .to_dict()
            )

            status_compare_rows = []

            for status_name in [
                "취약",
                "양호",
                "N/A"
            ]:
                status_compare_rows.extend(
                    [
                        {
                            "판정": status_name,
                            "진단 방식": "수동 진단",
                            "건수": int(
                                manual_status_counts.get(
                                    status_name,
                                    0
                                )
                            )
                        },
                        {
                            "판정": status_name,
                            "진단 방식": "자동 진단",
                            "건수": int(
                                auto_status_counts.get(
                                    status_name,
                                    0
                                )
                            )
                        }
                    ]
                )

            status_compare_df = pd.DataFrame(
                status_compare_rows
            )

            status_compare_chart = (
                alt.Chart(
                    status_compare_df
                )
                .mark_bar(
                    cornerRadiusTopLeft=4,
                    cornerRadiusTopRight=4
                )
                .encode(
                    x=alt.X(
                        "판정:N",
                        sort=[
                            "취약",
                            "양호",
                            "N/A"
                        ],
                        title=None,
                        axis=alt.Axis(
                            labelAngle=0,
                            labelPadding=8
                        )
                    ),
                    xOffset=alt.XOffset(
                        "진단 방식:N"
                    ),
                    y=alt.Y(
                        "건수:Q",
                        title=[
                            "건",
                            "수"
                        ],
                        axis=alt.Axis(
                            tickMinStep=1,
                            titleAngle=0,
                            titleAlign="center",
                            titleAnchor="middle",
                            titleLineHeight=14,
                            titlePadding=10
                        )
                    ),
                    color=alt.Color(
                        "진단 방식:N",
                        scale=alt.Scale(
                            domain=[
                                "수동 진단",
                                "자동 진단"
                            ],
                            range=[
                                "#60A5FA",
                                "#A78BFA"
                            ]
                        ),
                        legend=alt.Legend(
                            orient="bottom",
                            direction="horizontal",
                            title=None
                        )
                    ),
                    tooltip=[
                        alt.Tooltip(
                            "진단 방식:N",
                            title="진단 방식"
                        ),
                        alt.Tooltip(
                            "판정:N",
                            title="판정"
                        ),
                        alt.Tooltip(
                            "건수:Q",
                            title="건수"
                        )
                    ]
                )
                .properties(
                    height=245
                )
                .configure_view(
                    stroke=None
                )
            )

            st.altair_chart(
                status_compare_chart,
                use_container_width=True
            )

        st.subheader(
            "비교 결과"
        )

        st.dataframe(
            style_comparison_dataframe(
                current_comparison_df
            ),
            use_container_width=True,
            hide_index=True,
            height=min(
                560,
                38 + len(
                    current_comparison_df
                ) * 35
            ),
            column_config={
                "취약점": st.column_config.TextColumn(
                    "취약점",
                    width="large"
                ),
                "수동 진단": st.column_config.TextColumn(
                    "수동 진단",
                    width="small"
                ),
                "자동 진단": st.column_config.TextColumn(
                    "자동 진단",
                    width="small"
                ),
                "비교 결과": st.column_config.TextColumn(
                    "비교 결과",
                    width="small"
                ),
                "비교 사유": st.column_config.TextColumn(
                    "비교 사유",
                    width="large"
                )
            }
        )

        # 상세 비교에 사용할 수동/자동 진단 정보
        def _manual_detail_map(field):
            grouped_values = {}

            for item in manual_results:
                key = _normalize_vulnerability_key(
                    item.get(
                        "vulnerability",
                        ""
                    )
                )

                if not key:
                    continue

                value = str(
                    item.get(
                        field,
                        ""
                    )
                    or ""
                ).strip()

                if not value:
                    continue

                grouped_values.setdefault(
                    key,
                    []
                )

                if value not in grouped_values[key]:
                    grouped_values[key].append(
                        value
                    )

            return {
                key: " / ".join(values)
                if values
                else "-"
                for key, values in grouped_values.items()
            }

        def _auto_detail_map(field):
            return {
                _normalize_vulnerability_key(
                    item.get(
                        "vulnerability",
                        ""
                    )
                ): item.get(
                    field,
                    "-"
                ) or "-"
                for item in aggregated_results
            }

        manual_reason_map = _manual_detail_map(
            "reason"
        )
        manual_url_map = _manual_detail_map(
            "url"
        )
        manual_parameter_map = _manual_detail_map(
            "parameter"
        )
        manual_payload_map = _manual_detail_map(
            "payload"
        )
        manual_evidence_map = _manual_detail_map(
            "evidence"
        )

        auto_reason_map = _auto_detail_map(
            "reason"
        )
        auto_url_map = _auto_detail_map(
            "source_file"
        )
        auto_parameter_map = _auto_detail_map(
            "parameter"
        )
        auto_payload_map = _auto_detail_map(
            "payload"
        )
        auto_evidence_map = _auto_detail_map(
            "evidence"
        )

        # 불일치 항목은 표 아래에서 양쪽의 실제 점검 정보를 함께 보여줌
        mismatch_df = current_comparison_df[
            current_comparison_df[
                "비교 결과"
            ] == "불일치"
        ]

        if not mismatch_df.empty:

            st.subheader(
                "불일치 항목 확인"
            )

            st.warning(
                "수동 진단과 자동 진단의 판정이 다른 항목입니다. "
                "파라미터·입력값·확인 내용과 판정 근거를 함께 비교하세요."
            )

            for _, row in mismatch_df.iterrows():

                vulnerability_name = row[
                    "취약점"
                ]

                key = (
                    _normalize_vulnerability_key(
                        vulnerability_name
                    )
                )

                with st.expander(
                    f"{vulnerability_name} "
                    f"· 수동 {row['수동 진단']} / "
                    f"자동 {row['자동 진단']}"
                ):

                    st.write(
                        f"**불일치 사유:** "
                        f"{row['비교 사유']}"
                    )

                    manual_col, auto_col = st.columns(
                        2,
                        gap="large"
                    )

                    with manual_col:
                        st.markdown(
                            "##### 수동 진단"
                        )
                        st.write(
                            f"**URL:** "
                            f"{manual_url_map.get(key, '-')}"
                        )
                        st.write(
                            f"**파라미터:** "
                            f"{manual_parameter_map.get(key, '-')}"
                        )
                        st.write(
                            f"**입력값:** "
                            f"{manual_payload_map.get(key, '-')}"
                        )
                        st.write(
                            f"**확인 내용:** "
                            f"{manual_evidence_map.get(key, '-')}"
                        )
                        st.write(
                            f"**판정 근거:** "
                            f"{manual_reason_map.get(key, '-')}"
                        )

                    with auto_col:
                        st.markdown(
                            "##### 자동 진단"
                        )
                        st.write(
                            f"**URL/대상:** "
                            f"{auto_url_map.get(key, '-')}"
                        )
                        st.write(
                            f"**파라미터:** "
                            f"{auto_parameter_map.get(key, '-')}"
                        )
                        st.write(
                            f"**입력값:** "
                            f"{auto_payload_map.get(key, '-')}"
                        )
                        st.write(
                            f"**탐지 내용:** "
                            f"{auto_evidence_map.get(key, '-')}"
                        )
                        st.write(
                            f"**판정 근거:** "
                            f"{auto_reason_map.get(key, '-')}"
                        )

        elif comparable_count:
            st.success(
                "비교 가능한 모든 항목에서 "
                "수동 진단과 자동 진단의 판정이 일치합니다."
            )

        action_col1, action_col2 = st.columns(
            [3, 1]
        )

        with action_col1:
            st.caption(
                "업로드한 수동 진단 결과는 현재 세션에서 유지되며 "
                "XLSX 결과보고서의 수동-자동 비교 시트에도 반영됩니다."
            )

        with action_col2:
            if st.button(
                "수동 결과 초기화",
                key="clear_manual_results",
                use_container_width=True
            ):
                for state_key in [
                    "uploaded_manual_results",
                    "manual_upload_name",
                    "manual_upload_hash",
                    "generated_xlsx",
                    "manual_result_uploader"
                ]:
                    if state_key in st.session_state:
                        del st.session_state[state_key]

                st.rerun()

    else:

        st.info(
            "아직 수동 진단 결과가 없습니다. "
            "위의 XLSX 양식을 내려받아 작성한 뒤 업로드하세요."
        )

        st.caption(
            "입력 형식은 XLSX로 통일되어 있습니다. "
            "상단 양식을 내려받아 작성하면 취약점명이 자동진단 항목과 정확히 매칭됩니다."
        )

# TAB 4 - AI 기반 종합 분석
if selected_view == "AI 기반 종합 분석":

    st.subheader("AI 기반 종합 분석")

    st.caption(
        "진단 데이터를 기반으로 AI 종합 분석, "
        "SQL Injection 보조 검증 및 보안 질의를 수행합니다."
    )

    # ------------------------------------------------------------------
    # AI 참고용 실제 업로드 파일 진단 결과
    # ------------------------------------------------------------------
    # 대시보드의 공식 전체/취약/양호/N/A 집계는 aggregated_results를 그대로 사용하고,
    # 실제 민원에 첨부된 PDF/JPG/PNG 등의 정적 분석 결과는 별도 참고 데이터로 AI에 전달합니다.
    # 따라서 화면의 공식 건수와 AI가 언급하는 공식 건수는 기존 값과 일치하면서도,
    # 사용자가 실제 업로드 파일(PDF 포함)에 대해 질문하면 해당 파일 결과를 근거로 답변할 수 있습니다.
    actual_file_ai_results = []

    for report in st.session_state.get(
        "realtime_uploaded_file_results",
        []
    ):
        if not isinstance(report, dict):
            continue

        actual_filename = str(
            report.get(
                "filename",
                "알 수 없는 파일"
            )
        ).strip()

        file_url = report.get(
            "file_url"
        )

        inquiry_id = report.get(
            "inquiry_id"
        )

        for item in report.get(
            "results",
            []
        ):
            if not isinstance(item, dict):
                continue

            item_copy = item.copy()
            item_copy["source_type"] = "실제 업로드 파일 진단"
            item_copy["source_file"] = actual_filename

            if file_url:
                item_copy["file_url"] = file_url

            if inquiry_id is not None:
                item_copy["inquiry_id"] = inquiry_id

            actual_file_ai_results.append(
                item_copy
            )

    # Hugging Face SQL Injection 보조 분석용 결과 탐색
    # 단일 항목이 아니라 취약으로 판정된 SQL Injection 결과 전체를 수집합니다.
    sqli_items = [
        item
        for item in results
        if (
            item.get(
                "source_type"
            ) == "SQL Injection 진단"
            and item.get(
                "status"
            ) == "취약"
        )
    ]

    def _extract_target_label(item):
        """
        SQL Injection 결과에서 실제 진단 대상을 추출합니다.

        1) source_file / parameter 값에 파일 확장자가 있으면 확장자 표시
        2) 파일 확장자가 없고 parameter가 있으면 '파라미터: 값' 형태로 표시
        3) 둘 다 없으면 웹 애플리케이션으로 표시

        현재 전달받은 SQLi JSON은 parameter가 keyword, id 형태이므로
        진단 대상은 '파라미터: keyword', '파라미터: id'처럼 표시됩니다.
        """

        candidates = [
            item.get("source_file"),
            item.get("parameter")
        ]

        for candidate in candidates:

            if not candidate:
                continue

            candidate_text = str(
                candidate
            ).strip()

            extension = (
                os.path.splitext(
                    candidate_text
                )[1]
                .lstrip(".")
                .upper()
            )

            if extension:
                return extension

        parameter = item.get(
            "parameter"
        )

        if parameter:
            return (
                f"파라미터: {parameter}"
            )

        source_file = item.get(
            "source_file"
        )

        if (
            source_file
            and source_file != "웹 애플리케이션"
        ):
            return str(
                source_file
            )

        return "웹 애플리케이션"

    def _shorten_payload(value, limit=52):
        """
        화면 표시용 payload만 축약합니다.
        Hugging Face 분석에는 항상 원본 payload를 전달합니다.
        """

        if value is None:
            return ""

        value = str(value).replace(
            "\n",
            " "
        ).strip()

        if len(value) <= limit:
            return value

        return (
            value[:limit - 1]
            + "…"
        )

    # 실제 SQL Injection 취약 결과에서 진단 대상만 추출합니다.
    # 결과가 1개면 1개만, 여러 개면 실제 존재하는 대상만 표시합니다.
    hf_target_labels = []

    for item in sqli_items:

        target_label = (
            _extract_target_label(
                item
            )
        )

        if (
            target_label
            not in hf_target_labels
        ):
            hf_target_labels.append(
                target_label
            )

    sqli_payload_items = [
        item
        for item in sqli_items
        if str(
            item.get(
                "payload",
                ""
            )
        ).strip()
    ]

    # 분석 카드를 세로로 배치합니다.
    # AI 종합 분석 아래에 SQL Injection 보조 분석이 이어져
    # 긴 AI 결과가 생성돼도 우측에 큰 여백이 생기지 않습니다.
    ai_col = st.container()
    hf_col = st.container()

    # AI 종합 분석 카드
    with ai_col:

        with st.container(border=True):

            st.markdown("### AI 종합 분석")

            st.caption(
                "전체 진단 결과를 분석하여 보안 상태, "
                "주요 취약점 및 조치 우선순위를 정리합니다."
            )

            st.markdown(
                f"""
                **분석 대상:** 전체 진단 {total}건  
                **취약 항목:** {vulnerable}건  
                **분석 방식:** 생성형 AI 기반 종합 분석
                """
            )

            if st.button(
                "AI 분석 실행",
                key="gpt_analysis_button",
                use_container_width=True
            ):

                with st.spinner(
                    "진단 결과를 분석하고 있습니다..."
                ):

                    try:

                        analysis = analyze_results(
                            aggregated_results,
                            supplemental_results=actual_file_ai_results
                        )

                        st.session_state[
                            "ai_analysis"
                        ] = analysis

                    except Exception as e:

                        st.error(
                            f"AI 분석 중 오류가 발생했습니다: {e}"
                        )

            # 기존 분석 결과 유지
            if st.session_state.get("ai_analysis"):

                st.divider()

                st.markdown(
                    "#### 분석 결과"
                )

                st.markdown(
                    st.session_state["ai_analysis"]
                )

    # Hugging Face SQL Injection 보조 분석 카드
    with hf_col:

        with st.container(border=True):

            st.markdown(
                "### SQL Injection 보조 분석"
            )

            st.caption(
                "Hugging Face 모델을 활용해 "
                "SQL Injection 탐지 결과를 보조 검증합니다."
            )

            if sqli_items:

                # 여러 진단 대상 확장자를 한눈에 볼 수 있도록 배지 형태로 표시
                target_badges = "".join(
                    (
                        "<span style='"
                        "display:inline-block;"
                        "padding:4px 10px;"
                        "margin:2px 6px 2px 0;"
                        "border-radius:999px;"
                        "border:1px solid rgba(96,165,250,.28);"
                        "background:rgba(30,41,59,.68);"
                        "color:#DBEAFE;"
                        "font-size:13px;"
                        "font-weight:700;'>"
                        f"{escape(str(label))}"
                        "</span>"
                    )
                    for label in hf_target_labels
                )

                st.markdown(
                    f"""
                    <div style="margin-bottom:0.35rem;">
                        <div style="
                            color:#A9B7CA;
                            font-size:0.86rem;
                            margin-bottom:0.35rem;
                        ">
                            진단 대상
                        </div>
                        <div>
                            {target_badges}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                st.markdown(
                    f"**분석 상태:** SQL Injection 취약 항목 {len(sqli_items)}건 확인"
                )

                if sqli_payload_items:

                    st.markdown(
                        "**분석 입력값:**"
                    )

                    payload_options = []

                    for index, item in enumerate(
                        sqli_payload_items,
                        start=1
                    ):

                        parameter = str(
                            item.get(
                                "parameter",
                                "-"
                            )
                        )

                        original_payload = str(
                            item.get(
                                "payload",
                                ""
                            )
                        )

                        target_label = (
                            _extract_target_label(
                                item
                            )
                        )

                        payload_options.append(
                            {
                                "index": index,
                                "target": target_label,
                                "parameter": parameter,
                                "payload": original_payload
                            }
                        )

                    # 모든 입력값을 한 번에 확인할 수 있도록 요약 표로 표시합니다.
                    # raw payload를 코드블록으로 크게 노출하지 않고,
                    # 화면에는 축약 문자열만 보여줍니다.
                    payload_rows = []

                    for payload_item in payload_options:

                        payload_rows.append(
                            {
                                "번호": payload_item[
                                    "index"
                                ],
                                "진단 대상": payload_item[
                                    "target"
                                ],
                                "파라미터": payload_item[
                                    "parameter"
                                ],
                                "입력값": _shorten_payload(
                                    payload_item[
                                        "payload"
                                    ],
                                    limit=46
                                )
                            }
                        )

                    st.dataframe(
                        pd.DataFrame(
                            payload_rows
                        ),
                        use_container_width=True,
                        hide_index=True
                    )

                    # HF 분석은 여러 탐지값을 한 번에 전달할 수 있도록
                    # 원본 payload 전체를 줄바꿈으로 결합합니다.
                    payload = "\n".join(
                        item[
                            "payload"
                        ]
                        for item in payload_options
                    )

                    parameter_extension = ", ".join(
                        dict.fromkeys(
                            item[
                                "target"
                            ]
                            for item in payload_options
                        )
                    )

                    with st.expander(
                        "원본 입력값 전체 보기"
                    ):

                        for payload_item in payload_options:

                            st.markdown(
                                f"**{payload_item['index']}. "
                                f"[{escape(payload_item['target'])}] "
                                f"{escape(payload_item['parameter'])}**"
                            )

                            # 코드처럼 보이지 않도록 일반 텍스트 영역으로 표시
                            st.text(
                                payload_item[
                                    "payload"
                                ]
                            )

                    if st.button(
                        "SQLi AI 분석",
                        key="hf_sqli_button",
                        use_container_width=True
                    ):

                        with st.spinner(
                            "Hugging Face 모델로 "
                            "분석 중입니다..."
                        ):

                            try:

                                hf_result = analyze_sqli(
                                    payload
                                )

                                st.session_state[
                                    "hf_result"
                                ] = {
                                    "parameter": (
                                        parameter_extension
                                    ),
                                    "payload": payload,
                                    "status": hf_result[
                                        "status"
                                    ],
                                    "label": hf_result[
                                        "label"
                                    ],
                                    "score": hf_result[
                                        "score"
                                    ],
                                    "input_count": len(
                                        payload_options
                                    )
                                }

                            except Exception as e:

                                st.error(
                                    "Hugging Face 분석 중 "
                                    f"오류가 발생했습니다: {e}"
                                )

                    saved_hf_result = (
                        st.session_state.get(
                            "hf_result"
                        )
                    )

                    if saved_hf_result:

                        st.divider()

                        hf_metric1, hf_metric2 = (
                            st.columns(2)
                        )

                        hf_metric1.metric(
                            "AI 판정",
                            saved_hf_result[
                                "status"
                            ]
                        )

                        hf_metric2.metric(
                            "모델 확신도",
                            (
                                f"{saved_hf_result['score'] * 100:.2f}%"
                            )
                        )

                        with st.expander(
                            "모델 세부정보"
                        ):

                            st.write(
                                f"**Model Label:** "
                                f"{saved_hf_result['label']}"
                            )

                            st.write(
                                f"**진단 대상:** "
                                f"{saved_hf_result['parameter']}"
                            )

                            st.write(
                                f"**분석 입력 수:** "
                                f"{saved_hf_result.get('input_count', 1)}건"
                            )

                            st.caption(
                                "원본 입력값은 상단의 '원본 입력값 전체 보기'에서 확인할 수 있습니다."
                            )

                else:

                    st.info(
                        "SQL Injection 취약 결과는 존재하지만 "
                        "분석할 payload 정보가 없습니다."
                    )

            else:

                st.info(
                    "취약으로 판정된 SQL Injection 결과가 없어 "
                    "Hugging Face 보조 분석을 수행하지 않습니다."
                )

    st.divider()

    # AI 보안 질의
    st.subheader(
        "AI 보안 질의"
    )

    with st.container(border=True):

        st.caption(
            "현재 진단 결과를 기준으로 우선 조치 항목, "
            "취약점 원인, 대응방안 등을 질문할 수 있습니다."
        )

        with st.form(
            "security_question_form",
            clear_on_submit=False
        ):

            security_question = st.text_input(
                "진단 결과에 대해 질문하세요",
                placeholder=(
                    "예: 현재 진단 결과에서 가장 우선적으로 "
                    "조치해야 할 취약점은 무엇인가요?"
                ),
                key="security_question_input"
            )

            submitted = st.form_submit_button(
                "질문하기",
                use_container_width=True
            )

        if submitted:

            if not security_question.strip():

                st.warning(
                    "질문을 입력해주세요."
                )

            else:

                with st.spinner(
                    "진단 결과를 기반으로 "
                    "답변을 생성하고 있습니다..."
                ):

                    try:

                        answer = ask_security_question(
                            aggregated_results,
                            security_question,
                            supplemental_results=actual_file_ai_results
                        )

                        st.session_state[
                            "security_question"
                        ] = security_question

                        st.session_state[
                            "security_answer"
                        ] = answer

                    except Exception as e:

                        st.error(
                            f"AI 질의응답 중 오류가 "
                            f"발생했습니다: {e}"
                        )

        # 기존 질문/답변 유지
        if st.session_state.get(
            "security_answer"
        ):

            st.divider()

            st.markdown(
                "#### AI 답변"
            )

            st.markdown(
                st.session_state[
                    "security_answer"
                ]
            )

    st.divider()


    # 결과 보고서 생성
    st.subheader(
        "진단 결과 보고서"
    )

    hf_report_result = (
        st.session_state.get(
            "hf_result"
        )
    )

    ai_report_result = (
        st.session_state.get(
            "ai_analysis"
        )
    )

    report_col1, report_col2 = st.columns(2)

    with report_col1:

        if st.button(
            "PDF 생성",
            key="generate_pdf_button",
            use_container_width=True
        ):

            with st.spinner(
                "PDF 진단 결과 보고서를 생성하고 있습니다..."
            ):

                try:

                    pdf_data = generate_pdf_report(
                        aggregated_results,
                        hf_report_result,
                        target_name=target_filename
                    )

                    st.session_state[
                        "generated_pdf"
                    ] = pdf_data

                    st.success(
                        "PDF 진단 결과 보고서 생성이 완료되었습니다."
                    )

                except Exception as e:

                    st.error(
                        f"PDF 보고서 생성 중 오류가 발생했습니다: {e}"
                    )

    with report_col2:

        if st.button(
            "XLSX 생성",
            key="generate_xlsx_button",
            use_container_width=True
        ):

            with st.spinner(
                "XLSX 진단 결과 보고서를 생성하고 있습니다..."
            ):

                try:

                    xlsx_data = generate_xlsx_report(
                        aggregated_results,
                        comparison_data=comparison_df,
                        hf_result=hf_report_result,
                        ai_analysis=ai_report_result,
                        actual_file_reports=st.session_state.get(
                            "realtime_uploaded_file_results",
                            []
                        ),
                        target_name=target_filename
                    )

                    st.session_state[
                        "generated_xlsx"
                    ] = xlsx_data

                    st.success(
                        "XLSX 진단 결과 보고서 생성이 완료되었습니다."
                    )

                except Exception as e:

                    st.error(
                        f"XLSX 진단 결과 보고서 생성 중 오류가 발생했습니다: {e}"
                    )

    download_col1, download_col2 = st.columns(2)

    with download_col1:

        if st.session_state.get(
            "generated_pdf"
        ):

            st.download_button(
                label="PDF 진단 결과 보고서 다운로드",
                data=st.session_state[
                    "generated_pdf"
                ],
                file_name="진단_결과_보고서.pdf",
                mime="application/pdf",
                use_container_width=True
            )

    with download_col2:

        if st.session_state.get(
            "generated_xlsx"
        ):

            st.download_button(
                label="XLSX 진단 결과 보고서 다운로드",
                data=st.session_state[
                    "generated_xlsx"
                ],
                file_name="진단_결과_보고서.xlsx",
                mime=(
                    "application/vnd.openxmlformats-officedocument."
                    "spreadsheetml.sheet"
                ),
                use_container_width=True
            )

