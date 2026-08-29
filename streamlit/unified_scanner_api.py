"""
unified_scanner_api.py
==================
4개의 독립적인 취약점 진단 도구(파일 업로드 / SQL Injection / 세션-인증 / XSS)를
대시보드가 단일 API로 호출할 수 있도록 감싸는 통합 REST API 서버.

기존 file-upload 부분(ver5_file_upload_vuln_scanner.py 래핑)은 그대로 유지했고,
sqli_scanner.py / session_scanner.py / xss_scanner_ai.py 세 개도 이제 별도로
import하지 않고, ver5_file_upload_vuln_scanner.py가 이미 재노출해둔
sqli_scanner / session_scanner / xss_scanner_ai를 통해 한 곳에서 가져온다
(즉 이 파일은 import 대상이 ver5_file_upload_vuln_scanner.py 하나뿐이다).
각 도구의 진단 로직 자체는 전혀 건드리지 않았다.

핵심 요구사항: "대시보드에서 진단을 누르면 4개가 동시에 실행"
  -> POST /api/v1/scan/all         : 4개 스캐너를 각각 별도 백그라운드 스레드로
                                      동시에 시작하고, 4개의 job_id를 묶은
                                      group_id를 즉시 반환한다 (논블로킹).
  -> GET  /api/v1/scan/all/{gid}   : 그 group_id 하나로 4개 진단의 진행 상태/
                                      결과를 한 번에 폴링한다.
  -> POST /api/v1/scan/all/sync    : 테스트/데모용. 4개를 동시에(스레드) 실행하고
                                      전부 끝날 때까지 기다렸다가 한 번에 반환한다.

개별 스캐너만 따로 쓰고 싶을 때를 위해, 기존 file-upload와 동일한 패턴으로
sqli / session / xss 각각에 대해서도 개별 엔드포인트(POST 시작, GET 상태조회,
POST .../sync)를 그대로 제공한다.

네 스캐너의 결과 스키마는 이미 동일하게 맞춰져 있다:
  vulnerability, status(양호/취약/N/A), risk(낮음/중간/높음),
  evidence, reason, recommendation, parameter, payload, confidence, tested_at
(단, file-upload는 위 스키마를 DiagnosisResult로, 나머지 셋은 dict로 반환한다.
 최종적으로는 모두 JSON이므로 대시보드 입장에서는 필드가 동일하게 보인다.
 다만 confidence 허용값은 완전히 같지 않다 — file-upload는 "확정"/"추정" 두 값만
 쓰고, sqli/session/xss는 "확정"/"추정"/"판단불가" 세 값을 쓴다. 각 도구 원본
 그대로 가져온 것이라 이 차이를 통일하지 않았다.)

XSS 스캐너(xss_scanner_ai.py)는 Playwright(헤드리스 브라우저)가
필요하다. 설치돼 있지 않으면 이 서버 자체는 정상 기동하되, XSS 관련 엔드포인트만
503으로 "설치 필요" 안내를 반환한다 (서버 전체가 죽지 않도록 방어적으로 처리).

실행 방법
  pip install fastapi uvicorn requests --break-system-packages
  pip install playwright --break-system-packages && playwright install chromium
  python -m uvicorn unified_scanner_api:app --host 0.0.0.0 --port 8001 --reload
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
import threading
import uuid
from datetime import datetime
from types import SimpleNamespace
from typing import Any, Dict, List, Optional

import requests
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ver6_file_upload_vuln_scanner import (
    FileUploadVulnScanner,
    FileFormatNameAnalyzer,
    AIVulnerabilityReporter,
    TOOL_VERSION,
    sqli_scanner,
    session_scanner,
    xss_scanner_ai as _xss_mod,
    _sqli_scanner_import_error,
    _session_scanner_import_error,
    _xss_scanner_ai_import_error,
)

# sqli_scanner.py / session_scanner.py는 requests만 있으면 되므로 사실상 항상 로드되지만,
# xss_scanner_ai.py는 playwright(헤드리스 브라우저)가 있어야 로드된다. 셋 다
# ver5_file_upload_vuln_scanner.py가 이미 방어적으로 임포트해뒀으므로(실패해도 None),
# 여기서는 그 결과만 그대로 이어받아 API 가용성 플래그로 쓴다.
SQLI_AVAILABLE = sqli_scanner is not None
SESSION_AVAILABLE = session_scanner is not None
XSS_AVAILABLE = _xss_mod is not None
_xss_import_error: Optional[str] = _xss_scanner_ai_import_error

if XSS_AVAILABLE:
    from playwright.sync_api import sync_playwright as _sync_playwright


app = FastAPI(title="통합 취약점 진단 API", version="2.0.0")

# 대시보드가 다른 오리진(다른 포트/도메인)에서 호출할 수 있도록 CORS 개방.
# 발표/운영 환경에서는 allow_origins를 대시보드 실제 도메인으로 좁힐 것.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================================== #
# 공통 Job 모델 (4개 스캐너 모두 동일한 형태로 상태/결과를 표현)
# =========================================================================== #

class JobRecord(BaseModel):
    job_id: str
    status: str  # "running" | "done" | "error"
    target_url: str
    started_at: str
    finished_at: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    # "endpoint_scan" | "file_content" | "sqli_scan" | "session_scan" | "xss_scan"
    analysis_type: str = "endpoint_scan"


def _new_job(target_url: str, analysis_type: str) -> JobRecord:
    return JobRecord(
        job_id=uuid.uuid4().hex,
        status="running",
        target_url=target_url,
        started_at=datetime.now().isoformat(),
        analysis_type=analysis_type,
    )


def _finish_job(store: Dict[str, JobRecord], lock: threading.Lock, job_id: str,
                 result: Optional[Dict[str, Any]] = None, error: Optional[str] = None) -> None:
    with lock:
        job = store[job_id]
        job.status = "error" if error else "done"
        job.finished_at = datetime.now().isoformat()
        job.result = result
        job.error = error


# =========================================================================== #
# 1) 파일 업로드 (ver4_file_upload_vuln_scanner.py) — 기존 기능 그대로 유지
# =========================================================================== #

class ScanRequest(BaseModel):
    target_url: str = Field(..., description="진단 대상 업로드 엔드포인트 URL (http/https)")
    confirm_authorized: bool = Field(
        ..., description="이 대상에 대한 진단 권한이 있음을 명시적으로 확인 (필수)"
    )
    upload_field: str = "file"
    headers: Optional[Dict[str, str]] = None
    cookies: Optional[Dict[str, str]] = None
    extra_fields: Optional[Dict[str, str]] = None
    uploaded_file_base_url: Optional[str] = None
    run_dos_test: bool = False
    no_verify_ssl: bool = False
    timeout: int = 10
    max_retries: int = 1
    request_delay: float = 0.3
    cleanup: bool = False

    # --- OpenAI(gpt-5.6-sol) 관련 옵션 ---
    # 규칙 기반(_classify_response)으로 성공/차단을 못 가르는 애매한 응답에서만,
    # AI가 베이스라인과 이번 응답을 비교해 최종 판정을 내리게 할지 여부.
    # 규칙이 이미 확신을 가진 판정에는 절대 개입하지 않는다.
    ai_judge_ambiguous: bool = Field(
        False, description="애매한 판정에 한해 OpenAI가 최종 success/blocked를 확정하게 함"
    )
    # 취약 항목들을 사람이 읽기 좋은 자연어(항목별 정리)로 요약해 결과에 함께 담을지 여부.
    # 판정 자체에는 관여하지 않고, 이미 나온 결과를 정리하는 역할만 한다.
    include_ai_summary: bool = Field(
        False, description="취약 항목들을 OpenAI로 자연어 요약해 ai_summary 필드에 포함"
    )
    openai_api_key: Optional[str] = Field(
        None, description="OpenAI API 키. 생략 시 서버의 OPENAI_API_KEY 환경변수(.env 포함)를 사용"
    )
    ai_model: str = Field(
        AIVulnerabilityReporter.DEFAULT_MODEL,
        description=f"AI 판정/요약에 사용할 모델 (기본: {AIVulnerabilityReporter.DEFAULT_MODEL})",
    )


class FileAnalyzeTriggerRequest(BaseModel):
    target_url: str = Field(..., description="이 파일이 업로드된 엔드포인트 URL (참고/조회용)")
    filename: str = Field(..., description="실제 업로드된 원본 파일명")
    content_base64: str = Field(..., description="업로드된 파일 내용 전체를 base64로 인코딩한 값")


_jobs: Dict[str, JobRecord] = {}
_jobs_lock = threading.Lock()


def _validate_target(target_url: str, confirm_authorized: bool) -> None:
    if not confirm_authorized:
        raise HTTPException(status_code=400, detail="confirm_authorized=true로 진단 권한을 명시적으로 확인해야 합니다.")
    if not target_url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="target_url(또는 base_url)은 http:// 또는 https:// 로 시작해야 합니다.")


def _build_scanner(req: ScanRequest) -> FileUploadVulnScanner:
    return FileUploadVulnScanner(
        target_url=req.target_url,
        upload_field=req.upload_field,
        extra_form_fields=req.extra_fields,
        headers=req.headers,
        cookies=req.cookies,
        verify_ssl=not req.no_verify_ssl,
        timeout=req.timeout,
        uploaded_file_base_url=req.uploaded_file_base_url,
        skip_dos=not req.run_dos_test,
        max_retries=req.max_retries,
        request_delay=req.request_delay,
        cleanup=req.cleanup,
        ai_judge_ambiguous=req.ai_judge_ambiguous,
        openai_api_key=req.openai_api_key,
        ai_model=req.ai_model,
    )


def _run_and_load_json(scanner: FileUploadVulnScanner, req: Optional[ScanRequest] = None) -> Dict[str, Any]:
    """scanner.run_all()을 실행하고, 기존에 검증된 save_json()의 스키마를 그대로
    재사용해 결과 dict를 만든다. req.include_ai_summary가 True면, 방금 나온
    scanner.results를 바탕으로 OpenAI 자연어 요약을 만들어 'ai_summary' 필드로 덧붙인다
    (AI 요약 생성이 실패해도 나머지 결과는 그대로 반환됨 — 구조화된 결과가 AI 문제 때문에
    통째로 안 나오는 일이 없도록)."""
    scanner.run_all()
    fd, tmp_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    try:
        scanner.save_json(tmp_path)
        with open(tmp_path, "r", encoding="utf-8") as f:
            result = json.load(f)
    finally:
        os.remove(tmp_path)

    if req is not None and req.include_ai_summary:
        try:
            reporter = AIVulnerabilityReporter(api_key=req.openai_api_key, model=req.ai_model)
            result["ai_summary"] = reporter.generate_summary(scanner.results)
        except Exception as e:
            result["ai_summary"] = f"[AI 요약 생성 실패: {e}]"

    return result


def _run_file_upload_job(job_id: str, req: ScanRequest) -> None:
    try:
        result = _run_and_load_json(_build_scanner(req), req)
        _finish_job(_jobs, _jobs_lock, job_id, result=result)
    except Exception as e:
        _finish_job(_jobs, _jobs_lock, job_id, error=str(e))


def _start_file_upload_job(req: ScanRequest) -> JobRecord:
    job = _new_job(req.target_url, "endpoint_scan")
    with _jobs_lock:
        _jobs[job.job_id] = job
    threading.Thread(target=_run_file_upload_job, args=(job.job_id, req), daemon=True).start()
    return job


@app.post("/api/v1/scan/file-upload", response_model=JobRecord)
def start_scan(req: ScanRequest) -> JobRecord:
    _validate_target(req.target_url, req.confirm_authorized)
    return _start_file_upload_job(req)


@app.post("/api/v1/analyze/file-upload/trigger", response_model=JobRecord)
def trigger_file_analysis(req: FileAnalyzeTriggerRequest) -> JobRecord:
    """웹훅 전용: 네트워크 요청 없이, 넘겨받은 파일 내용 자체를
    FileFormatNameAnalyzer로 정적 분석한다 (app.py와 동일한 결과 스키마)."""
    try:
        content = base64.b64decode(req.content_base64, validate=False)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"content_base64 디코딩 실패: {e}")

    analyzer = FileFormatNameAnalyzer()
    results = analyzer.analyze(req.filename, content, field_name=req.filename)
    has_vulnerability = any(r.status == "취약" for r in results)

    result_payload = {
        "filename": req.filename,
        "has_vulnerability": has_vulnerability,
        "results": [r.to_dict() for r in results],
        "saved_at": datetime.now().isoformat(),
    }

    now = datetime.now().isoformat()
    job = JobRecord(
        job_id=uuid.uuid4().hex, status="done", target_url=req.target_url,
        started_at=now, finished_at=now, result=result_payload, analysis_type="file_content",
    )
    with _jobs_lock:
        _jobs[job.job_id] = job
    return job


@app.get("/api/v1/scan/file-upload", response_model=List[JobRecord])
def list_file_upload_jobs(target_url: Optional[str] = None) -> List[JobRecord]:
    with _jobs_lock:
        jobs = list(_jobs.values())
    if target_url:
        jobs = [j for j in jobs if j.target_url == target_url]
    jobs.sort(key=lambda j: j.started_at, reverse=True)
    return jobs


@app.get("/api/v1/scan/file-upload/{job_id}", response_model=JobRecord)
def get_file_upload_result(job_id: str) -> JobRecord:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="해당 job_id를 찾을 수 없습니다.")
    return job


@app.post("/api/v1/scan/file-upload/sync")
def start_file_upload_sync(req: ScanRequest) -> Dict[str, Any]:
    _validate_target(req.target_url, req.confirm_authorized)
    return _run_and_load_json(_build_scanner(req), req)


# =========================================================================== #
# 2) SQL Injection (sqli_scanner.py)
# =========================================================================== #

class SqliScanRequest(BaseModel):
    base_url: str = Field(..., description="예: http://localhost:8081")
    confirm_authorized: bool = Field(..., description="진단 권한 확인 (필수)")
    search_path: str = "/inquiry/list.php"
    search_param: str = "keyword"
    login_path: str = "/auth/login.php"
    id_param: str = "id"
    pw_param: str = "pw"
    success_indicator: str = "환영합니다"
    allow_destructive: bool = False
    # sqli_scanner.py는 모든 판정을 생성형 AI(OpenAI)에게 맡긴다 — 코드가 관찰한
    # 사실(technical_evidence)만 근거로 status/risk/confidence/reason/recommendation을
    # 최종 판정하며, 키가 없으면 자동으로 N/A(판단불가)로 폴백한다(스캔 자체는 안 죽음).
    openai_api_key: Optional[str] = Field(
        None, description="OpenAI API 키. 생략 시 서버의 OPENAI_API_KEY 환경변수(.env 포함) 사용"
    )
    ai_model: str = Field("gpt-4o-mini", description="판정에 사용할 OpenAI 모델")


_sqli_jobs: Dict[str, JobRecord] = {}
_sqli_jobs_lock = threading.Lock()


def _require_sqli_available() -> None:
    if not SQLI_AVAILABLE:
        raise HTTPException(status_code=503, detail=f"sqli_scanner 모듈을 불러올 수 없습니다: {_sqli_scanner_import_error}")


def _run_sqli(req: SqliScanRequest) -> Dict[str, Any]:
    _require_sqli_available()
    client, client_error = sqli_scanner.get_openai_client(req.openai_api_key)
    results = sqli_scanner.run_all(
        client=client,
        base_url=req.base_url,
        search_path=req.search_path,
        search_param=req.search_param,
        login_path=req.login_path,
        id_param=req.id_param,
        pw_param=req.pw_param,
        success_indicator=req.success_indicator,
        allow_destructive=req.allow_destructive,
        model=req.ai_model,
    )
    payload: Dict[str, Any] = {"results": results}
    if client is None:
        # 판정 자체는 각 결과별로 이미 N/A(판단불가)로 폴백돼 있지만, "왜 전부 N/A인지"를
        # 응답 최상위에서도 바로 보이게 별도 필드로 남긴다.
        payload["ai_warning"] = client_error
    return payload


def _run_sqli_job(job_id: str, req: SqliScanRequest) -> None:
    try:
        _finish_job(_sqli_jobs, _sqli_jobs_lock, job_id, result=_run_sqli(req))
    except Exception as e:
        _finish_job(_sqli_jobs, _sqli_jobs_lock, job_id, error=str(e))


def _start_sqli_job(req: SqliScanRequest) -> JobRecord:
    job = _new_job(req.base_url, "sqli_scan")
    with _sqli_jobs_lock:
        _sqli_jobs[job.job_id] = job
    threading.Thread(target=_run_sqli_job, args=(job.job_id, req), daemon=True).start()
    return job


@app.post("/api/v1/scan/sqli", response_model=JobRecord)
def start_sqli_scan(req: SqliScanRequest) -> JobRecord:
    _require_sqli_available()
    _validate_target(req.base_url, req.confirm_authorized)
    return _start_sqli_job(req)


@app.get("/api/v1/scan/sqli", response_model=List[JobRecord])
def list_sqli_jobs(target_url: Optional[str] = None) -> List[JobRecord]:
    with _sqli_jobs_lock:
        jobs = list(_sqli_jobs.values())
    if target_url:
        jobs = [j for j in jobs if j.target_url == target_url]
    jobs.sort(key=lambda j: j.started_at, reverse=True)
    return jobs


@app.get("/api/v1/scan/sqli/{job_id}", response_model=JobRecord)
def get_sqli_result(job_id: str) -> JobRecord:
    with _sqli_jobs_lock:
        job = _sqli_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="해당 job_id를 찾을 수 없습니다.")
    return job


@app.post("/api/v1/scan/sqli/sync")
def start_sqli_sync(req: SqliScanRequest) -> Dict[str, Any]:
    _validate_target(req.base_url, req.confirm_authorized)
    return _run_sqli(req)


# =========================================================================== #
# 3) 세션/인증 (session_scanner.py)
# =========================================================================== #

class SessionScanRequest(BaseModel):
    base_url: str = Field(..., description="예: http://localhost:8081")
    confirm_authorized: bool = Field(..., description="진단 권한 확인 (필수)")
    login_path: str = "/auth/login.php"
    logout_path: str = "/auth/logout.php"
    mypage_path: str = "/inquiry/my.php"
    id_param: str = "id"
    pw_param: str = "pw"
    valid_id: str = "test999"
    valid_pw: str = "test999"
    logout_fail_indicator: str = "로그인이 필요합니다"
    cookie_name: str = "PHPSESSID"
    session_timeout_wait: int = 0  # opt-in. 0(기본)이면 idle timeout 항목은 건너뜀
    openai_api_key: Optional[str] = Field(
        None, description="OpenAI API 키. 생략 시 서버의 OPENAI_API_KEY 환경변수(.env 포함) 사용"
    )
    ai_model: str = Field("gpt-4o-mini", description="판정에 사용할 OpenAI 모델")


_session_jobs: Dict[str, JobRecord] = {}
_session_jobs_lock = threading.Lock()


def _require_session_available() -> None:
    if not SESSION_AVAILABLE:
        raise HTTPException(status_code=503,
                             detail=f"session_scanner 모듈을 불러올 수 없습니다: {_session_scanner_import_error}")


def _run_session(req: SessionScanRequest) -> Dict[str, Any]:
    _require_session_available()
    client, client_error = session_scanner.get_openai_client(req.openai_api_key)
    results = session_scanner.run_all(
        client=client,
        base_url=req.base_url,
        login_path=req.login_path,
        logout_path=req.logout_path,
        mypage_path=req.mypage_path,
        id_param=req.id_param,
        pw_param=req.pw_param,
        valid_id=req.valid_id,
        valid_pw=req.valid_pw,
        logout_fail_indicator=req.logout_fail_indicator,
        cookie_name=req.cookie_name,
        session_timeout_wait=req.session_timeout_wait,
        model=req.ai_model,
    )
    payload: Dict[str, Any] = {"results": results}
    if client is None:
        payload["ai_warning"] = client_error
    return payload


def _run_session_job(job_id: str, req: SessionScanRequest) -> None:
    try:
        _finish_job(_session_jobs, _session_jobs_lock, job_id, result=_run_session(req))
    except Exception as e:
        _finish_job(_session_jobs, _session_jobs_lock, job_id, error=str(e))


def _start_session_job(req: SessionScanRequest) -> JobRecord:
    job = _new_job(req.base_url, "session_scan")
    with _session_jobs_lock:
        _session_jobs[job.job_id] = job
    threading.Thread(target=_run_session_job, args=(job.job_id, req), daemon=True).start()
    return job


@app.post("/api/v1/scan/session", response_model=JobRecord)
def start_session_scan(req: SessionScanRequest) -> JobRecord:
    _require_session_available()
    _validate_target(req.base_url, req.confirm_authorized)
    if req.session_timeout_wait > 0:
        # 실제로 그 시간만큼 대기하는 항목이라, 잘못된 값이면 API가 오래 묶일 수 있어 상한을 둔다.
        if req.session_timeout_wait > 600:
            raise HTTPException(status_code=400, detail="session_timeout_wait는 최대 600초까지만 허용됩니다.")
    return _start_session_job(req)


@app.get("/api/v1/scan/session", response_model=List[JobRecord])
def list_session_jobs(target_url: Optional[str] = None) -> List[JobRecord]:
    with _session_jobs_lock:
        jobs = list(_session_jobs.values())
    if target_url:
        jobs = [j for j in jobs if j.target_url == target_url]
    jobs.sort(key=lambda j: j.started_at, reverse=True)
    return jobs


@app.get("/api/v1/scan/session/{job_id}", response_model=JobRecord)
def get_session_result(job_id: str) -> JobRecord:
    with _session_jobs_lock:
        job = _session_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="해당 job_id를 찾을 수 없습니다.")
    return job


@app.post("/api/v1/scan/session/sync")
def start_session_sync(req: SessionScanRequest) -> Dict[str, Any]:
    _validate_target(req.base_url, req.confirm_authorized)
    return _run_session(req)


# =========================================================================== #
# 4) XSS (xss_crawler_scanner_improved.py) — Playwright 필요
# =========================================================================== #

class XssScanRequest(BaseModel):
    base_url: str = Field(..., description="예: http://localhost:8081")
    confirm_authorized: bool = Field(..., description="진단 권한 확인 (필수)")
    max_depth: int = 2
    max_pages: int = 30
    scan_types: List[str] = Field(default_factory=lambda: ["reflected", "stored", "dom"],
                                   description="reflected/stored/dom 중 선택, 생략 시 전체 실행")
    allow_post: List[str] = Field(default_factory=lambda: ["/src/inquiry/create.php"],
                                   description="Stored XSS 테스트를 허용할 POST action 경로")
    cleanup_url: str = ""
    login_url: str = "/auth/login.php"
    login_id_field: str = "id"
    login_pw_field: str = "pw"
    register_if_needed: bool = False
    register_url: str = "/auth/register.php"
    register_name: str = "XSS Tester"
    register_name_field: str = "name"
    # None이면 xss_scanner_ai.py 모듈 기본 로그인 계정(LOGIN_ID/LOGIN_PW)을 그대로 사용.
    # 값을 주면 그 요청을 처리하는 동안만 모듈 전역값을 바꿔서 사용한다 (아래 _run_xss 주석 참고).
    login_id: Optional[str] = None
    login_pw: Optional[str] = None
    # xss_scanner_ai.py는 스캔 후 raw evidence를 생성형 AI(OpenAI)로 최종 보강하는데,
    # 이 키를 함수 인자가 아니라 환경변수(OPENAI_API_KEY/OPENAI_MODEL)로만 읽는다.
    # 여기 값을 주면 이번 스캔이 도는 동안만 그 환경변수를 임시로 바꿔서 쓴다.
    openai_api_key: Optional[str] = Field(
        None, description="OpenAI API 키. 생략 시 서버의 OPENAI_API_KEY 환경변수(.env 포함) 사용"
    )
    ai_model: Optional[str] = Field(
        None, description="AI 결과 보강에 사용할 모델. 생략 시 xss_scanner_ai.py 기본값 사용"
    )


_xss_jobs: Dict[str, JobRecord] = {}
_xss_jobs_lock = threading.Lock()

# xss_scanner_ai.py의 authenticate()는 LOGIN_ID/LOGIN_PW를, call_openai_json()은
# OPENAI_API_KEY/OPENAI_MODEL을 각각 모듈 전역 상수·환경변수로 참조한다(함수 인자로
# 안 받음). 요청마다 다른 값을 쓰려면 스캔 전체를 이 락으로 감싸 임시로 바꿔치기하고
# 끝나면 원래 값으로 복원해야 한다 — 그 사이 다른 XSS 스캔 요청은 대기하게 되지만,
# 파일업로드/SQLi/세션 스캔과는 여전히 완전히 동시에 진행된다.
_xss_login_patch_lock = threading.Lock()


def _require_xss_available() -> None:
    if not XSS_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail=(
                f"playwright가 설치되어 있지 않아 XSS 진단 기능을 사용할 수 없습니다 ({_xss_import_error}). "
                f"서버에서 'pip install playwright --break-system-packages && playwright install chromium' "
                f"실행 후 서버를 재시작하세요."
            ),
        )


def _run_xss(req: XssScanRequest) -> Dict[str, Any]:
    if not XSS_AVAILABLE:
        raise RuntimeError(
            f"playwright가 설치되어 있지 않아 XSS 진단을 실행할 수 없습니다 ({_xss_import_error}). "
            f"'pip install playwright --break-system-packages && playwright install chromium' 실행 후 재시도하세요."
        )

    args = SimpleNamespace(
        base_url=req.base_url,
        max_depth=req.max_depth,
        max_pages=req.max_pages,
        scan=req.scan_types,
        allow_post=req.allow_post,
        cleanup_url=req.cleanup_url,
        login_url=req.login_url,
        login_id_field=req.login_id_field,
        login_pw_field=req.login_pw_field,
        register_if_needed=req.register_if_needed,
        register_url=req.register_url,
        register_name=req.register_name,
        register_name_field=req.register_name_field,
        headed=False,
    )

    with _xss_login_patch_lock:
        if req.login_id is not None:
            _xss_mod.LOGIN_ID = req.login_id
        if req.login_pw is not None:
            _xss_mod.LOGIN_PW = req.login_pw

        prev_api_key = os.environ.get("OPENAI_API_KEY")
        prev_model = os.environ.get("OPENAI_MODEL")
        if req.openai_api_key is not None:
            os.environ["OPENAI_API_KEY"] = req.openai_api_key
        if req.ai_model is not None:
            os.environ["OPENAI_MODEL"] = req.ai_model

        try:
            session = requests.Session()
            auth_result = _xss_mod.authenticate(session, args)
            pages, forms = _xss_mod.crawl(session, args.base_url, args.max_depth, args.max_pages)
            reflected_targets = _xss_mod.reflected_targets_from(pages, forms)
            # xss_scanner_ai.py의 main()과 동일한 흐름: 스캔에 앞서 AI 보강용 컨텍스트를
            # 먼저 만들어두고, 스캔이 다 끝난 뒤 raw evidence를 AI로 최종 보강한다.
            ai_context = _xss_mod.build_ai_scan_context(pages, forms, reflected_targets)

            meta = {
                "base_url": args.base_url,
                "auth": auth_result,
                "crawled_pages": len(pages),
                "discovered_forms": len(forms),
                "ai": {
                    "enabled": _xss_mod.AI_ANALYSIS_ENABLED,
                    "api_key_available": bool(os.getenv("OPENAI_API_KEY")),
                    "model": os.getenv("OPENAI_MODEL", _xss_mod.AI_MODEL),
                },
            }

            with _sync_playwright() as playwright:
                try:
                    browser = playwright.chromium.launch(headless=True)
                except Exception as error:
                    return _xss_mod.browser_start_failure(error, meta)
                try:
                    scan_types = set(args.scan or ["reflected", "stored", "dom"])
                    scan_results: Dict[str, Any] = {}
                    if "reflected" in scan_types:
                        scan_results["reflected_xss"] = _xss_mod.scan_reflected_xss(browser, session, reflected_targets)
                    if "stored" in scan_types:
                        scan_results["stored_xss"] = _xss_mod.scan_stored_xss(
                            browser, session, forms, pages, args.allow_post, args.cleanup_url
                        )
                    if "dom" in scan_types:
                        scan_results["dom_xss"] = _xss_mod.scan_dom_xss(browser, session, pages)
                    final_result = {"meta": meta, "xss_scan_result": scan_results}
                    final_result["meta"]["ai"].update(_xss_mod.enhance_result_with_ai(final_result, ai_context))
                    return final_result
                finally:
                    browser.close()
        finally:
            # 다른 요청/스캐너에 영향 주지 않도록 환경변수를 원래 값으로 되돌린다.
            if req.openai_api_key is not None:
                if prev_api_key is None:
                    os.environ.pop("OPENAI_API_KEY", None)
                else:
                    os.environ["OPENAI_API_KEY"] = prev_api_key
            if req.ai_model is not None:
                if prev_model is None:
                    os.environ.pop("OPENAI_MODEL", None)
                else:
                    os.environ["OPENAI_MODEL"] = prev_model


def _run_xss_job(job_id: str, req: XssScanRequest) -> None:
    try:
        _finish_job(_xss_jobs, _xss_jobs_lock, job_id, result=_run_xss(req))
    except Exception as e:
        _finish_job(_xss_jobs, _xss_jobs_lock, job_id, error=str(e))


def _start_xss_job(req: XssScanRequest) -> JobRecord:
    job = _new_job(req.base_url, "xss_scan")
    with _xss_jobs_lock:
        _xss_jobs[job.job_id] = job
    threading.Thread(target=_run_xss_job, args=(job.job_id, req), daemon=True).start()
    return job


@app.post("/api/v1/scan/xss", response_model=JobRecord)
def start_xss_scan(req: XssScanRequest) -> JobRecord:
    _require_xss_available()
    _validate_target(req.base_url, req.confirm_authorized)
    return _start_xss_job(req)


@app.get("/api/v1/scan/xss", response_model=List[JobRecord])
def list_xss_jobs(target_url: Optional[str] = None) -> List[JobRecord]:
    with _xss_jobs_lock:
        jobs = list(_xss_jobs.values())
    if target_url:
        jobs = [j for j in jobs if j.target_url == target_url]
    jobs.sort(key=lambda j: j.started_at, reverse=True)
    return jobs


@app.get("/api/v1/scan/xss/{job_id}", response_model=JobRecord)
def get_xss_result(job_id: str) -> JobRecord:
    with _xss_jobs_lock:
        job = _xss_jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="해당 job_id를 찾을 수 없습니다.")
    return job


@app.post("/api/v1/scan/xss/sync")
def start_xss_sync(req: XssScanRequest) -> Dict[str, Any]:
    _require_xss_available()
    _validate_target(req.base_url, req.confirm_authorized)
    return _run_xss(req)


# =========================================================================== #
# 5) 통합 실행 — 대시보드의 [진단하기] 버튼 하나로 4개를 동시에
# =========================================================================== #

class UnifiedScanRequest(BaseModel):
    base_url: str = Field(..., description="공통 대상. 예: http://localhost:8081")
    confirm_authorized: bool = Field(..., description="네 가지 진단 모두에 대한 진단 권한을 명시적으로 확인 (필수)")

    # 파일 업로드만 "base_url + 경로"가 아니라 별도의 업로드 엔드포인트 URL이 필요하다.
    # 생략하면 base_url + '/src/inquiry/create.php'(xss 스캐너의 기본 allow_post 경로와 동일,
    # 데모 앱의 문의글 작성 겸 첨부파일 업로드 엔드포인트로 추정)를 기본값으로 사용한다.
    # 실제 업로드 엔드포인트가 다르면 반드시 upload_url을 지정할 것.
    upload_url: Optional[str] = Field(None, description="파일 업로드 진단 대상 엔드포인트 URL")

    # 스캐너별로 세부 옵션을 다르게 주고 싶으면 해당 스캐너의 요청 객체를 통째로 넘기면 된다.
    # 생략된 스캐너는 base_url/confirm_authorized 기반의 기본 설정으로 자동 구성된다.
    file_upload: Optional[ScanRequest] = None
    sqli: Optional[SqliScanRequest] = None
    session: Optional[SessionScanRequest] = None
    xss: Optional[XssScanRequest] = None

    run_file_upload: bool = True
    run_sqli: bool = True
    run_session: bool = True
    # XSS는 헤드리스 브라우저를 띄우는 무거운 진단이라 필요 시 끌 수 있게 별도 플래그로 둠.
    run_xss: bool = True


class ScanGroupRecord(BaseModel):
    group_id: str
    target_base_url: str
    started_at: str
    jobs: Dict[str, Optional[str]]     # {"file_upload": job_id, ...}. 비활성/미설치면 None
    enabled: Dict[str, bool]


_scan_groups: Dict[str, ScanGroupRecord] = {}
_scan_groups_lock = threading.Lock()


def _build_unified_sub_requests(req: UnifiedScanRequest):
    fu_req = req.file_upload or ScanRequest(
        target_url=req.upload_url or (req.base_url.rstrip("/") + "/src/inquiry/create.php"),
        confirm_authorized=req.confirm_authorized,
        uploaded_file_base_url=req.base_url.rstrip("/") + "/uploads",
    )
    sqli_req = req.sqli or SqliScanRequest(base_url=req.base_url, confirm_authorized=req.confirm_authorized)
    session_req = req.session or SessionScanRequest(base_url=req.base_url, confirm_authorized=req.confirm_authorized)
    xss_req = req.xss or XssScanRequest(base_url=req.base_url, confirm_authorized=req.confirm_authorized)
    return fu_req, sqli_req, session_req, xss_req


@app.post("/api/v1/scan/all")
def start_all_scans(req: UnifiedScanRequest) -> Dict[str, Any]:
    """대시보드의 [진단하기] 버튼용 엔드포인트. 파일업로드/SQLi/세션인증/XSS 4개를
    각각 독립된 백그라운드 스레드로 '동시에' 시작하고 즉시 응답한다(논블로킹).
    이후 GET /api/v1/scan/all/{group_id} 하나로 4개의 진행 상태를 함께 폴링하면 된다."""
    if not req.confirm_authorized:
        raise HTTPException(status_code=400, detail="confirm_authorized=true로 네 가지 진단 모두에 대한 권한을 확인해야 합니다.")
    if not req.base_url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="base_url은 http:// 또는 https:// 로 시작해야 합니다.")

    fu_req, sqli_req, session_req, xss_req = _build_unified_sub_requests(req)

    jobs: Dict[str, Optional[str]] = {"file_upload": None, "sqli": None, "session": None, "xss": None}
    enabled = {
        "file_upload": req.run_file_upload, "sqli": req.run_sqli,
        "session": req.run_session, "xss": req.run_xss,
    }

    if req.run_file_upload:
        _validate_target(fu_req.target_url, fu_req.confirm_authorized)
        jobs["file_upload"] = _start_file_upload_job(fu_req).job_id

    if req.run_sqli:
        jobs["sqli"] = _start_sqli_job(sqli_req).job_id

    if req.run_session:
        jobs["session"] = _start_session_job(session_req).job_id

    if req.run_xss:
        if XSS_AVAILABLE:
            jobs["xss"] = _start_xss_job(xss_req).job_id
        else:
            enabled["xss"] = False  # 설치 안 되어 있으면 조용히 건너뜀 (group 조회 시 이유가 보이도록 아래 참고)

    record = ScanGroupRecord(
        group_id=uuid.uuid4().hex,
        target_base_url=req.base_url,
        started_at=datetime.now().isoformat(),
        jobs=jobs,
        enabled=enabled,
    )
    with _scan_groups_lock:
        _scan_groups[record.group_id] = record

    result = record.dict()
    if req.run_xss and not XSS_AVAILABLE:
        result["xss_skipped_reason"] = _xss_import_error
    return result


@app.get("/api/v1/scan/all/{group_id}")
def get_all_scans_status(group_id: str) -> Dict[str, Any]:
    """group_id 하나로 4개 스캐너 job의 현재 상태/결과를 한 번에 모아서 반환한다.
    대시보드는 done/error가 아닌 동안 이 엔드포인트만 주기적으로 폴링하면 된다."""
    with _scan_groups_lock:
        group = _scan_groups.get(group_id)
    if group is None:
        raise HTTPException(status_code=404, detail="해당 group_id를 찾을 수 없습니다.")

    def _lookup(store: Dict[str, JobRecord], lock: threading.Lock, job_id: Optional[str]):
        if not job_id:
            return None
        with lock:
            job = store.get(job_id)
        return job.dict() if job else None

    jobs_status = {
        "file_upload": _lookup(_jobs, _jobs_lock, group.jobs.get("file_upload")),
        "sqli": _lookup(_sqli_jobs, _sqli_jobs_lock, group.jobs.get("sqli")),
        "session": _lookup(_session_jobs, _session_jobs_lock, group.jobs.get("session")),
        "xss": _lookup(_xss_jobs, _xss_jobs_lock, group.jobs.get("xss")),
    }

    active_statuses = [
        j["status"] for name, j in jobs_status.items() if j is not None and group.enabled.get(name)
    ]
    if not active_statuses:
        overall = "done"
    elif all(s in ("done", "error") for s in active_statuses):
        overall = "partial_error" if any(s == "error" for s in active_statuses) else "done"
    else:
        overall = "running"

    return {
        "group_id": group_id,
        "target_base_url": group.target_base_url,
        "started_at": group.started_at,
        "enabled": group.enabled,
        "overall_status": overall,
        "jobs": jobs_status,
    }


@app.post("/api/v1/scan/all/sync")
def start_all_scans_sync(req: UnifiedScanRequest) -> Dict[str, Any]:
    """테스트/데모용 블로킹 버전. 4개를 스레드로 동시에 실행하고 전부 끝날 때까지
    기다렸다가 한 번에 반환한다. 진단 항목/도구 특성상 수초~수분 걸릴 수 있으므로
    실제 대시보드 연동에는 위의 비동기(job) 방식(/api/v1/scan/all)을 권장한다."""
    if not req.confirm_authorized:
        raise HTTPException(status_code=400, detail="confirm_authorized=true로 네 가지 진단 모두에 대한 권한을 확인해야 합니다.")
    if not req.base_url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="base_url은 http:// 또는 https:// 로 시작해야 합니다.")

    fu_req, sqli_req, session_req, xss_req = _build_unified_sub_requests(req)

    results: Dict[str, Any] = {}
    errors: Dict[str, str] = {}

    def _run_and_store(name: str, fn) -> None:
        try:
            results[name] = fn()
        except Exception as e:
            errors[name] = str(e)

    threads: List[threading.Thread] = []

    if req.run_file_upload:
        _validate_target(fu_req.target_url, fu_req.confirm_authorized)
        threads.append(threading.Thread(
            target=_run_and_store, args=("file_upload", lambda: _run_and_load_json(_build_scanner(fu_req), fu_req))
        ))
    if req.run_sqli:
        threads.append(threading.Thread(target=_run_and_store, args=("sqli", lambda: _run_sqli(sqli_req))))
    if req.run_session:
        threads.append(threading.Thread(target=_run_and_store, args=("session", lambda: _run_session(session_req))))
    if req.run_xss:
        if XSS_AVAILABLE:
            threads.append(threading.Thread(target=_run_and_store, args=("xss", lambda: _run_xss(xss_req))))
        else:
            errors["xss"] = f"playwright 미설치: {_xss_import_error}"

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return {"target_base_url": req.base_url, "results": results, "errors": errors}


# =========================================================================== #
# 헬스체크
# =========================================================================== #

@app.get("/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "file_upload_tool_version": TOOL_VERSION,
        "sqli_available": SQLI_AVAILABLE,
        "sqli_unavailable_reason": _sqli_scanner_import_error,
        "session_available": SESSION_AVAILABLE,
        "session_unavailable_reason": _session_scanner_import_error,
        "xss_available": XSS_AVAILABLE,
        "xss_unavailable_reason": _xss_import_error,
        # 서버 환경변수(.env 포함)로 OPENAI_API_KEY가 잡혀있는지. 대시보드에서
        # openai_api_key를 매번 안 보내도 되는 조건인지 미리 확인할 때 씀.
        "openai_configured": bool(os.environ.get("OPENAI_API_KEY")),
    }
