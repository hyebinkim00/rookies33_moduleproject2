"""
file_upload_vuln_scanner.py

파일 업로드 취약점 자동 진단 도구
==================================
웹 애플리케이션의 파일 업로드 기능에 대해 알려진 우회 기법(이중 확장자, 널 바이트,
Content-Type 스푸핑, 매직 바이트 조작, 경로 조작, SVG 기반 공격, 폴리글랏 파일 등)을
순차적으로 시도하고, 각 시도에 대해 "무엇을 시도했는지 / 어떻게 판단했는지 / 왜 그렇게
판단했는지"를 구조화된 근거와 함께 기록합니다.

또한 업로드에 사용되는 파일의 "포맷(실제 시그니처)"과 "파일명" 자체를 정적으로 분석하는
FileFormatNameAnalyzer 모듈을 통해, 서버 응답에 의존하지 않고도 파일 자체의 위험 요소를
진단할 수 있습니다.

추가로 mrm8488/codebert-base-finetuned-detect-insecure-code 모델을 이용해
업로드 처리 서버 측 소스코드(제공 시)에 대한 정적 코드 수준 위험 분석을 보조로
수행합니다.

⚠️ 반드시 진단 권한이 있는 대상(자체 구축 랩 환경, 사내 승인된 시스템 등)에만
사용하세요.

필요 패키지:
    pip install requests transformers torch
"""

from __future__ import annotations

import argparse
import base64
import difflib
import io
import json
import os
import random
import re
import time
import unicodedata
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urljoin

import numpy as np
import requests

TOOL_VERSION = "0.5.0"


# --------------------------------------------------------------------------- #
# 결과 스키마
# --------------------------------------------------------------------------- #

# status 값 정의:
#   "양호" : 시도한 우회/공격이 서버에서 정상적으로 방어됨
#   "취약" : 시도한 우회/공격이 성공하여 취약점이 확인됨
#   "N/A"  : 아래 두 경우를 모두 포함한다.
#            (1) 대상 환경/파일 특성상 해당 진단 항목 자체가 구조적으로 적용되지 않는 경우
#                (예: Apache가 아닌 서버에 .htaccess 테스트, 이미지가 아닌 엔드포인트에
#                     이미지 시그니처 검사 등)
#            (2) 네트워크 오류, 모델 로드 실패 등으로 근거가 불충분해 양호/취약를
#                명확히 판단할 수 없는 경우

VALID_STATUSES = ("양호", "취약", "N/A")
VALID_RISKS = ("낮음", "중간", "높음")
# confidence: status(양호/취약/N/A) 3분류는 그대로 두되, "취약" 판정이 실제로
# 검증(실행 확인, 콘텐츠 대조 등)된 것인지 아니면 요청이 수락된 것만으로 추정한
# 것인지를 별도로 표시한다. 블랙박스 진단의 본질적 한계(응답만으로 실제 영향을
# 확정할 수 없는 경우가 많음)를 status를 늘리지 않고도 드러내기 위함.
VALID_CONFIDENCE = ("확정", "추정")


@dataclass
class DiagnosisResult:
    vulnerability: str          # 취약점명 (또는 진단 항목명)
    status: str                 # "양호" / "취약" / "N/A"
    risk: str                   # "낮음" / "중간" / "높음"
    evidence: str                # 자동진단에서 실제 탐지한 내용
    reason: str                  # 해당 결과로 판정한 근거
    recommendation: str          # 보안 대응방안
    parameter: str = ""         # 진단에 사용된 파라미터/필드명 (업로드 폼의 file 필드명, 분석 대상 파일명 등)
    payload: str = ""           # 진단 시 실제 사용한 입력값(페이로드) 원문. 여러 개면 '; '로 이어붙임
    confidence: str = "확정"     # "확정"(직접 검증됨) / "추정"(요청 수락만으로 추론)
    tested_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def __post_init__(self):
        if self.status not in VALID_STATUSES:
            raise ValueError(f"잘못된 status 값: {self.status} (허용값: {VALID_STATUSES})")
        if self.risk not in VALID_RISKS:
            raise ValueError(f"잘못된 risk 값: {self.risk} (허용값: {VALID_RISKS})")
        if self.confidence not in VALID_CONFIDENCE:
            raise ValueError(f"잘못된 confidence 값: {self.confidence} (허용값: {VALID_CONFIDENCE})")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# 파일 포맷 / 파일명 정적 분석기 (서버 응답과 무관하게 파일 자체를 진단)
# --------------------------------------------------------------------------- #

class FileFormatNameAnalyzer:
    """
    업로드에 사용되는(혹은 사용될) 파일의 실제 포맷(매직 바이트 시그니처)과
    파일명 자체의 위험 패턴을 정적으로 분석한다. 서버에 요청을 보내지 않고
    로컬 파일 하나만으로도 독립적으로 사용할 수 있다.
    """

    # 확장자별 실행/스크립트 위험도가 있는 확장자 (서버사이드 인터프리터 매핑 대상)
    DANGEROUS_EXTENSIONS = {
        ".php", ".php3", ".php4", ".php5", ".php7", ".phtml", ".pht", ".phar",
        ".jsp", ".jspx", ".jsw", ".jsv",
        ".asp", ".aspx", ".asa", ".cer", ".ashx",
        ".exe", ".dll", ".sh", ".bash", ".bat", ".cmd", ".ps1",
        ".cgi", ".pl", ".py", ".rb",
        ".htaccess", ".config",
    }

    # 파일 매직 바이트 시그니처 (앞부분 바이트 -> 실제 포맷 이름)
    # 텍스트 기반 포맷(svg, php 등)은 바이트 시그니처가 아니라 콘텐츠 패턴으로 별도 판별
    MAGIC_SIGNATURES: List[Tuple[bytes, str]] = [
        (b"\xFF\xD8\xFF", "JPEG"),
        (b"\x89PNG\r\n\x1a\n", "PNG"),
        (b"GIF87a", "GIF"),
        (b"GIF89a", "GIF"),
        (b"%PDF-", "PDF"),
        (b"PK\x03\x04", "ZIP/OOXML/JAR/APK (ZIP 기반 컨테이너)"),
        (b"\x7fELF", "ELF 실행파일 (Linux)"),
        (b"MZ", "PE 실행파일 (Windows .exe/.dll)"),
        (b"BM", "BMP"),
        (b"\x00\x00\x01\x00", "ICO"),
        (b"RIFF", "RIFF 컨테이너 (WAV/AVI/WEBP)"),
    ]

    # 확장자 -> 이 확장자라면 기대되는 포맷 이름 목록 (매칭 검증용)
    EXPECTED_FORMAT_BY_EXT = {
        ".jpg": ["JPEG"], ".jpeg": ["JPEG"],
        ".png": ["PNG"],
        ".gif": ["GIF"],
        ".pdf": ["PDF"],
        ".zip": ["ZIP/OOXML/JAR/APK (ZIP 기반 컨테이너)"],
        ".docx": ["ZIP/OOXML/JAR/APK (ZIP 기반 컨테이너)"],
        ".xlsx": ["ZIP/OOXML/JAR/APK (ZIP 기반 컨테이너)"],
        ".pptx": ["ZIP/OOXML/JAR/APK (ZIP 기반 컨테이너)"],
        ".bmp": ["BMP"],
        ".ico": ["ICO"],
        ".webp": ["RIFF 컨테이너 (WAV/AVI/WEBP)"],
    }

    RESERVED_WINDOWS_NAMES = {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }

    # 텍스트 기반 콘텐츠에서 스크립트/코드 실행 신호를 찾기 위한 패턴
    SCRIPT_CONTENT_PATTERNS = [
        (re.compile(rb"<\?php", re.IGNORECASE), "PHP 코드"),
        (re.compile(rb"<%@\s*page", re.IGNORECASE), "JSP 코드"),
        (re.compile(rb"<script[\s>]", re.IGNORECASE), "HTML <script> 태그"),
        (re.compile(rb"#!\s*/(bin|usr)/", re.IGNORECASE), "쉘 스크립트 셔뱅(shebang)"),
    ]

    @staticmethod
    def get_extension(filename: str) -> str:
        base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        if "." not in base:
            return ""
        return "." + base.rsplit(".", 1)[-1].lower()

    @classmethod
    def get_all_extensions(cls, filename: str) -> List[str]:
        """이중/삼중 확장자를 모두 추출 (예: shell.php.jpg -> ['.php', '.jpg'])"""
        base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        parts = base.split(".")
        if len(parts) <= 1:
            return []
        return ["." + p.lower() for p in parts[1:]]

    @classmethod
    def detect_format_by_signature(cls, content: bytes) -> str:
        """매직 바이트 기준으로 실제 파일 포맷 판별. 매칭 실패 시 텍스트 기반
        스크립트 콘텐츠 여부까지 확인하고, 그마저 실패하면 'UNKNOWN' 반환."""
        for signature, name in cls.MAGIC_SIGNATURES:
            if content[: len(signature)] == signature:
                return name
        for pattern, name in cls.SCRIPT_CONTENT_PATTERNS:
            if pattern.search(content[:4096]):
                return name
        # 텍스트로 디코딩 가능한 순수 텍스트 파일인지 확인
        try:
            content[:512].decode("utf-8")
            return "PLAIN_TEXT"
        except UnicodeDecodeError:
            return "UNKNOWN"

    # ------------------------------------------------------------------ #
    # 개별 진단 항목
    # ------------------------------------------------------------------ #

    def check_extension_format_mismatch(self, filename: str, content: bytes, field_name: str = "file") -> DiagnosisResult:
        """파일명 확장자와 실제 콘텐츠 시그니처가 일치하는지 검사 (확장자 위장 탐지)"""
        vuln = "확장자-실제 포맷 불일치 (Extension/Content Mismatch)"
        ext = self.get_extension(filename)
        detected = self.detect_format_by_signature(content)

        if not ext:
            return DiagnosisResult(
                vuln, "N/A", "낮음",
                evidence="파일명에 확장자가 없어 비교 대상이 없음",
                reason="확장자가 없는 파일은 확장자-포맷 일치 여부 검사 대상이 아님",
                recommendation="해당 없음",
                parameter=field_name,
            )

        expected_formats = self.EXPECTED_FORMAT_BY_EXT.get(ext)
        script_like = detected not in ("UNKNOWN", "PLAIN_TEXT") and any(
            detected == name for _, name in self.SCRIPT_CONTENT_PATTERNS
        )

        if expected_formats is None:
            # 이미지/문서류로 기대 포맷이 정의되지 않은 확장자 (php, sh 등) - 스크립트 패턴만 확인
            if script_like or ext in self.DANGEROUS_EXTENSIONS and detected != "UNKNOWN":
                return DiagnosisResult(
                    vuln, "N/A", "중간",
                    evidence=f"확장자 '{ext}'는 기대 바이너리 포맷이 정의되어 있지 않음 (실제 탐지: {detected})",
                    reason="이미지/문서류가 아닌 확장자라 정합성 비교 기준이 없어 정상/취약으로 단정할 수 없음",
                    recommendation="이 확장자 자체가 서버에서 허용되어서는 안 되는지 별도 정책 확인 필요",
                    parameter=field_name,
                )
            return DiagnosisResult(
                vuln, "N/A", "낮음",
                evidence=f"확장자 '{ext}'에 대한 기대 포맷 매핑이 정의되어 있지 않음",
                reason="비교 기준(이미지/문서 등 알려진 바이너리 포맷)이 없는 확장자",
                recommendation="해당 없음",
                parameter=field_name,
            )

        if detected in expected_formats:
            return DiagnosisResult(
                vuln, "양호", "낮음",
                evidence=f"확장자 '{ext}'와 실제 탐지 포맷 '{detected}'이 일치함",
                reason="파일 시그니처가 확장자와 부합하여 위장 정황이 없음",
                recommendation="현재 상태 유지, 다만 서버 측에서도 동일한 시그니처 검증을 수행하는지 별도 확인 권장",
                parameter=field_name,
            )

        risk = "높음" if script_like else "중간"
        return DiagnosisResult(
            vuln, "취약", risk,
            evidence=f"파일명 확장자는 '{ext}'이나 실제 콘텐츠는 '{detected}'로 탐지됨",
            reason="확장자와 실제 파일 시그니처가 불일치하여, 이미지 등으로 위장된 악성 콘텐츠일 가능성이 있음"
                    + ("(콘텐츠 내 스크립트 실행 코드 패턴 확인됨)" if script_like else ""),
            recommendation="파일명이 아닌 실제 콘텐츠 시그니처(매직 바이트)를 기준으로 파일 타입을 검증하고, "
                            "가능하면 이미지 재인코딩 등으로 페이로드를 무력화할 것",
            parameter=field_name,
        )

    def check_polyglot_signature(self, content: bytes, field_name: str = "file") -> DiagnosisResult:
        """정상 이미지 시그니처와 스크립트 코드가 한 파일 안에 동시에 존재하는
        폴리글랏(polyglot) 파일 여부 검사"""
        vuln = "폴리글랏 파일 (이미지+스크립트 동시 포함)"
        has_image_sig = any(content[: len(sig)] == sig for sig, _ in self.MAGIC_SIGNATURES[:5])
        script_hits = [name for pattern, name in self.SCRIPT_CONTENT_PATTERNS if pattern.search(content)]

        if has_image_sig and script_hits:
            return DiagnosisResult(
                vuln, "취약", "높음",
                evidence=f"파일 앞부분은 정상 이미지 시그니처이나, 콘텐츠 내부에 {', '.join(script_hits)} 패턴이 함께 존재함",
                reason="이미지 헤더와 실행 가능한 스크립트 코드가 한 파일에 공존하는 전형적인 폴리글랏 웹셸 구조로 판단",
                recommendation="이미지 업로드 처리 시 반드시 재인코딩(리사이즈/재압축)을 수행해 원본 바이트를 보존하지 않도록 하고, "
                                "업로드 디렉터리는 스크립트 실행 권한을 제거할 것",
                parameter=field_name,
            )
        if script_hits and not has_image_sig:
            return DiagnosisResult(
                vuln, "N/A", "낮음",
                evidence=f"이미지 시그니처는 없으나 스크립트 패턴({', '.join(script_hits)})이 발견됨",
                reason="폴리글랏 조건(이미지 시그니처 + 스크립트 동시 존재) 중 일부만 충족하여 별도 항목(확장자/콘텐츠 불일치 등)에서 이미 다루어질 가능성이 있음",
                recommendation="이 결과는 확장자-포맷 불일치 진단 결과와 함께 교차 확인할 것",
                parameter=field_name,
            )
        return DiagnosisResult(
            vuln, "양호", "낮음",
            evidence="이미지 시그니처와 스크립트 패턴이 동시에 발견되지 않음",
            reason="폴리글랏 구조의 증거가 없음",
            recommendation="해당 없음",
            parameter=field_name,
        )

    def check_filename_pattern(self, filename: str, field_name: str = "file") -> DiagnosisResult:
        """파일명 자체에 포함된 위험 패턴 종합 검사: 이중 확장자, 위험 확장자 포함,
        경로 조작 문자, 널 바이트 흔적, 대소문자 우회, 길이, trailing dot/space 등"""
        vuln = "파일명 위험 패턴 (Filename Risk Pattern)"
        findings: List[str] = []
        risk = "낮음"

        base = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        all_exts = self.get_all_extensions(filename)

        # 1) 위험 확장자가 파일명 어디에든(이중 확장자 포함) 포함되는지
        dangerous_hits = [e for e in all_exts if e in self.DANGEROUS_EXTENSIONS]
        if dangerous_hits:
            findings.append(f"위험 확장자 포함: {', '.join(dangerous_hits)}")
            risk = "높음"

        # 2) 이중 이상 확장자 여부
        if len(all_exts) >= 2:
            findings.append(f"이중/다중 확장자 구조: {'.'.join(all_exts)}")
            if risk != "높음":
                risk = "중간"

        # 3) 경로 조작 문자
        if "../" in filename or "..\\" in filename or filename.startswith("/"):
            findings.append("경로 조작 문자열('../' 등) 포함")
            risk = "높음"

        # 4) 널 바이트 / 제어 문자
        if "\x00" in filename or any(ord(c) < 0x20 for c in filename):
            findings.append("널 바이트 또는 제어 문자 포함")
            risk = "높음"

        # 5) 대소문자 우회 시도 (예: pHp, PHP, PhP)
        for e in all_exts:
            if e.lower() in self.DANGEROUS_EXTENSIONS and re.search(r"[A-Z]", filename) and re.search(r"[a-z]", filename):
                findings.append("확장자 대소문자 혼용 (필터 우회 시도 가능성)")
                break

        # 6) 유니코드 RTLO / 동형문자(homoglyph) 악용 여부
        if "\u202e" in filename or "\u200f" in filename:
            findings.append("우로부터좌 제어문자(RTLO 등) 포함 - 확장자 위장 가능성")
            risk = "높음"
        if any(unicodedata.category(c) == "Cf" for c in filename):
            findings.append("비가시 유니코드 서식 문자 포함")
            if risk == "낮음":
                risk = "중간"

        # 7) Windows 예약 장치명
        name_wo_ext = base.split(".")[0].upper()
        if name_wo_ext in self.RESERVED_WINDOWS_NAMES:
            findings.append(f"Windows 예약 장치명 '{name_wo_ext}' 사용")
            if risk == "낮음":
                risk = "중간"

        # 8) 파일명 끝에 공백/점 (Windows에서 자동 제거되어 확장자 위장에 악용 가능)
        if base != base.rstrip(" ."):
            findings.append("파일명 끝에 공백 또는 점(trailing dot/space) 포함")
            if risk == "낮음":
                risk = "중간"

        # 9) 과도한 길이
        if len(filename.encode("utf-8")) > 255:
            findings.append(f"파일명 길이 초과 ({len(filename.encode('utf-8'))} bytes > 255)")
            if risk == "낮음":
                risk = "중간"

        # 10) 숨김파일(닷파일) - .htaccess, .env 등
        if base.startswith(".") and base not in (".", ".."):
            findings.append(f"숨김/설정 파일 형태의 파일명 ('{base}')")
            risk = "높음"

        if findings:
            return DiagnosisResult(
                vuln, "취약", risk,
                evidence="; ".join(findings),
                reason="파일명 자체에서 확장자 필터/경로 검증 우회에 흔히 쓰이는 패턴이 다수 발견됨",
                recommendation="서버에서 원본 파일명을 신뢰하지 말고, 업로드 시 UUID 등으로 파일명을 재생성하여 저장할 것. "
                                "부득이하게 원본 파일명을 보존해야 한다면 화이트리스트 문자 집합(영숫자, '-', '_')만 허용할 것",
                parameter=field_name,
                payload=filename,
            )
        return DiagnosisResult(
            vuln, "양호", "낮음",
            evidence=f"파일명 '{base}'에서 알려진 위험 패턴이 발견되지 않음",
            reason="이중 확장자, 경로 조작, 제어문자, 예약어 등 점검 항목에서 특이사항 없음",
            recommendation="현재 상태 유지",
            parameter=field_name,
        )

    def analyze(self, filename: str, content: bytes, field_name: str = "file") -> List[DiagnosisResult]:
        """파일명 + 콘텐츠에 대해 포맷/이름/콘텐츠 관련 진단 항목을 모두 실행.
        field_name: 이 파일이 실려온 실제 업로드 폼/HTTP 요청의 파라미터명(예: 'file').
        각 DiagnosisResult의 parameter 필드에 그대로 채워, "어떤 입력 파라미터를
        테스트했는지"가 리포트에 남도록 한다."""
        return [
            self.check_extension_format_mismatch(filename, content, field_name=field_name),
            self.check_polyglot_signature(content, field_name=field_name),
            self.check_filename_pattern(filename, field_name=field_name),
            *ContentPatternScanner.check_content_patterns(filename, content, field_name=field_name),
        ]

    def analyze_path(self, path: str, field_name: str = "file") -> List[DiagnosisResult]:
        """로컬 디스크에 있는 실제 파일 경로를 읽어 분석 (오프라인 진단용)"""
        with open(path, "rb") as f:
            content = f.read()
        return self.analyze(os.path.basename(path), content, field_name=field_name)


# --------------------------------------------------------------------------- #
# 파일 내부 콘텐츠(텍스트) 패턴 스캐너 — SQLi/XSS 등 공격 문자열이 파일 안에
# 텍스트 형태로 숨어있는지 검사 (파일명/시그니처만으로는 잡을 수 없는 영역)
# --------------------------------------------------------------------------- #

class ContentPatternScanner:
    """
    파일에서 실제 텍스트를 추출한 뒤(가능한 경우), SQL Injection / XSS /
    Command Injection / SSTI 등 공격에 흔히 쓰이는 문자열 패턴이 있는지 검사한다.

    PDF는 pypdf로 페이지 텍스트 + 메타데이터(Title/Author/Subject/Keywords)까지
    모두 추출해서 검사한다 (메타데이터 필드에 페이로드를 숨기는 경우가 실제로
    있으므로 반드시 함께 검사해야 함). 그 외 포맷은 UTF-8 디코딩이 가능한
    경우에 한해 원문 그대로를 대상으로 검사한다 (일반 텍스트/HTML/SVG/CSV/코드 등).

    ⚠️ 여기서 하는 것은 "파일 안에 이런 문자열이 있다"는 정적 패턴 매칭이지,
    실제로 그 SQL/스크립트를 실행해보는 것이 아니다. 따라서 오탐(false positive)이
    있을 수 있으며, 최종 판단은 사람이 evidence를 보고 교차 확인해야 한다.
    """

    # 카테고리별 탐지 정규식 (대소문자 무시). 필요에 따라 팀에서 패턴을 추가/조정할 것.
    PATTERN_CATEGORIES: Dict[str, List["re.Pattern"]] = {
        "SQL Injection": [
            re.compile(r"'\s*or\s*'?1'?\s*=\s*'?1", re.IGNORECASE),
            re.compile(r"\bunion\s+select\b", re.IGNORECASE),
            re.compile(r"\bdrop\s+table\b", re.IGNORECASE),
            re.compile(r"\bxp_cmdshell\b", re.IGNORECASE),
            re.compile(r"\bsleep\s*\(\s*\d+\s*\)", re.IGNORECASE),
            re.compile(r"\binformation_schema\b", re.IGNORECASE),
            re.compile(r"admin'\s*--", re.IGNORECASE),
            re.compile(r"'\s*;\s*(drop|delete|insert|update)\b", re.IGNORECASE),
        ],
        "XSS (Cross-Site Scripting)": [
            re.compile(r"<script[\s>]", re.IGNORECASE),
            re.compile(r"on(error|load|focus|mouseover|click|blur)\s*=", re.IGNORECASE),
            re.compile(r"javascript\s*:", re.IGNORECASE),
            re.compile(r"<svg[^>]*onload", re.IGNORECASE),
            re.compile(r"<iframe[\s>]", re.IGNORECASE),
            re.compile(r"alert\s*\(\s*(document\.cookie|['\"1])", re.IGNORECASE),
        ],
        "Command Injection": [
            re.compile(r";\s*(rm|cat|whoami|nc|wget|curl|bash|sh)\b", re.IGNORECASE),
            re.compile(r"\$\([^)]{1,80}\)"),
            re.compile(r"`[^`]{1,80}`"),
            re.compile(r"\|\|\s*(rm|cat|whoami|nc)\b", re.IGNORECASE),
        ],
        "SSTI (서버사이드 템플릿 인젝션)": [
            re.compile(r"\{\{.{0,40}7\s*\*\s*7.{0,40}\}\}"),
            re.compile(r"\$\{.{0,40}7\s*\*\s*7.{0,40}\}"),
            re.compile(r"#\{.{0,40}7\s*\*\s*7.{0,40}\}"),
        ],
    }

    # 카테고리별 (취약 시 위험도, 대응방안)
    CATEGORY_INFO = {
        "SQL Injection": ("높음",
            "이 문자열이 DB 쿼리에 그대로 사용/저장/전시되는 경로가 있다면 반드시 파라미터화된 쿼리(Prepared "
            "Statement)를 사용하고, 파일 콘텐츠를 신뢰하지 말 것. 파일을 파싱해 DB에 적재하는 배치가 있다면 "
            "해당 배치의 입력 검증도 함께 점검할 것"),
        "XSS (Cross-Site Scripting)": ("중간",
            "파일 내용을 웹 화면에 그대로 렌더링(미리보기, 뷰어 등)하는 기능이 있다면 반드시 출력 시 "
            "HTML 이스케이프를 적용하고, 가능하면 CSP(Content-Security-Policy)를 함께 적용할 것"),
        "Command Injection": ("높음",
            "파일 내용을 셸 명령이나 서버 스크립트 실행 인자로 사용하는 경로가 있는지 반드시 확인하고, "
            "있다면 셸 실행 자체를 피하거나 입력을 엄격히 검증/이스케이프할 것"),
        "SSTI (서버사이드 템플릿 인젝션)": ("중간",
            "파일 내용을 템플릿 엔진(Jinja2, Freemarker 등)에 그대로 전달해 렌더링하는 경로가 있는지 확인하고, "
            "있다면 사용자 제공 콘텐츠를 템플릿 컨텍스트가 아닌 순수 데이터로만 취급할 것"),
    }

    @classmethod
    def _extract_text(cls, filename: str, content: bytes) -> Tuple[Optional[str], str]:
        """콘텐츠에서 검사 가능한 텍스트를 추출한다.
        반환: (추출된 텍스트 또는 None, 텍스트 출처 설명)"""
        if content[:5] == b"%PDF-":
            try:
                import io as _io
                from pypdf import PdfReader
                reader = PdfReader(_io.BytesIO(content))
                parts = []
                meta = reader.metadata or {}
                for key in ("title", "author", "subject", "keywords", "creator", "producer"):
                    value = getattr(meta, key, None)
                    if value:
                        parts.append(f"[메타데이터:{key}] {value}")
                for i, page in enumerate(reader.pages):
                    try:
                        text = page.extract_text() or ""
                    except Exception:
                        text = ""
                    if text.strip():
                        parts.append(f"[페이지 {i + 1}] {text}")
                if not parts:
                    return "", "PDF (텍스트/메타데이터 없음)"
                return "\n".join(parts), "PDF 본문 텍스트 + 메타데이터"
            except ImportError:
                return None, "pypdf 미설치로 PDF 텍스트 추출 불가 (pip install pypdf 필요)"
            except Exception as e:
                return None, f"PDF 파싱 실패: {e}"

        # ZIP 기반 오피스 문서(docx/xlsx/pptx)는 document.xml 등에서 텍스트만 간단히 추출
        if content[:4] == b"PK\x03\x04":
            try:
                import io as _io
                import zipfile
                extracted = []
                with zipfile.ZipFile(_io.BytesIO(content)) as zf:
                    for name in zf.namelist():
                        if name.endswith(".xml") and (
                            "word/" in name or "sheet" in name or "slide" in name or name == "docProps/core.xml"
                        ):
                            try:
                                xml_bytes = zf.read(name)
                                text_only = re.sub(rb"<[^>]+>", b" ", xml_bytes).decode("utf-8", errors="ignore")
                                if text_only.strip():
                                    extracted.append(f"[{name}] {text_only}")
                            except Exception:
                                continue
                if extracted:
                    return "\n".join(extracted), "OOXML(docx/xlsx/pptx) 내부 XML 텍스트"
                return "", "ZIP 기반 컨테이너 (추출 가능한 텍스트 없음)"
            except Exception as e:
                return None, f"ZIP/OOXML 파싱 실패: {e}"

        # 그 외: UTF-8로 디코딩 가능하면 원문 그대로 검사 (일반 텍스트/HTML/SVG/CSV/코드 등)
        try:
            return content.decode("utf-8"), "UTF-8 디코딩된 원문 텍스트"
        except UnicodeDecodeError:
            # 바이너리라 UTF-8 디코딩이 안 되더라도, latin-1은 항상 디코딩되므로
            # 이를 이용한 best-effort 스캔으로 완전히 놓치지는 않도록 함
            return content.decode("latin-1", errors="ignore"), "바이너리 파일 내 ASCII 문자열 best-effort 스캔"

    @classmethod
    def check_content_patterns(cls, filename: str, content: bytes, field_name: str = "file") -> List[DiagnosisResult]:
        text, source_desc = cls._extract_text(filename, content)
        results: List[DiagnosisResult] = []

        if text is None:
            for category in cls.PATTERN_CATEGORIES:
                results.append(DiagnosisResult(
                    vulnerability=f"콘텐츠 패턴 진단: {category}", status="N/A", risk="낮음",
                    evidence=f"텍스트 추출 불가 ({source_desc})",
                    reason="파일 내부 텍스트를 추출할 수 없어 콘텐츠 기반 패턴 검사를 수행할 수 없음",
                    recommendation="필요 패키지 설치 여부를 확인하거나, 해당 포맷 전용 파서를 추가할 것",
                    parameter=field_name,
                ))
            return results

        for category, patterns in cls.PATTERN_CATEGORIES.items():
            matches = []       # evidence 표시용 (60자로 축약)
            raw_matches = []   # payload 필드용 (외부 시스템 연동용, 500자까지 원문 보존)
            for rgx in patterns:
                m = rgx.search(text)
                if m:
                    raw = m.group(0)
                    raw_matches.append(raw[:500])
                    snippet = raw if len(raw) <= 60 else raw[:60] + "..."
                    matches.append(snippet)

            if matches:
                risk, recommendation = cls.CATEGORY_INFO[category]
                results.append(DiagnosisResult(
                    vulnerability=f"콘텐츠 패턴 진단: {category}", status="취약", risk=risk,
                    evidence=f"[{source_desc}] 다음 패턴이 발견됨: {matches}",
                    reason=f"파일 내부 텍스트에서 {category} 공격에 흔히 쓰이는 문자열 패턴이 {len(matches)}건 발견됨 "
                           f"(정적 패턴 매칭 결과이므로 실제 악용 가능 여부는 이 파일을 사용하는 기능을 기준으로 별도 확인 필요)",
                    recommendation=recommendation,
                    parameter=field_name,
                    payload="; ".join(raw_matches),
                ))
            else:
                results.append(DiagnosisResult(
                    vulnerability=f"콘텐츠 패턴 진단: {category}", status="양호", risk="낮음",
                    evidence=f"[{source_desc}] 알려진 {category} 패턴이 발견되지 않음",
                    reason="정의된 탐지 규칙 기준으로 특이 패턴 없음",
                    recommendation="현재 상태 유지. 다만 정규식 기반 탐지의 한계상 신종/변형 패턴은 놓칠 수 있음",
                    parameter=field_name,
                ))
        return results


# --------------------------------------------------------------------------- #
# 파일 업로드 취약점 스캐너 (블랙박스, 대상 서버에 실제 요청 전송)
# --------------------------------------------------------------------------- #

class FileUploadVulnScanner:
    """
    대상 URL의 파일 업로드 엔드포인트에 대해 여러 우회 기법을 시도하는 블랙박스
    진단기.

    v0.4 변경사항 (실무 피드백 반영):
    - 판정 기준을 "키워드 추측"이 아니라 "정상 파일(베이스라인) 업로드 응답과의 비교"로
      바꿈. run_all() 시작 시 실제 정상 PNG를 한 번 업로드해 성공 응답의 모양(상태코드,
      Content-Type, 저장 경로 패턴)을 학습하고, 이후 모든 시도를 이 베이스라인과 비교한다.
    - 401/403/406/429는 "업로드 필터가 막음(양호)"이 아니라 "인증/CSRF/WAF/레이트리밋에
      막혔을 가능성(N/A, 수동확인 필요)"으로 분리한다.
    - RCE(코드 실행) 확인 시, 소스 원문 에코와 실제 실행을 구분하기 위해 "그 자리에서
      계산해야만 나올 수 있는 값"(예: 난수 곱셈 결과)을 마커로 쓰고, 응답에 원본 PHP
      태그가 남아있지 않은 경우에만 "실행됨"으로 판정한다.
    - 업로드 성공 응답(JSON/redirect 등)에서 저장 경로/URL을 정규식·JSON 파싱으로
      자동 추출해, uploaded_file_base_url을 몰라도 실행/접근 검증을 시도한다.
    - 대상 서버에 실제로 시도한 파일 목록(attempted_uploads)을 기록하고, cleanup=True면
      추출된 저장 URL에 대해 best-effort DELETE 요청까지 시도한다 (REST 규약을 따르는
      경우에만 동작하며, 보장되지는 않음 — 최종 정리는 팀이 직접 확인할 것).

    v0.5 변경사항 (베이스라인이 본문을 안 보는 문제 수정):
    - 상당수 실무 앱은 성공/거부 모두 같은 상태코드+Content-Type(예: 200+text/html,
      200+application/json)으로 응답하고 차이는 "본문 내용"에만 있다. v0.4까지는
      상태코드 계열+Content-Type만 비교해서 이런 앱에서 체계적 오탐이 났다.
      v0.5부터 _classify_response가 본문까지 비교한다: JSON이면 최상위 키 집합을,
      그 외(HTML/텍스트)면 베이스라인과의 difflib 유사도를 비교하고, 본문에
      BLOCKED_KEYWORDS가 있으면 상태코드/CT가 같아도 무조건 차단으로 판정한다.
      판정 근거 문장은 evidence에 그대로 실어(무엇을 비교해서 어떻게 판단했는지)
      감사 가능성을 확보했다.
    - "실행/콘텐츠까지 직접 검증된 취약점"과 "요청이 수락된 것만으로 추정한 취약점"을
      구분하기 위해 DiagnosisResult에 confidence("확정"/"추정") 필드를 추가했다.
      status(양호/취약/N/A) 3분류는 그대로 유지하면서, 리포트 summary에서
      confirmed_vulnerabilities(확정)와 estimated_vulnerabilities(추정)를 분리해
      우선순위를 정할 때 바로 참고할 수 있게 했다.
    - SVG XXE 체크에서, 업로드만 성공하고 실제 파일 읽기 증거(root:x:0:0)가 없는
      경우를 "취약"이 아니라 "N/A(수동확인 필요)"로 정정했다 — 엔티티가 확장되지
      않은 원문 그대로 서빙되는 것이 오히려 정상적인 경우가 많아, 업로드 성공만으로
      XXE를 취약으로 단정하는 것은 과단정이었다.
    """

    SUCCESS_KEYWORDS = ["success", "uploaded", "업로드 성공", "ok"]
    BLOCKED_KEYWORDS = ["denied", "invalid", "not allowed", "차단", "거부", "error"]
    # 파일 업로드 필터가 아니라 인증/CSRF/WAF/레이트리밋에 의해 막혔을 가능성이 높은 상태코드.
    # 이 경우를 "양호"로 잘못 분류하면 실제로는 확인되지 않은 것을 확인됐다고 보고하게 되므로
    # 반드시 별도(N/A)로 분리한다.
    AUTH_OR_WAF_STATUS_CODES = {401, 403, 406, 429}

    DEFAULT_USER_AGENT = f"Mozilla/5.0 (compatible; FileUploadVulnScanner/{TOOL_VERSION}; internal-security-test)"

    # 1x1 투명 PNG. 베이스라인(정상) 업로드 요청에 사용해 "성공 시 응답이 어떤 모양인지"를
    # 먼저 학습하기 위한 용도.
    BASELINE_PNG = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk"
        "+A8AAQUBAScY42YAAAAASUVORK5CYII="
    )

    def __init__(
        self,
        target_url: str,
        upload_field: str = "file",
        extra_form_fields: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True,
        timeout: int = 10,
        uploaded_file_base_url: Optional[str] = None,
        dos_size_mb: int = 10,
        skip_dos: bool = True,
        max_retries: int = 1,
        request_delay: float = 0.3,
        cleanup: bool = False,
    ):
        if target_url != "(offline)" and not target_url.lower().startswith(("http://", "https://")):
            raise ValueError(
                f"target_url은 http:// 또는 https:// 로 시작해야 합니다: '{target_url}'"
            )

        self.target_url = target_url
        self.upload_field = upload_field
        self.extra_form_fields = extra_form_fields or {}
        self.headers = dict(headers or {})
        self.headers.setdefault("User-Agent", self.DEFAULT_USER_AGENT)
        self.cookies = cookies or {}
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.uploaded_file_base_url = uploaded_file_base_url
        self.dos_size_mb = dos_size_mb
        self.skip_dos = skip_dos
        self.max_retries = max_retries
        self.request_delay = request_delay
        self.cleanup = cleanup
        self.session = requests.Session()

        self.results: List[DiagnosisResult] = []
        self.format_analyzer = FileFormatNameAnalyzer()
        self._server_header: Optional[str] = None
        self._server_header_checked = False

        # run_all() 시작 시 _establish_baseline()이 채움. None이면 베이스라인 학습에
        # 실패한 것이므로 이후 판정은 키워드 휴리스틱으로 폴백한다.
        self.baseline: Optional[Dict[str, Any]] = None
        self._waf_suspected = False
        self._last_classification_detail: str = ""

        # 이번 실행에서 대상 서버에 실제로 업로드를 "시도"한 파일명 기록.
        # 성공 여부와 무관하게 남기며, 진단 종료 후 팀이 대상 서버에 잔여
        # 아티팩트가 남아있지 않은지 수동으로 정리할 때 참고 목록으로 쓰인다.
        self.attempted_uploads: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # 내부 유틸
    # ------------------------------------------------------------------ #

    def _post_file(self, filename: str, content: bytes, content_type: str):
        """업로드 요청을 보낸다. 일시적 네트워크 오류에 한해 최대 self.max_retries회
        재시도하며, 성공/실패와 무관하게 시도 이력을 self.attempted_uploads에 남긴다.
        WAF/레이트리밋 회피를 위해 요청 사이에 self.request_delay만큼 대기한다."""
        if self.request_delay > 0:
            time.sleep(self.request_delay)

        last_err = None
        resp = None
        for attempt in range(self.max_retries + 1):
            files = {self.upload_field: (filename, io.BytesIO(content), content_type)}
            try:
                resp = self.session.post(
                    self.target_url,
                    files=files,
                    data=self.extra_form_fields,
                    headers=self.headers,
                    cookies=self.cookies,
                    verify=self.verify_ssl,
                    timeout=self.timeout,
                )
                last_err = None
                break
            except requests.RequestException as e:
                last_err = str(e)
                if attempt < self.max_retries:
                    time.sleep(1)
                continue

        storage_url = self._extract_storage_url(resp, filename) if resp is not None else None
        attempt_record = {
            "filename": filename,
            "http_status": resp.status_code if resp is not None else None,
            "looks_successful": self._classify_response(resp) == "success" if resp is not None else False,
            "resolved_storage_url": self._resolve_uploaded_url(filename, storage_url),
            "cleanup_attempted": False,
            "cleanup_result": None,
            "attempted_at": datetime.now().isoformat(),
        }

        if attempt_record["looks_successful"] and self.cleanup and attempt_record["resolved_storage_url"]:
            attempt_record["cleanup_attempted"] = True
            try:
                del_resp = self.session.delete(
                    attempt_record["resolved_storage_url"], headers=self.headers,
                    cookies=self.cookies, verify=self.verify_ssl, timeout=self.timeout,
                )
                attempt_record["cleanup_result"] = f"HTTP {del_resp.status_code}"
            except requests.RequestException as e:
                attempt_record["cleanup_result"] = f"실패: {e}"

        self.attempted_uploads.append(attempt_record)

        if last_err:
            return None, last_err
        return resp, None

    # 상태코드 계열+Content-Type이 같아도 이 유사도 미만이면 "본문이 확연히 다르다"고
    # 보고 차단으로, 이 유사도 이상이면 "베이스라인과 사실상 같은 내용"이라고 보고
    # 성공으로 판정한다. 그 사이는 애매(ambiguous)로 남겨 과단정을 피한다.
    BODY_SIMILARITY_SUCCESS_THRESHOLD = 0.6
    BODY_SIMILARITY_BLOCKED_THRESHOLD = 0.3

    @staticmethod
    def _json_top_level_keys(resp: requests.Response) -> Optional[frozenset]:
        try:
            data = resp.json()
        except (ValueError, requests.exceptions.JSONDecodeError):
            return None
        if isinstance(data, dict):
            return frozenset(data.keys())
        return None

    def _classify_response(self, resp: Optional[requests.Response]) -> str:
        """resp를 "success" / "blocked" / "auth_or_waf_blocked" / "ambiguous" 중 하나로
        분류한다.

        v0.5: 상태코드 계열/Content-Type만으로는 "200+정상 페이지"와 "200+차단
        안내 페이지"를 구분 못 하는 앱이 실무에 많아, 이제 응답 '본문'까지 반드시
        확인한다.
        - 본문에 BLOCKED_KEYWORDS가 있으면 상태코드/CT가 베이스라인과 같아도 차단으로 본다.
        - JSON 응답이면 최상위 키 집합을 베이스라인과 비교한다(같으면 성공 쪽 신호,
          다르면 실패 쪽 신호).
        - 그 외(HTML/텍스트)에는 베이스라인 본문과의 difflib 유사도를 사용한다.
        판정 근거는 self._last_classification_detail에 사람이 읽을 문장으로 남겨,
        호출부가 evidence에 그대로 실어 투명성을 확보할 수 있게 한다."""
        if resp is None:
            self._last_classification_detail = "응답 없음"
            return "ambiguous"

        if resp.status_code in self.AUTH_OR_WAF_STATUS_CODES:
            self._waf_suspected = True
            self._last_classification_detail = f"HTTP {resp.status_code} (인증/CSRF/WAF/레이트리밋 의심 상태코드)"
            return "auth_or_waf_blocked"

        body_lower = resp.text.lower() if resp.text else ""
        has_blocked_kw = any(k in body_lower for k in self.BLOCKED_KEYWORDS)

        if self.baseline is None:
            # 베이스라인 학습 실패 시의 폴백: 기존 키워드 휴리스틱
            if 200 <= resp.status_code < 400 and not has_blocked_kw:
                self._last_classification_detail = (
                    f"HTTP {resp.status_code}, 베이스라인 없음 → 키워드 휴리스틱만으로 성공 추정"
                )
                return "success"
            self._last_classification_detail = (
                f"HTTP {resp.status_code}, 베이스라인 없음, "
                + ("차단 키워드 발견" if has_blocked_kw else "2xx/3xx 아님")
            )
            return "blocked"

        baseline_family = self.baseline["status_family"]
        this_family = resp.status_code // 100
        baseline_ctype = self.baseline["content_type"]
        this_ctype = resp.headers.get("Content-Type", "").split(";")[0].strip()
        family_and_ctype_match = this_family == baseline_family and (not baseline_ctype or this_ctype == baseline_ctype)

        if not family_and_ctype_match:
            self._last_classification_detail = (
                f"HTTP {resp.status_code} ({this_ctype or 'CT 없음'}) — 베이스라인(HTTP "
                f"{self.baseline['status_code']}, {baseline_ctype or 'CT 없음'})과 상태코드 계열/타입 자체가 달라 차단으로 판단"
            )
            return "blocked"

        if has_blocked_kw:
            self._last_classification_detail = (
                f"HTTP {resp.status_code}로 베이스라인과 상태코드/타입은 같지만, 본문에 차단 관련 키워드가 "
                f"포함되어 있어 차단으로 판단"
            )
            return "blocked"

        # 상태코드/타입이 같고 차단 키워드도 없음 → 본문 내용 자체를 비교
        baseline_keys = self.baseline.get("json_keys")
        if baseline_keys is not None:
            this_keys = self._json_top_level_keys(resp)
            if this_keys is None:
                self._last_classification_detail = (
                    "베이스라인은 JSON 응답이었으나 이번 응답은 JSON으로 파싱되지 않아 애매함"
                )
                return "ambiguous"
            if this_keys == baseline_keys:
                self._last_classification_detail = (
                    f"JSON 최상위 키 집합이 베이스라인과 동일함({sorted(this_keys)}) → 성공으로 판단"
                )
                return "success"
            shared = this_keys & baseline_keys
            union = this_keys | baseline_keys
            key_overlap = len(shared) / len(union) if union else 1.0
            if key_overlap < 0.5:
                self._last_classification_detail = (
                    f"JSON 최상위 키 집합이 베이스라인과 크게 다름(베이스라인: {sorted(baseline_keys)}, "
                    f"이번 응답: {sorted(this_keys)}) → 차단/다른 처리 경로로 판단"
                )
                return "blocked"
            self._last_classification_detail = (
                f"JSON 키 집합이 베이스라인과 부분적으로만 겹침(겹침 비율 {key_overlap:.2f}) → 자동 판정 신뢰도 낮음"
            )
            return "ambiguous"

        baseline_body = self.baseline.get("body_text") or ""
        this_body = resp.text or ""
        similarity = difflib.SequenceMatcher(None, baseline_body[:5000], this_body[:5000]).ratio()

        if similarity >= self.BODY_SIMILARITY_SUCCESS_THRESHOLD:
            self._last_classification_detail = (
                f"본문이 베이스라인과 유사함(유사도 {similarity:.2f} ≥ {self.BODY_SIMILARITY_SUCCESS_THRESHOLD}) "
                f"→ 성공으로 판단"
            )
            return "success"
        if similarity <= self.BODY_SIMILARITY_BLOCKED_THRESHOLD:
            self._last_classification_detail = (
                f"본문이 베이스라인과 확연히 다름(유사도 {similarity:.2f} ≤ {self.BODY_SIMILARITY_BLOCKED_THRESHOLD}) "
                f"→ 차단(다른 안내 페이지 등)으로 판단"
            )
            return "blocked"
        self._last_classification_detail = (
            f"본문 유사도가 애매한 구간임(유사도 {similarity:.2f}, 성공 기준 {self.BODY_SIMILARITY_SUCCESS_THRESHOLD} / "
            f"차단 기준 {self.BODY_SIMILARITY_BLOCKED_THRESHOLD}) → 자동 판정 신뢰도 낮음"
        )
        return "ambiguous"

    def _extract_storage_url(self, resp: Optional[requests.Response], filename: str) -> Optional[str]:
        """업로드 성공 응답(JSON 또는 텍스트)에서 저장 경로/URL을 최대한 추출한다.
        uploaded_file_base_url을 몰라도 실행/접근 검증을 시도할 수 있게 하기 위함."""
        if resp is None:
            return None

        # 1) Location 헤더 (201 Created + Location, 또는 리다이렉트)
        loc = resp.headers.get("Location")
        if loc:
            return loc

        # 2) JSON 응답 바디에서 흔히 쓰이는 키 탐색
        candidate_keys = ("url", "file_url", "fileurl", "path", "file_path", "filepath",
                          "location", "src", "link", "download_url", "downloadurl")
        try:
            data = resp.json()
            found = self._find_key_recursive(data, candidate_keys)
            if found:
                return found
        except (ValueError, requests.exceptions.JSONDecodeError):
            pass

        # 3) 일반 텍스트/HTML 응답에서 파일명을 포함한 경로 패턴 탐색
        try:
            m = re.search(
                r'["\'](?P<url>(?:https?://[^"\']+)?/[^"\'<>\s]*' + re.escape(filename) + r')["\']',
                resp.text,
            )
            if m:
                return m.group("url")
        except Exception:
            pass

        return None

    @staticmethod
    def _find_key_recursive(data: Any, keys: Tuple[str, ...], depth: int = 0) -> Optional[str]:
        """dict/list 구조를 얕게(최대 4단계) 순회하며 candidate_keys 중 하나와
        대소문자 무시하고 일치하는 첫 문자열 값을 찾는다."""
        if depth > 4:
            return None
        lower_keys = {k.lower() for k in keys}
        if isinstance(data, dict):
            for k, v in data.items():
                if isinstance(k, str) and k.lower() in lower_keys and isinstance(v, str) and v:
                    return v
            for v in data.values():
                found = FileUploadVulnScanner._find_key_recursive(v, keys, depth + 1)
                if found:
                    return found
        elif isinstance(data, list):
            for item in data:
                found = FileUploadVulnScanner._find_key_recursive(item, keys, depth + 1)
                if found:
                    return found
        return None

    def _resolve_uploaded_url(self, filename: str, extracted_url: Optional[str]) -> Optional[str]:
        """추출된 저장 경로(상대/절대)를 대상 URL 기준 절대 URL로 변환하거나,
        추출에 실패했을 경우 uploaded_file_base_url + filename으로 폴백한다."""
        if extracted_url:
            return urljoin(self.target_url, extracted_url)
        if self.uploaded_file_base_url:
            return self.uploaded_file_base_url.rstrip("/") + "/" + filename
        return None

    def _try_access_uploaded_file(
        self, filename: str, resp: Optional[requests.Response] = None
    ) -> Optional[requests.Response]:
        """filename에 해당하는 업로드된 파일에 실제로 접근을 시도한다.
        resp가 주어지면 그 응답에서 저장 경로를 추출해 우선 사용하고,
        실패하면 uploaded_file_base_url + filename으로 폴백한다."""
        extracted = self._extract_storage_url(resp, filename) if resp is not None else None
        url = self._resolve_uploaded_url(filename, extracted)
        if not url:
            return None
        try:
            return self.session.get(url, timeout=self.timeout, verify=self.verify_ssl,
                                     headers=self.headers, cookies=self.cookies)
        except requests.RequestException:
            return None

    def _establish_baseline(self) -> None:
        """정상적인 이미지 파일을 실제로 업로드해, 이 엔드포인트에서 '성공'이
        어떤 모양(상태코드 계열, Content-Type, 응답 본문)으로 응답되는지 학습한다.
        이후 모든 판정은 이 베이스라인과의 비교를 우선으로 한다.

        v0.5: 상태코드/Content-Type만으로는 "정상 처리"와 "동일한 상태코드로
        차단 안내"를 구분 못 하는 앱이 많아, 본문(JSON이면 최상위 키 집합, 아니면
        텍스트 원문)까지 함께 저장해 _classify_response에서 비교 기준으로 쓴다."""
        filename = f"diag_baseline_{uuid.uuid4().hex[:8]}.png"
        resp, err = self._post_file(filename, self.BASELINE_PNG, "image/png")
        if err or resp is None:
            self.baseline = None
            return
        self.baseline = {
            "status_code": resp.status_code,
            "status_family": resp.status_code // 100,
            "content_type": resp.headers.get("Content-Type", "").split(";")[0].strip(),
            "filename": filename,
            "json_keys": self._json_top_level_keys(resp),
            "body_text": resp.text[:5000] if resp.text else "",
        }

    def _detect_server_header(self) -> str:
        """대상 서버의 Server 헤더를 1회만 조회해 캐싱 (N/A 판정에 사용)"""
        if self._server_header_checked:
            return self._server_header or ""
        self._server_header_checked = True
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout, verify=self.verify_ssl,
                                     headers=self.headers)
            self._server_header = resp.headers.get("Server", "")
        except requests.RequestException:
            self._server_header = ""
        return self._server_header

    def _add(self, result: DiagnosisResult):
        self.results.append(result)

    def _build(self, vuln, status, risk, evidence, reason, recommendation,
               confidence: str = "확정", payload: str = "") -> DiagnosisResult:
        result = DiagnosisResult(
            vulnerability=vuln, status=status, risk=risk,
            evidence=evidence, reason=reason, recommendation=recommendation,
            # 이 스캐너가 실제로 테스트를 실어보낸 멀티파트 폼 필드명 (예: 'file').
            # "테스트가 들어간 입력 파라미터명"에 해당.
            parameter=self.upload_field,
            payload=payload,
            confidence=confidence,
        )
        self._add(result)
        return result

    def _build_from_classification(
        self, vuln: str, resp: Optional[requests.Response], err: Optional[str], *,
        on_success, blocked_recommendation: str = "현재 방어 유지", payload: str = "",
    ) -> DiagnosisResult:
        """공통 판정 골격: 네트워크 오류 → N/A, 인증/WAF 차단 → N/A(수동확인),
        베이스라인과 다르게 처리(차단) → 양호, 애매함 → N/A, 성공 → on_success(resp) 호출.
        on_success는 이 경우에 맞는 최종 DiagnosisResult를 만들어 반환해야 한다.
        payload: 이번 시도에 실제로 사용한 입력값(보통 파일명)을 넘기면 blocked/ambiguous/
        auth_or_waf_blocked/네트워크 오류 분기에서도 결과에 함께 남는다."""
        if err:
            return self._build(vuln, "N/A", "중간", f"요청 실패: {err}",
                                "네트워크 오류로 판단 불가", "재진단 필요", payload=payload)

        classification = self._classify_response(resp)
        classify_detail = self._last_classification_detail

        if classification == "auth_or_waf_blocked":
            return self._build(
                vuln, "N/A", "중간",
                evidence=f"HTTP {resp.status_code} 응답 ({classify_detail})",
                reason="파일 업로드 필터가 아니라 인증/CSRF 검증 또는 WAF/레이트리밋에 의해 "
                       "차단되었을 가능성이 있어, 이 결과만으로 '양호'라고 단정할 수 없음",
                recommendation="유효한 인증 세션·CSRF 토큰으로 재진단(--header/--cookie/--extra-field)하거나, "
                                "수동으로 요청을 재현해 실제 차단 주체(업로드 필터 vs 인증/WAF)를 확인할 것",
                payload=payload,
            )

        if classification == "ambiguous":
            snippet = resp.text[:150].replace("\n", " ") if resp.text else ""
            return self._build(
                vuln, "N/A", "낮음",
                evidence=f"HTTP {resp.status_code}. {classify_detail}"
                          + (f" (응답 일부: {snippet!r})" if snippet else ""),
                reason="정상 업로드 시의 베이스라인 응답과 비교했을 때 성공/차단을 자동으로 명확히 구분하기 어려움",
                recommendation="이 항목은 응답 원문을 직접 열어 수동으로 판정할 것",
                payload=payload,
            )

        if classification == "blocked":
            snippet = resp.text[:150].replace("\n", " ") if resp.text else ""
            snippet_suffix = f" (응답 일부: {snippet!r})" if snippet else ""
            evidence = f"HTTP {resp.status_code}. {classify_detail}" + snippet_suffix
            reason = ("정상 파일 업로드 시의 베이스라인 응답(상태코드/Content-Type/본문 내용)과 비교했을 때 "
                      "이 요청은 다르게(차단되는 형태로) 처리됨")
            return self._build(vuln, "양호", "낮음", evidence, reason, blocked_recommendation, payload=payload)

        return on_success(resp)

    # ------------------------------------------------------------------ #
    # 개별 진단 항목 (블랙박스)
    # ------------------------------------------------------------------ #

    def _verify_php_execution(self, filename: str, resp: requests.Response,
                               a: int, b: int, expected: int) -> Dict[str, str]:
        """업로드된 PHP 페이로드가 '저장만 됨'인지 '실제로 실행됨'인지 구분한다.
        핵심: 페이로드가 소스에 없는 계산값(a*b)을 만들게 하고, 응답에 그 계산
        결과값은 있으면서 동시에 PHP 소스 원문(<?php, 'a*b' 표현식)은 없을 때만
        '실행됨'으로 판정한다. 파일이 실행되지 않고 텍스트로 그대로 서빙되면
        소스 원문 자체에 이미 그 문자열들이 들어있으므로 이렇게 구분해야 오탐이 없다."""
        access_resp = self._try_access_uploaded_file(filename, resp)
        if access_resp is None:
            return {"state": "no_access",
                    "detail": "저장 위치를 특정할 수 없어 접근 검증 불가 "
                              "(--uploaded-base-url 미지정 또는 응답에서 경로 추출 실패)"}

        body = access_resp.text
        raw_source_present = ("<?php" in body) or (f"{a}*{b}" in body) or (f"{a} * {b}" in body)

        if str(expected) in body and not raw_source_present:
            return {"state": "executed",
                    "detail": f"응답에 연산 결과값 '{expected}'가 포함되어 있고 PHP 소스 원문은 없음 "
                              f"(요청 URL: {access_resp.url})"}
        if raw_source_present:
            return {"state": "stored_not_executed",
                    "detail": f"응답에 PHP 소스 원문이 그대로 노출됨 → 이번 진단에서는 실행되지 않고 "
                              f"정적 텍스트로 서빙되는 것으로 확인됨 (요청 URL: {access_resp.url})"}
        return {"state": "unknown",
                "detail": f"응답(HTTP {access_resp.status_code})에서 실행 여부·원문 여부를 판별할 근거를 "
                          f"찾지 못함 (요청 URL: {access_resp.url})"}

    # ------------------------------------------------------------------ #
    # 개별 진단 항목 (블랙박스)
    # ------------------------------------------------------------------ #

    def check_dangerous_extension_allowed(self) -> DiagnosisResult:
        """위험 확장자 업로드 허용 여부를, 여러 필터 우회 변종(대소문자 혼용,
        trailing dot/space, phtml 등)을 순서대로 시도해 확인한다. 필터가 일부
        변종만 막고 있으면 단일 시도로는 놓칠 수 있기 때문."""
        vuln = "위험 확장자 업로드 허용 (Unrestricted File Type)"
        a, b = random.randint(1000, 9999), random.randint(1000, 9999)
        expected = a * b
        payload = f"<?php echo {a}*{b}; ?>".encode()

        variants = [
            (f"diag_{uuid.uuid4().hex[:8]}.php", "기본"),
            (f"diag_{uuid.uuid4().hex[:8]}.pHp", "대소문자 혼용"),
            (f"diag_{uuid.uuid4().hex[:8]}.php.", "끝에 점(trailing dot)"),
            (f"diag_{uuid.uuid4().hex[:8]}.php ", "끝에 공백(trailing space)"),
            (f"diag_{uuid.uuid4().hex[:8]}.phtml", "phtml 확장자"),
        ]

        tried_log = []
        for filename, label in variants:
            resp, err = self._post_file(filename, payload, "application/x-php")
            if err:
                tried_log.append(f"{label}: 요청 실패({err})")
                continue

            classification = self._classify_response(resp)
            tried_log.append(f"{label}({filename}): HTTP {resp.status_code} → {classification}")

            if classification == "auth_or_waf_blocked":
                return self._build(
                    vuln, "N/A", "중간",
                    evidence=f"'{label}' 변종 시도 중 HTTP {resp.status_code} 발생. 시도 로그: {tried_log}",
                    reason="업로드 필터가 아니라 인증/CSRF/WAF/레이트리밋에 막혔을 가능성이 있어 판정 보류",
                    recommendation="유효한 인증 세션·CSRF 토큰으로 재진단할 것",
                    payload=filename,
                )

            if classification == "success":
                exec_info = self._verify_php_execution(filename, resp, a, b, expected)
                if exec_info["state"] == "executed":
                    return self._build(
                        vuln, "취약", "높음",
                        evidence=f"'{label}' 변종({filename})으로 업로드 성공, 실행까지 확인됨. "
                                 f"{exec_info['detail']}. 시도 로그: {tried_log}",
                        reason="위험 확장자 파일이 업로드되었고, 실제 코드 실행(RCE)까지 연산 결과값으로 검증됨 "
                               "(소스 원문 에코와 구분)",
                        recommendation="업로드 파일 확장자에 화이트리스트만 적용하고, 웹에서 직접 접근 가능한 "
                                        "경로에는 스크립트 실행 권한을 제거할 것. 대소문자/trailing 문자 변형도 "
                                        "빠짐없이 차단되는지 함께 확인할 것",
                        confidence="확정",
                        payload=filename,
                    )
                exec_confidence = "확정" if exec_info["state"] == "stored_not_executed" else "추정"
                return self._build(
                    vuln, "취약", "중간",
                    evidence=f"'{label}' 변종({filename})으로 업로드는 성공함. {exec_info['detail']}. "
                             f"시도 로그: {tried_log}",
                    reason="위험 확장자에 대한 필터링이 최소 하나의 변종에서 우회됨 (실행 여부는 evidence 참고)",
                    recommendation="확장자 검사를 대소문자/trailing 공백·점까지 정규화한 뒤 비교하도록 강화할 것",
                    confidence=exec_confidence,
                    payload=filename,
                )

        return self._build(
            vuln, "양호", "낮음",
            evidence=f"시도한 모든 위험 확장자 변종이 차단됨. 시도 로그: {tried_log}",
            reason="대소문자 혼용, trailing dot/space, phtml 등 흔한 우회 변종 모두 베이스라인과 다르게 "
                   "처리되어 차단으로 판단",
            recommendation="현재 방어 로직 유지, 정기적인 신규 우회 기법 재검증 권장",
            payload="; ".join(fn for fn, _ in variants),
        )

    def check_double_extension_bypass(self) -> DiagnosisResult:
        vuln = "이중 확장자 우회 (Double Extension Bypass)"
        a, b = random.randint(1000, 9999), random.randint(1000, 9999)
        expected = a * b
        payload = f"<?php echo {a}*{b}; ?>".encode()
        filename = f"diag_{uuid.uuid4().hex[:8]}.jpg.php"

        resp, err = self._post_file(filename, payload, "image/jpeg")

        def on_success(resp):
            exec_info = self._verify_php_execution(filename, resp, a, b, expected)
            risk = "높음" if exec_info["state"] == "executed" else "중간"
            confidence = "확정" if exec_info["state"] in ("executed", "stored_not_executed") else "추정"
            return self._build(
                vuln, "취약", risk,
                evidence=f"'{filename}' 형태의 이중 확장자 파일이 업로드됨 (HTTP {resp.status_code}). "
                         f"{exec_info['detail']}",
                reason="서버가 마지막 확장자(.php) 기준이 아닌 첫 확장자만 검사하거나 확장자 목록 전체를 "
                       "검사하지 않는 것으로 확인됨",
                recommendation="확장자 검증 시 파일명 전체를 정규식으로 검사하고, 마지막 '.' 이후 문자열만이 "
                                "아닌 전체 확장자 패턴을 확인할 것",
                confidence=confidence,
                payload=filename,
            )

        return self._build_from_classification(vuln, resp, err, on_success=on_success, payload=filename)

    def check_null_byte_injection(self) -> DiagnosisResult:
        vuln = "널 바이트 인젝션 (Null Byte Injection)"
        a, b = random.randint(1000, 9999), random.randint(1000, 9999)
        expected = a * b
        payload = f"<?php echo {a}*{b}; ?>".encode()
        filename = f"diag_{uuid.uuid4().hex[:8]}.php\x00.jpg"

        resp, err = self._post_file(filename, payload, "image/jpeg")

        def on_success(resp):
            exec_info = self._verify_php_execution(filename, resp, a, b, expected)
            risk = "높음" if exec_info["state"] == "executed" else "중간"
            confidence = "확정" if exec_info["state"] in ("executed", "stored_not_executed") else "추정"
            return self._build(
                vuln, "취약", risk,
                evidence=f"널 바이트가 포함된 파일명이 그대로 처리됨 (HTTP {resp.status_code}). {exec_info['detail']}",
                reason="서버가 파일명 문자열 처리 시 널 문자 이후를 잘라내는 구형 동작을 보임",
                recommendation="최신 언어 런타임 사용 및 파일명에서 제어 문자를 명시적으로 제거/검증할 것",
                confidence=confidence,
                payload=filename,
            )

        return self._build_from_classification(vuln, resp, err, on_success=on_success, payload=filename)

    def check_content_type_spoofing(self) -> DiagnosisResult:
        vuln = "Content-Type 검증 미흡 (MIME Type Spoofing)"
        a, b = random.randint(1000, 9999), random.randint(1000, 9999)
        expected = a * b
        payload = f"<?php echo {a}*{b}; ?>".encode()
        filename = f"diag_{uuid.uuid4().hex[:8]}.php"

        resp, err = self._post_file(filename, payload, "image/jpeg")

        def on_success(resp):
            exec_info = self._verify_php_execution(filename, resp, a, b, expected)
            risk = "높음" if exec_info["state"] == "executed" else "중간"
            confidence = "확정" if exec_info["state"] in ("executed", "stored_not_executed") else "추정"
            return self._build(
                vuln, "취약", risk,
                evidence=f"확장자는 .php이나 Content-Type을 image/jpeg로 위장하자 업로드 성공 "
                         f"(HTTP {resp.status_code}). {exec_info['detail']}",
                reason="서버가 클라이언트가 보낸 Content-Type 헤더만 신뢰하고 실제 파일 시그니처(매직 바이트)는 "
                       "검증하지 않는 것으로 판단됨",
                recommendation="Content-Type 헤더는 클라이언트가 조작 가능하므로 신뢰하지 말고, 파일 시그니처"
                                "(magic byte) 또는 서버 측 MIME 재검사를 수행할 것",
                confidence=confidence,
                payload=filename,
            )

        return self._build_from_classification(vuln, resp, err, on_success=on_success, payload=filename)

    def check_magic_byte_bypass(self) -> DiagnosisResult:
        vuln = "파일 시그니처(매직 바이트) 검증 우회"
        a, b = random.randint(1000, 9999), random.randint(1000, 9999)
        expected = a * b
        payload = f"GIF89a;\n<?php echo {a}*{b}; ?>".encode()
        filename = f"diag_{uuid.uuid4().hex[:8]}.php"

        resp, err = self._post_file(filename, payload, "image/gif")

        def on_success(resp):
            exec_info = self._verify_php_execution(filename, resp, a, b, expected)
            risk = "높음" if exec_info["state"] == "executed" else "중간"
            confidence = "확정" if exec_info["state"] in ("executed", "stored_not_executed") else "추정"
            return self._build(
                vuln, "취약", risk,
                evidence=f"GIF 매직 바이트(GIF89a)로 위장된 PHP 코드가 업로드됨 (HTTP {resp.status_code}). "
                         f"{exec_info['detail']}",
                reason="파일 헤더(매직 바이트)를 이미지로 위장했음에도 업로드가 허용되어, 시그니처 기반 검증이 "
                       "없거나 우회 가능한 것으로 판단",
                recommendation="파일 시그니처 검증과 더불어 업로드 디렉터리에 스크립트 실행 권한을 제거하고, "
                                "가능하면 이미지 재인코딩(리사이즈/재저장)으로 페이로드를 무력화할 것",
                confidence=confidence,
                payload=filename,
            )

        return self._build_from_classification(vuln, resp, err, on_success=on_success, payload=filename)

    def check_path_traversal_filename(self) -> DiagnosisResult:
        vuln = "파일명 경로 조작 (Path Traversal via Filename)"
        filename = "../../../../tmp/diag_traversal_" + uuid.uuid4().hex[:8] + ".txt"
        payload = b"path traversal diagnostic marker"

        resp, err = self._post_file(filename, payload, "text/plain")

        def on_success(resp):
            return self._build(
                vuln, "취약", "중간",
                evidence=f"'../' 경로 조작 문자열이 포함된 파일명이 그대로 수락됨 (HTTP {resp.status_code})",
                reason="서버가 파일명에서 경로 구분자를 제거/검증하지 않고 요청을 수락함. 다만 블랙박스 진단의 "
                       "한계상 실제로 지정된 디렉터리 밖에 파일이 쓰였는지까지는 검증하지 못했음 (요청 수락 여부만 "
                       "으로 추정한 결과)",
                recommendation="파일명에서 경로 구분자(../, /, \\\\)를 제거하고, 서버에서 파일명을 직접 사용하지 "
                                "말고 UUID 등으로 재생성하여 저장할 것. 서버 측 로그/파일시스템을 직접 확인해 "
                                "실제 경로 이탈 여부를 검증할 것을 권장",
                confidence="추정",
                payload=filename,
            )

        return self._build_from_classification(vuln, resp, err, on_success=on_success, payload=filename)

    def check_svg_stored_xss(self) -> DiagnosisResult:
        vuln = "SVG 업로드를 통한 저장형 XSS"
        marker = uuid.uuid4().hex[:8]
        payload = (
            f'<svg xmlns="http://www.w3.org/2000/svg">'
            f'<script>/* diag_marker_{marker} */alert(1)</script></svg>'
        ).encode()
        filename = f"diag_{marker}.svg"

        resp, err = self._post_file(filename, payload, "image/svg+xml")

        def on_success(resp):
            return self._build(
                vuln, "취약", "중간",
                evidence=f"<script> 태그가 포함된 SVG 파일이 필터링 없이 업로드됨 (HTTP {resp.status_code})",
                reason="SVG는 XML 기반으로 스크립트를 포함할 수 있어, 업로드된 SVG가 브라우저에서 직접 렌더링될 "
                       "경우 저장형 XSS로 이어질 수 있음. 다만 이번 진단에서는 업로드 수락만 확인했고, 브라우저가 "
                       "실제로 이 SVG를 image/svg+xml로 렌더링하며 스크립트를 실행하는지까지는 확인하지 못했음",
                recommendation="SVG 업로드 허용 시 서버 측에서 <script>, on* 이벤트 속성 등을 제거하는 새니타이징을 "
                                "적용하거나, Content-Disposition: attachment로 강제 다운로드 처리할 것. 실제 브라우저 "
                                "렌더링 여부는 수동으로 재현해 확인할 것",
                confidence="추정",
                payload=filename,
            )

        return self._build_from_classification(vuln, resp, err, on_success=on_success, payload=filename)

    def check_svg_xxe(self) -> DiagnosisResult:
        """SVG는 XML 기반이라 스크립트뿐 아니라 외부 엔티티(XXE)를 통한 서버 내
        파일 읽기·SSRF에도 악용될 수 있다. /etc/passwd를 읽어보고, 응답에 그
        내용의 전형적 signature('root:x:0:0')가 그대로 나타나는지로 판정한다.

        중요: 파일이 파싱되지 않고 원문 그대로 서빙되면 엔티티는 확장되지 않은
        채(&xxe_marker; 원문 그대로) 나오는 것이 정상이므로, 이 경우는 '취약'이
        아니라 '수동 확인이 필요한 미확정 상태(N/A)'로 두는 것이 정확하다.
        업로드 수락 여부만으로 XXE 자체를 취약으로 단정하지 않는다."""
        vuln = "SVG 업로드를 통한 XXE (XML External Entity)"
        marker = uuid.uuid4().hex[:8]
        payload = (
            f'<?xml version="1.0" standalone="yes"?>'
            f'<!DOCTYPE svg [<!ENTITY xxe_{marker} SYSTEM "file:///etc/passwd">]>'
            f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe_{marker};</text></svg>'
        ).encode()
        filename = f"diag_xxe_{marker}.svg"

        resp, err = self._post_file(filename, payload, "image/svg+xml")

        def on_success(resp):
            access_resp = self._try_access_uploaded_file(filename, resp)
            if access_resp is not None and "root:x:0:0" in access_resp.text:
                return self._build(
                    vuln, "취약", "높음",
                    evidence=f"업로드된 SVG에 접근한 결과 /etc/passwd의 내용('root:x:0:0...')이 그대로 "
                             f"노출됨 (요청 URL: {access_resp.url})",
                    reason="SVG를 파싱하는 XML 파서가 외부 엔티티(SYSTEM)를 확장 처리하여 서버 로컬 파일을 "
                           "읽어낼 수 있음이 확인됨 (XXE)",
                    recommendation="SVG를 파싱/렌더링하는 라이브러리에서 외부 엔티티 처리(DTD 로딩)를 명시적으로 "
                                    "비활성화할 것 (예: libxml2 사용 시 resolve_entities=False 또는 "
                                    "LIBXML_NOENT 미사용)",
                    confidence="확정",
                    payload=filename,
                )
            return self._build(
                vuln, "N/A", "낮음",
                evidence="XXE 페이로드가 포함된 SVG 파일 업로드 자체는 성공했으나, 접근 응답에서 /etc/passwd "
                         "노출 신호가 확인되지 않음 (엔티티가 확장되지 않고 원문 그대로 서빙되는 것이 오히려 "
                         "정상적인 경우가 많으므로, 이것만으로 '취약' 또는 '양호'로 단정하지 않음)",
                reason="파일이 업로드되었다는 사실만으로는 서버가 이 SVG를 실제로 XML 파서에 통과시켜 "
                       "파싱/렌더링하는지 알 수 없음. XXE는 업로드된 SVG가 실제로 파싱되는 별도 기능(썸네일 생성, "
                       "미리보기 등)이 있을 때만 발현되므로 자동 블랙박스 진단만으로는 확정할 수 없음",
                recommendation="SVG 미리보기/썸네일 생성 등 서버 측에서 SVG를 실제로 파싱하는 기능이 있는지 "
                                "수동으로 확인하고, 있다면 XML 파서의 외부 엔티티 처리를 비활성화할 것",
                confidence="추정",
                payload=filename,
            )

        return self._build_from_classification(vuln, resp, err, on_success=on_success, payload=filename)

    def check_htaccess_upload(self) -> DiagnosisResult:
        """.htaccess 업로드를 통한 Apache 설정 변경 시도. Apache 계열이 아님이
        확인되면 구조적으로 해당 없는 항목이므로 N/A로 판정한다."""
        vuln = ".htaccess 업로드를 통한 서버 설정 변조"
        server_header = self._detect_server_header()

        if server_header and "apache" not in server_header.lower():
            return self._build(
                vuln, "N/A", "낮음",
                evidence=f"대상 서버의 Server 헤더: '{server_header}'",
                reason="Apache 계열 웹서버가 아닌 것으로 확인되어, .htaccess를 통한 설정 변조가 구조적으로 "
                       "적용되지 않음",
                recommendation="해당 없음. 다만 사용 중인 웹서버(Nginx/IIS 등)에 해당하는 별도 설정 파일 업로드 "
                                "취약점 점검을 권장",
            )

        payload = b"AddType application/x-httpd-php .jpg\n"
        filename = ".htaccess"
        resp, err = self._post_file(filename, payload, "text/plain")

        def on_success(resp):
            return self._build(
                vuln, "취약", "높음",
                evidence=f".htaccess 파일이 필터링 없이 업로드됨 (HTTP {resp.status_code}, "
                         f"Server: {server_header or '미확인'})",
                reason="파일명 자체를 차단하는 로직이 없어 업로드를 수락함. 다만 실제로 이 .htaccess 설정이 "
                       "Apache에 의해 로드되어 적용되었는지(AllowOverride 여부 등)까지는 블랙박스로 검증하지 "
                       "못했으므로, 업로드 수락 여부만으로 추정한 결과임",
                recommendation="파일명이 '.'으로 시작하는 숨김/설정 파일 업로드를 명시적으로 차단하고, 업로드 "
                                "디렉터리에서 .htaccess 재정의(AllowOverride None) 적용할 것. 실제 설정 반영 "
                                "여부는 서버에 직접 접근해 확인할 것을 권장",
                confidence="추정",
                payload=filename,
            )

        return self._build_from_classification(vuln, resp, err, on_success=on_success, payload=filename)

    def check_overwrite_same_filename(self) -> DiagnosisResult:
        """같은 파일명으로 서로 다른 내용을 두 번 업로드했을 때, 나중 것이 앞의
        것을 덮어쓰는지 확인한다. 파일명 유일성이 보장되지 않으면 경쟁 상태나
        타 사용자 파일 교체로 이어질 수 있다. 진단용 파일끼리만 다루므로 안전하다."""
        vuln = "동일 파일명 덮어쓰기 허용 (Filename Collision / Overwrite)"
        token = uuid.uuid4().hex[:10]
        filename = f"diag_overwrite_{token}.txt"
        first_marker = f"ORIGINAL_{token}"
        second_marker = f"REPLACED_{token}"

        resp1, err1 = self._post_file(filename, first_marker.encode(), "text/plain")
        if err1:
            return self._build(vuln, "N/A", "낮음", f"첫 업로드 요청 실패: {err1}",
                                "네트워크 오류로 판단 불가", "재진단 필요", payload=filename)
        if self._classify_response(resp1) != "success":
            return self._build(
                vuln, "N/A", "낮음",
                evidence=f"기본 텍스트 파일 업로드 자체가 성공하지 않아(HTTP {resp1.status_code}) "
                         f"덮어쓰기 여부를 시험할 수 없음",
                reason="선행 조건(정상 업로드) 미충족으로 이 항목은 판정 보류",
                recommendation="해당 없음",
                payload=filename,
            )

        resp2, err2 = self._post_file(filename, second_marker.encode(), "text/plain")
        if err2:
            return self._build(vuln, "N/A", "낮음", f"두 번째 업로드 요청 실패: {err2}",
                                "네트워크 오류로 판단 불가", "재진단 필요", payload=filename)

        access_resp = self._try_access_uploaded_file(filename, resp2)
        if access_resp is None:
            return self._build(
                vuln, "N/A", "낮음",
                evidence="두 파일 모두 업로드 요청은 보냈으나 저장 위치를 특정할 수 없어 내용을 비교하지 못함",
                reason="접근 경로를 확인할 수 없어 덮어쓰기 여부를 검증하지 못함",
                recommendation="--uploaded-base-url을 지정하거나 응답의 저장 경로 필드명을 확인해 재진단할 것",
                payload=filename,
            )

        body = access_resp.text
        if second_marker in body and first_marker not in body:
            return self._build(
                vuln, "취약", "중간",
                evidence=f"동일 파일명으로 재업로드하자 이전 내용이 사라지고 새 내용으로 덮어써짐 "
                         f"(요청 URL: {access_resp.url})",
                reason="파일명 유일성이 보장되지 않아, 다른 사용자가 같은 이름으로 파일을 올리면 기존 파일이 "
                       "임의로 교체될 수 있음 (경쟁 상태·설정파일 교체 등으로 악용 가능)",
                recommendation="저장 파일명을 UUID 등으로 항상 고유하게 생성하고, 원본 파일명은 메타데이터로만 "
                                "보관할 것",
                payload=filename,
            )
        if first_marker in body:
            return self._build(
                vuln, "양호", "낮음",
                evidence=f"동일 파일명 재업로드 후에도 원본 내용이 유지됨 (요청 URL: {access_resp.url})",
                reason="파일명이 충돌해도 기존 파일을 덮어쓰지 않는 것으로 확인됨 (내부적으로 고유 이름으로 "
                       "저장되었을 가능성)",
                recommendation="현재 방어 유지",
                payload=filename,
            )
        return self._build(
            vuln, "N/A", "낮음",
            evidence=f"응답 내용에서 두 마커 모두 확인되지 않아(HTTP {access_resp.status_code}) 덮어쓰기 여부를 "
                     f"판별하지 못함",
            reason="자동 판정 근거 불충분",
            recommendation="수동으로 두 업로드 결과를 비교해 확인할 것",
            payload=filename,
        )

    def check_filename_reflection_xss(self) -> DiagnosisResult:
        """파일명 자체에 HTML/스크립트를 넣어, 서버 응답(업로드 결과 페이지,
        파일 목록 등)에 이스케이프 없이 그대로 반영되는지 확인한다. 실행 여부와
        무관하게 '반영되는지'만 보는 것이므로 성공/차단 분류와 별개로 직접 검사한다."""
        vuln = "파일명 반사(reflection) XSS"
        marker = uuid.uuid4().hex[:6]
        xss_filename = f'diag_<script>alert({marker})</script>.txt'
        payload = b"filename reflection diagnostic content"

        resp, err = self._post_file(xss_filename, payload, "text/plain")
        if err:
            return self._build(vuln, "N/A", "낮음", f"요청 실패: {err}", "네트워크 오류로 판단 불가", "재진단 필요",
                                payload=xss_filename)

        raw_marker = f"<script>alert({marker})</script>"
        if raw_marker in resp.text:
            return self._build(
                vuln, "취약", "중간",
                evidence=f"업로드 응답 본문에 파일명이 이스케이프 없이 그대로 포함됨: '{raw_marker}'",
                reason="파일명을 HTML 응답에 출력할 때 이스케이프를 하지 않아, 악의적인 파일명을 통한 "
                       "저장형/반사형 XSS가 가능함",
                recommendation="파일명을 포함한 모든 출력 지점(업로드 결과, 파일 목록, 다운로드 페이지 등)에서 "
                                "반드시 HTML 이스케이프를 적용할 것",
                payload=xss_filename,
            )
        return self._build(
            vuln, "양호", "낮음",
            evidence="업로드 응답 본문에서 파일명이 이스케이프 없이 그대로 반영되는 패턴이 발견되지 않음",
            reason="이번 응답 기준으로는 파일명 반사 XSS 징후가 없음 (다른 화면-파일 목록, 관리자 페이지 등-은 "
                   "별도 확인 필요)",
            recommendation="업로드 응답 이외에 파일명이 노출되는 다른 화면도 함께 점검할 것",
            payload=xss_filename,
        )

    def check_serving_security_headers(self) -> DiagnosisResult:
        """업로드된 파일이 서빙될 때 X-Content-Type-Options / Content-Disposition
        헤더가 적절히 설정되어 있는지 확인한다. 없으면 브라우저의 MIME 스니핑으로
        업로드 파일이 HTML/스크립트로 해석되어 저장형 XSS로 이어질 수 있다."""
        vuln = "업로드 파일 서빙 시 보안 헤더 미적용"
        if self.baseline is None or not self.baseline.get("filename"):
            return self._build(
                vuln, "N/A", "낮음",
                evidence="베이스라인 업로드에 실패해 서빙 응답을 확인할 파일이 없음",
                reason="선행 조건(정상 업로드 성공) 미충족으로 판정 보류",
                recommendation="해당 없음",
            )

        baseline_filename = self.baseline["filename"]
        access_resp = self._try_access_uploaded_file(baseline_filename)
        if access_resp is None:
            return self._build(
                vuln, "N/A", "낮음",
                evidence="베이스라인 파일의 저장 위치를 특정할 수 없어 서빙 헤더를 확인하지 못함",
                reason="접근 경로 미확인으로 판정 보류",
                recommendation="--uploaded-base-url을 지정하거나 응답의 저장 경로 필드명을 확인해 재진단할 것",
                payload=baseline_filename,
            )

        nosniff = access_resp.headers.get("X-Content-Type-Options", "").lower() == "nosniff"
        content_disposition = access_resp.headers.get("Content-Disposition", "")
        has_disposition = bool(content_disposition)

        missing = []
        if not nosniff:
            missing.append("X-Content-Type-Options: nosniff")
        if not has_disposition:
            missing.append("Content-Disposition")

        if missing:
            return self._build(
                vuln, "취약", "중간",
                evidence=f"업로드 파일 서빙 응답(요청 URL: {access_resp.url})에 다음 헤더가 없음: {missing}",
                reason="이 헤더들이 없으면 브라우저가 응답 내용을 추측해 HTML/스크립트로 렌더링할 수 있어, "
                       "업로드 파일이 이미지/텍스트로 위장한 스크립트일 경우 저장형 XSS로 이어질 수 있음",
                recommendation="업로드 파일 서빙 시 X-Content-Type-Options: nosniff를 항상 붙이고, 사용자 "
                                "업로드 파일은 원칙적으로 Content-Disposition: attachment로 강제 다운로드 처리할 것",
                payload=baseline_filename,
            )
        return self._build(
            vuln, "양호", "낮음",
            evidence=f"업로드 파일 서빙 응답에 nosniff와 Content-Disposition이 모두 설정되어 있음 "
                     f"(요청 URL: {access_resp.url})",
            reason="MIME 스니핑 방지 헤더가 적용되어 있는 것으로 확인됨",
            recommendation="현재 방어 유지",
            payload=baseline_filename,
        )

    def check_eicar_av_scan(self) -> DiagnosisResult:
        """업로드 파일에 대한 안티멀웨어 스캔 여부를, 업계 표준 EICAR 테스트
        문자열(실제 악성 기능이 전혀 없는, AV 테스트 전용 공인 문자열)로 확인한다."""
        vuln = "업로드 파일 악성코드(AV) 스캔 미적용"
        eicar = (
            r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        ).encode()
        filename = f"diag_eicar_{uuid.uuid4().hex[:8]}.txt"

        resp, err = self._post_file(filename, eicar, "text/plain")

        def on_success(resp):
            return self._build(
                vuln, "취약", "중간",
                evidence=f"업계 표준 EICAR 테스트 문자열이 필터링 없이 업로드됨 (HTTP {resp.status_code})",
                reason="EICAR은 실제 악성 기능이 없는 공인 테스트 문자열로, 모든 AV 엔진이 탐지하도록 "
                       "표준화되어 있음. 이것이 그대로 통과했다면 업로드 파이프라인에 안티멀웨어 스캔이 "
                       "없거나 비활성화되어 있을 가능성이 높음 (다만 업로드 수락 여부만으로 추정한 것으로, "
                       "AV 스캔이 비동기/후처리로 동작해 이번 응답에는 반영되지 않았을 가능성도 배제할 수 없음)",
                recommendation="업로드 파일에 대해 ClamAV 등 안티멀웨어 스캔을 적용하는 것을 검토할 것",
                confidence="추정",
            )

        return self._build_from_classification(
            vuln, resp, err, on_success=on_success,
            blocked_recommendation="현재 방어 유지 (AV 스캔 또는 시그니처 기반 차단이 동작하는 것으로 보임)",
            payload=filename,
        )

    def check_oversized_file_dos(self) -> DiagnosisResult:
        """대용량 업로드 제한 여부를 작은 크기부터 단계적으로 늘려가며 확인한다
        (한 번에 dos_size_mb 전체를 쏘지 않음). '제한이 없다'는 그 자체로 반드시
        취약점은 아니며(정상적으로 큰 파일을 받는 서비스도 있음) 서비스 정책과
        함께 검토가 필요하다는 점을 reason/recommendation에 명시한다."""
        vuln = "파일 크기 제한 정책 확인 (대용량 업로드)"
        probe_sizes = sorted({1, max(1, self.dos_size_mb // 2 or 1), self.dos_size_mb})

        results_by_size = []
        last_resp = None
        for size_mb in probe_sizes:
            try:
                payload = b"0" * (size_mb * 1024 * 1024)
            except MemoryError:
                results_by_size.append((size_mb, "메모리 부족으로 생성 실패"))
                continue
            filename = f"diag_large_{size_mb}mb_{uuid.uuid4().hex[:6]}.txt"
            start = time.time()
            resp, err = self._post_file(filename, payload, "text/plain")
            elapsed = time.time() - start
            if err:
                results_by_size.append((size_mb, f"요청 실패({err})"))
                continue
            classification = self._classify_response(resp)
            results_by_size.append((size_mb, f"HTTP {resp.status_code} → {classification} ({elapsed:.1f}s)"))
            last_resp = resp
            if classification != "success":
                # 이 크기부터 막힌다면 어느 지점에서 제한이 걸리는지 알 수 있으므로 더 큰 크기는 생략
                break

        largest_succeeded = all(
            "success" in log for _, log in results_by_size
        ) and len(results_by_size) == len(probe_sizes)

        if largest_succeeded:
            return self._build(
                vuln, "취약", "낮음",
                evidence=f"단계적으로 시도한 크기({probe_sizes}MB) 모두 제한 없이 허용됨: {results_by_size}",
                reason="이 진단만으로 반드시 '취약점'이라고 단정할 수는 없음 — 정상적으로 대용량 파일을 받는 "
                       "서비스도 많으므로, 서비스 특성과 정책에 맞는 상한이 있는지 팀에서 별도로 검토할 것",
                recommendation="웹서버(Nginx/Apache) 및 애플리케이션 레벨에서 서비스 정책에 맞는 최대 업로드 "
                                "크기를 명시적으로 설정했는지 확인할 것 (설정 자체가 없다면 개선 필요)",
                confidence="추정",
            )
        return self._build(
            vuln, "양호", "낮음",
            evidence=f"단계적 시도 로그: {results_by_size}",
            reason="일정 크기 이상에서 요청이 거부되어, 크기 제한 정책이 존재하는 것으로 판단",
            recommendation="현재 설정된 제한 값이 서비스 요구사항에 맞는지 주기적으로 재검토할 것",
        )

    # ------------------------------------------------------------------ #

    def run_all(self) -> List[DiagnosisResult]:
        self.results = []
        self._establish_baseline()

        checks = [
            self.check_dangerous_extension_allowed,
            self.check_double_extension_bypass,
            self.check_null_byte_injection,
            self.check_content_type_spoofing,
            self.check_magic_byte_bypass,
            self.check_path_traversal_filename,
            self.check_svg_stored_xss,
            self.check_svg_xxe,
            self.check_htaccess_upload,
            self.check_overwrite_same_filename,
            self.check_filename_reflection_xss,
            self.check_serving_security_headers,
            self.check_eicar_av_scan,
        ]
        if not self.skip_dos:
            checks.append(self.check_oversized_file_dos)

        if self.baseline is None:
            self._build(
                "베이스라인(정상 업로드) 학습",
                "N/A", "중간",
                evidence="정상 이미지 파일 업로드 시도 자체가 실패하거나 응답을 받지 못함",
                reason="이후 모든 판정은 베이스라인 비교 대신 키워드 휴리스틱으로 폴백되어 정확도가 낮아질 수 있음",
                recommendation="대상 URL, 인증 정보(--header/--cookie/--extra-field), --field(폼 필드명)가 "
                                "올바른지 확인할 것",
            )

        for check in checks:
            try:
                check()
            except Exception as e:
                self._build(
                    vulnerability=getattr(check, "__name__", "unknown_check"),
                    status="N/A", risk="중간",
                    evidence=f"진단 중 예외 발생: {e}",
                    reason="스캐너 실행 오류로 판정 불가",
                    recommendation="예외 로그 확인 후 재진단 필요",
                )

        if self._waf_suspected:
            self._build(
                "WAF/레이트리밋 의심",
                "N/A", "낮음",
                evidence="진단 도중 401/403/406/429 응답이 1회 이상 관측됨",
                reason="일부 항목이 업로드 필터가 아니라 인증/CSRF/WAF/레이트리밋에 의해 차단되었을 수 있어, "
                       "해당 항목들의 '양호'/'N/A' 판정은 반드시 수동으로 교차 확인할 것을 권장",
                recommendation="인증 정보를 보강하거나, User-Agent/요청 빈도를 조정해 재진단할 것",
            )

        return self.results

    def analyze_external_file(self, path: str) -> None:
        """HTTP 진단과 별개로, 로컬에 있는 실제 파일(예: 팀에서 확보한 웹셸 샘플,
        업로드 테스트용 파일)을 포맷/이름/콘텐츠 관점에서 분석해 결과에 추가한다."""
        for r in self.format_analyzer.analyze_path(path):
            r.vulnerability = f"[외부 파일: {os.path.basename(path)}] {r.vulnerability}"
            self._add(r)

    def _summary(self) -> Dict[str, Any]:
        """상태별/위험도별/확실성별 집계 요약. 결과가 많아질수록 사람이 전체를 훑기
        어려우므로 리포트 상단에서 바로 파악할 수 있게 한다. confirmed_vulnerabilities는
        '취약'이면서 confidence가 '확정'인 것만 골라, 우선순위를 매길 때 바로 참고하도록
        한다 (요청 수락만으로 추정한 항목과 섞이지 않도록)."""
        by_status: Dict[str, int] = {}
        by_risk: Dict[str, int] = {}
        by_confidence: Dict[str, int] = {}
        confirmed_vulnerabilities = []
        estimated_vulnerabilities = []
        for r in self.results:
            by_status[r.status] = by_status.get(r.status, 0) + 1
            by_risk[r.risk] = by_risk.get(r.risk, 0) + 1
            by_confidence[r.confidence] = by_confidence.get(r.confidence, 0) + 1
            if r.status == "취약":
                if r.confidence == "확정":
                    confirmed_vulnerabilities.append(r.vulnerability)
                else:
                    estimated_vulnerabilities.append(r.vulnerability)
        return {
            "total": len(self.results),
            "by_status": by_status,
            "by_risk": by_risk,
            "by_confidence": by_confidence,
            # 실제 실행/콘텐츠 검증까지 된 취약점 (최우선 조치 대상)
            "confirmed_vulnerabilities": confirmed_vulnerabilities,
            # 요청 수락 여부만으로 추정한 취약점 (수동 확인 후 우선순위 결정 권장)
            "estimated_vulnerabilities": estimated_vulnerabilities,
        }

    def save_json(self, path: str):
        payload = {
            "tool": "file_upload_vuln_scanner",
            "tool_version": TOOL_VERSION,
            "target_url": self.target_url,
            "scanned_at": datetime.now().isoformat(),
            "baseline_established": self.baseline is not None,
            "waf_suspected": self._waf_suspected,
            "summary": self._summary(),
            "results": [r.to_dict() for r in self.results],
            # 대상 서버에 실제로 전송을 시도한 파일 목록. looks_successful=True인
            # 항목은 서버에 잔여 아티팩트로 남아있을 수 있으므로, 진단 종료 후 팀이
            # 이 목록을 참고해 수동으로 정리했는지(또는 cleanup_attempted 결과를)
            # 반드시 확인할 것.
            "attempted_uploads": self.attempted_uploads,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        return path


# --------------------------------------------------------------------------- #
# CodeBERT 기반 서버 측 소스코드 정적 분석 (보조 진단)
# --------------------------------------------------------------------------- #

class InsecureCodeAnalyzer:
    """
    mrm8488/codebert-base-finetuned-detect-insecure-code 모델을 이용해
    업로드 처리 서버 측 소스코드(제공된 경우)에 대한 보조 분석을 수행한다.

    ⚠️ 이 모델의 한계를 정확히 알고 사용할 것 (모델 카드 기준):
    - 학습 데이터가 CodeXGLUE Defect Detection(Devign) — C 언어 함수 단위 결함
      탐지 데이터셋이다. 즉 "파일 업로드 취약점"이나 PHP/Python 업로드 핸들러에
      특화된 모델이 아니라 "C 함수의 일반적 결함" 기준으로 판단하는 모델이므로,
      이 도구가 진단하는 대상(웹 업로드 핸들러)과 도메인이 다르다. 정확도 향상
      효과를 과신하지 말고 어디까지나 참고용 보조 신호로만 사용할 것.
    - max_length=512로 자르기 때문에, 실제 업로드 핸들러 코드가 길면 뒷부분
      (저장 로직 등 핵심 부분일 수 있음)이 잘려서 분석에서 누락될 수 있다.
    - 파일 전체를 이진 분류할 뿐이라 "어느 줄이 왜 문제인지" 근거를 제공하지
      않는다. evidence는 예측 라벨과 확률뿐이므로, 실제 조치를 위해서는 반드시
      사람이 코드를 직접 리뷰해야 한다.
    - 더 실질적인 개선은 이 모델보다는 (a) move_uploaded_file에 사용자 파일명을
      직접 사용하는지, (b) 확장자 화이트리스트 부재, (c) $_FILES['type'] 신뢰
      여부 같은 업로드 특화 규칙을 정규식/AST로 먼저 잡는 쪽이 ROI가 높다.

    라벨 인덱스는 하드코딩하지 않고 model.config.id2label에서 "insecure"/"vulnerable"/
    "1" 등의 키워드를 찾아 동적으로 판별하며, 매핑을 알 수 없을 때만 인덱스 1을
    기본값으로 폴백한다 (모델 카드 기준 0=secure, 1=insecure).
    """

    MODEL_NAME = "mrm8488/codebert-base-finetuned-detect-insecure-code"
    FALLBACK_INSECURE_LABEL_INDEX = 1

    def __init__(self, device: Optional[str] = None):
        self._tokenizer = None
        self._model = None
        self._device = device  # 예: "cuda", "cpu". None이면 CPU 사용
        self._insecure_label_index: Optional[int] = None

    def _load(self):
        if self._model is not None:
            return
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch  # noqa: F401  (로드 가능 여부 확인용)
        except ImportError as e:
            raise RuntimeError(
                "transformers/torch가 설치되어 있지 않습니다. `pip install transformers torch` 로 설치 후 다시 시도하세요."
            ) from e

        self._tokenizer = AutoTokenizer.from_pretrained(self.MODEL_NAME)
        self._model = AutoModelForSequenceClassification.from_pretrained(self.MODEL_NAME)
        if self._device:
            self._model.to(self._device)
        self._model.eval()

        # 라벨 매핑을 하드코딩 대신 모델 config에서 실제로 조회.
        id2label = getattr(self._model.config, "id2label", None) or {}
        insecure_idx = None
        for idx, label in id2label.items():
            if isinstance(label, str) and any(
                kw in label.lower() for kw in ("insecure", "vulnerable", "bad", "1")
            ):
                insecure_idx = int(idx)
                break
        self._insecure_label_index = (
            insecure_idx if insecure_idx is not None else self.FALLBACK_INSECURE_LABEL_INDEX
        )

    def analyze(self, code: str) -> Dict[str, Any]:
        """
        코드 스니펫 하나를 분류해 {"predicted_label": int, "probabilities": [..]} 를 반환한다.
        모델 카드 예시와 동일하게 tokenizer -> model -> logits -> argmax 순서로 처리한다.
        """
        self._load()
        import torch

        inputs = self._tokenizer(
            code, return_tensors="pt", truncation=True,
            padding="max_length", max_length=512,
        )
        if self._device:
            inputs = {k: v.to(self._device) for k, v in inputs.items()}

        with torch.no_grad():
            outputs = self._model(**inputs)
            logits = outputs.logits
            probs = torch.softmax(logits, dim=1).cpu().numpy()[0]
            predicted_label = int(np.argmax(logits.detach().cpu().numpy()))

        return {
            "predicted_label": predicted_label,
            "probabilities": probs.tolist(),
        }

    def analyze_to_diagnosis(self, code: str, context_name: str = "업로드 처리 코드") -> DiagnosisResult:
        vuln = f"CodeBERT 정적 분석(참고용, 도메인 불일치 주의): {context_name}"
        try:
            pred = self.analyze(code)
        except RuntimeError as e:
            return DiagnosisResult(
                vulnerability=vuln, status="N/A", risk="낮음",
                evidence=f"모델 실행 실패: {e}",
                reason="분석 모델을 로드하지 못해 판정 불가",
                recommendation="transformers/torch 설치 및 모델 다운로드 상태 확인",
            )

        predicted_label = pred["predicted_label"]
        score = float(pred["probabilities"][predicted_label])
        is_insecure = predicted_label == self._insecure_label_index

        if is_insecure:
            status, risk = "취약", "중간" if score < 0.85 else "높음"
            reason = (f"CodeBERT insecure-code 분류 모델이 라벨 {predicted_label}(취약, 신뢰도 {score:.2f})로 "
                      f"판정함. 단, 이 모델은 C 함수 결함 탐지용으로 학습되어 업로드 취약점과 도메인이 다르고, "
                      f"512 토큰 이후는 잘려서 분석되지 않았을 수 있으므로 반드시 사람이 직접 코드를 검토할 것")
            recommendation = ("정적 분석 결과는 참고용 보조 지표이므로, 실제 코드 리뷰를 통해 "

                               "입력 검증/파일 저장 경로/실행 권한 관련 로직을 사람이 직접 재확인할 것")
        else:
            status, risk = "양호", "낮음"
            reason = f"CodeBERT 모델이 라벨 {predicted_label}(정상, 신뢰도 {score:.2f})로 특이 패턴을 탐지하지 못함"
            recommendation = "정적 분석상 특이사항 없음. 다만 모델 오탐/미탐 가능성이 있으므로 참고용으로만 사용할 것"

        return DiagnosisResult(
            vulnerability=vuln, status=status, risk=risk,
            evidence=f"모델 출력: predicted_label={predicted_label}, probabilities={[round(p, 4) for p in pred['probabilities']]}",
            reason=reason, recommendation=recommendation,
        )


# --------------------------------------------------------------------------- #
# CLI 진입점
# --------------------------------------------------------------------------- #

def _parse_kv_list(items: Optional[List[str]], sep: str) -> Dict[str, str]:
    """'Key: Value' 또는 'key=value' 형태의 문자열 리스트를 dict로 변환"""
    result: Dict[str, str] = {}
    for item in items or []:
        if sep not in item:
            raise ValueError(f"형식이 잘못됨 (예상 형식: 'Key{sep}Value'): '{item}'")
        key, value = item.split(sep, 1)
        result[key.strip()] = value.strip()
    return result


def main():
    parser = argparse.ArgumentParser(description="파일 업로드 취약점 자동 진단 도구")
    parser.add_argument("--url", default=None, help="파일 업로드 엔드포인트 URL (블랙박스 진단, 선택)")
    parser.add_argument("--field", default="file", help="업로드 폼의 file input name (기본: file)")
    parser.add_argument("--uploaded-base-url", default=None,
                         help="업로드된 파일이 저장되는 경로의 base URL (실행 여부 검증용, 선택)")
    parser.add_argument("--output", default="upload_vuln_report.json", help="결과 JSON 저장 경로")
    parser.add_argument("--source-file", default=None,
                         help="업로드 처리 서버 측 소스코드 파일 경로 (CodeBERT 보조 분석용, 선택)")
    parser.add_argument("--analyze-file", action="append", default=None,
                         help="포맷/파일명/콘텐츠 정적 분석만 수행할 로컬 파일 경로 (여러 번 지정 가능, --url 없이 단독 사용 가능)")
    parser.add_argument("--no-verify-ssl", action="store_true", help="SSL 인증서 검증 비활성화 (자체서명 인증서 랩 환경용)")

    # 실무 환경(인증 필요, 커스텀 헤더 등)에 대응하기 위한 옵션
    parser.add_argument("--header", action="append", default=None, metavar="'Key: Value'",
                         help="요청에 추가할 헤더 (여러 번 지정 가능). 예: --header 'Authorization: Bearer xxx'")
    parser.add_argument("--cookie", action="append", default=None, metavar="key=value",
                         help="요청에 추가할 쿠키 (여러 번 지정 가능). 예: --cookie session=abc123")
    parser.add_argument("--extra-field", action="append", default=None, metavar="key=value",
                         help="업로드 폼에 함께 보낼 추가 필드, 예: CSRF 토큰 (여러 번 지정 가능)")
    parser.add_argument("--timeout", type=int, default=10, help="요청 타임아웃(초), 기본 10")
    parser.add_argument("--max-retries", type=int, default=1, help="네트워크 오류 시 재시도 횟수, 기본 1")
    parser.add_argument("--request-delay", type=float, default=0.3,
                         help="요청 사이 대기 시간(초), 기본 0.3. WAF/레이트리밋 회피 및 대상 서버 부하 완화 목적")
    parser.add_argument("--cleanup", action="store_true",
                         help="업로드 성공으로 판단되고 저장 경로가 파악된 진단용 파일에 대해 best-effort로 "
                              "DELETE 요청을 시도함 (REST 규약을 따르는 서버에서만 동작하며 보장되지 않음)")

    # 대상 서버에 실제로 부하/설정변경을 유발할 수 있는 항목에 대한 안전장치
    parser.add_argument("--dos-size-mb", type=int, default=10,
                         help="파일 크기 제한 테스트에 사용할 최대 업로드 크기(MB), 기본 10. 실제로는 이보다 "
                              "작은 크기부터 단계적으로 시도함")
    parser.add_argument("--run-dos-test", action="store_true",
                         help="대용량 업로드(크기 제한) 테스트를 실행함. 기본값은 미실행(opt-in)이며, "
                              "운영 서버 대상이라면 트래픽/부하 영향을 신중히 검토 후 사용할 것")
    parser.add_argument("--confirm-authorized", action="store_true",
                         help="[--url 사용 시 필수] 이 대상에 대해 진단 권한이 있음을 명시적으로 확인. "
                              "실서비스/운영 환경을 실수로 공격하는 사고를 막기 위한 안전장치")

    args = parser.parse_args()

    if not args.url and not args.analyze_file:
        parser.error("--url 또는 --analyze-file 중 하나는 반드시 지정해야 합니다.")

    if args.url and not args.confirm_authorized:
        parser.error(
            "--url로 대상 서버에 실제 진단 요청을 보내려면 --confirm-authorized 플래그로 "
            "해당 대상에 대한 진단 권한이 있음을 명시적으로 확인해야 합니다. "
            "(자체 구축 랩 환경, 사내 승인된 시스템 등에서만 사용하세요)"
        )

    try:
        headers = _parse_kv_list(args.header, sep=":")
        cookies = _parse_kv_list(args.cookie, sep="=")
        extra_fields = _parse_kv_list(args.extra_field, sep="=")
    except ValueError as e:
        parser.error(str(e))
        return

    if args.url:
        try:
            scanner = FileUploadVulnScanner(
                target_url=args.url,
                upload_field=args.field,
                uploaded_file_base_url=args.uploaded_base_url,
                verify_ssl=not args.no_verify_ssl,
                headers=headers,
                cookies=cookies,
                extra_form_fields=extra_fields,
                timeout=args.timeout,
                max_retries=args.max_retries,
                request_delay=args.request_delay,
                cleanup=args.cleanup,
                dos_size_mb=args.dos_size_mb,
                skip_dos=not args.run_dos_test,
            )
        except ValueError as e:
            parser.error(str(e))
            return
        print(f"[*] 진단 대상: {args.url}")
        scanner.run_all()
    else:
        # --url 없이 파일 분석만 수행하는 경우를 위한 최소 스캐너 인스턴스
        scanner = FileUploadVulnScanner(target_url="(offline)")

    if args.analyze_file:
        for path in args.analyze_file:
            if os.path.isfile(path):
                print(f"[*] 파일 포맷/이름/콘텐츠 정적 분석 수행 중: {path}")
                scanner.analyze_external_file(path)
            else:
                print(f"[!] --analyze-file 경로를 찾을 수 없습니다: {path}")

    if args.source_file:
        if os.path.isfile(args.source_file):
            with open(args.source_file, "r", encoding="utf-8", errors="ignore") as f:
                code = f.read()
            print("[*] CodeBERT 기반 소스코드 보조 분석 수행 중...")
            analyzer = InsecureCodeAnalyzer()
            code_result = analyzer.analyze_to_diagnosis(code, context_name=os.path.basename(args.source_file))
            scanner.results.append(code_result)
        else:
            print(f"[!] --source-file 경로를 찾을 수 없습니다: {args.source_file}")

    for r in scanner.results:
        print(f"- [{r.status}/{r.risk}] {r.vulnerability}")

    out_path = scanner.save_json(args.output)
    print(f"[*] 결과 저장 완료: {out_path}")

    # 대상 서버에 실제로 업로드가 성공한 것으로 보이는 진단용 파일이 있다면
    # 잔여 아티팩트로 남아있을 수 있으므로 반드시 정리 여부를 안내한다.
    leftover = [u for u in scanner.attempted_uploads if u["looks_successful"]]
    if leftover:
        print(f"\n[!] 주의: 대상 서버에 업로드가 성공한 것으로 보이는 진단용 파일이 {len(leftover)}개 있습니다.")
        print("    운영 환경이라면 아래 파일들이 실제로 남아있는지 확인하고 삭제하세요:")
        for u in leftover:
            print(f"      - {u['filename']} (HTTP {u['http_status']})")


if __name__ == "__main__":
    main()
