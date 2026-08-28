## AI 기반 웹 취약점 자동 진단 시스템

웹 애플리케이션의 주요 취약점을 자동으로 진단하고, Streamlit 대시보드를 통해 결과를 확인할 수 있는 프로젝트입니다.

## 주요 기능
SQL Injection 취약점 자동 진단
XSS 취약점 자동 진단
세션/인증 취약점 자동 진단
파일 업로드 취약점 자동 진단
OpenAI 기반 취약점 분석 및 대응방안 제공
수동 진단 결과 업로드 및 자동 진단 결과 비교
PDF / XLSX 진단 보고서 생성

## 실행 환경
Python 3.x
Streamlit
FastAPI
Docker 기반 진단 대상 웹 서비스

## 1. 프로젝트 다운로드

저장소를 Clone하거나 ZIP 파일로 다운로드합니다.

이후 streamlit 디렉터리로 이동합니다.

cd streamlit

## 2. 가상환경 생성 및 활성화

Windows 기준:

python -m venv .venv
.venv\Scripts\activate

## 3. 패키지 설치
pip install -r requirements.txt

## 4. OpenAI API Key 설정

.env.example 파일을 복사하여 .env 파일을 생성합니다.

OPENAI_API_KEY=본인의_API_KEY

.env 파일에는 실제 API Key가 포함되므로 GitHub에 업로드하지 않습니다.

## 5. 진단 대상 웹 서비스 실행

Docker를 이용하여 진단 대상 웹 서비스를 먼저 실행합니다.

예시:

http://localhost:8081

실제 포트 또는 주소가 다른 경우 본인의 실행 환경에 맞는 URL을 사용합니다.

## 6. 통합 Scanner API 실행

첫 번째 터미널에서 다음 명령어를 실행합니다.

uvicorn unified_scanner_api:app --host 0.0.0.0 --port 8001

Scanner API 기본 주소:

http://127.0.0.1:8001

## 7. Streamlit 실행

새로운 터미널을 열고 가상환경을 활성화한 뒤 실행합니다.

streamlit run app.py

실행 후 브라우저에서 Streamlit 대시보드에 접속합니다.

기본 주소:

http://localhost:8501

## 8. 취약점 진단

Streamlit 대시보드에서 진단 대상 URL을 입력합니다.

예시:

http://localhost:8081

진단을 실행하면 각 Scanner의 결과가 통합되어 대시보드에 표시됩니다.

## 프로젝트 구성
streamlit/
├── app.py
├── unified_scanner_api.py
├── sqli_scanner.py
├── session_scanner.py
├── ver4_file_upload_vuln_scanner.py
├── xss_crawler_scanner_improved.py
├── xss_scanner_add_dom.py
├── ai_analyzer.py
├── hf_analyzer.py
├── pdf_report.py
├── xlsx_report.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md

## 주의사항

본 프로젝트의 취약점 진단 기능은 교육 및 허가된 테스트 환경에서의 사용을 목적으로 합니다.

허가받지 않은 시스템을 대상으로 진단을 수행하지 마십시오.
