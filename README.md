# OMT_Third_Project_Scanner
스캐너(port_scanner.py)와 취약점 매퍼(vulnerability_mapper.py)의 산출물을 받아 리포트(HTML)·차트·스크린샷(PNG)·선택적 PDF를 자동으로 생성하는 소비자(consumer) 모듈입니다.
코드(스캐너/매퍼)는 수정하지 않고 산출물 파일만 받아서 동작합니다.

# 1. 요약
입력: data/scan_results_raw.json (포트 스캐너 출력) + data/mapper_final_results.json (취약점 매퍼 출력)
처리: 병합 → 정규화 → HTML 리포트 + Plotly 차트 생성
출력: out/report.html, out/report.png (선택) 및 (옵션) out/report.pdf

# 2. 요구 환경 / 설치 (로컬 개발자용)
Python 3.11

권장 가상환경
python -m venv .venv
- Windows
.\.venv\Scripts\activate
- macOS / Linux
source .venv/bin/activate

pip install --upgrade pip
pip install jinja2 plotly selenium pdfkit
-> (PDF 사용시) 시스템에 wkhtmltopdf 설치 필요

Selenium 스크린샷을 사용하려면 Chrome/Chromium 과 ChromeDriver(버전 일치) 필요

- ChromeDriver를 PATH에 넣거나 webdriver-manager 사용
- Windows: chromedriver.exe를 다운로드해 C:\tools 등 앱 경로에 두고 PATH에 추가

# 3. 필수 파일 위치(주의)
포트 스캐너 산출물 (필수)
data/scan_results_raw.json
- port_scanner.py --out 명령으로 생성된 JSON 파일(또는 팀원에게 받은 동일 포맷)
- 구조 예시 :
{
  "generated": 169xxx,
  "results": [
    {"target":"192.0.2.1","port":80,"state":"open","rtt":0.12,"banner":"nginx/1.20"},
    ...
  ]
}
- 리포트 모듈은 results 배열에서 state=="open"인 항목만 사용합니다.

취약점 매퍼 산출물 (권장)
data/mapper_final_results.json
- vulnerability_mapper.py의 출력(팀에서 stdout을 파일로 리다이렉트하거나 JSON을 저장한 것)
- 구조 예시: 딕셔너리 형태, 키는 "ip:port", 값은 매퍼가 만든 메타데이터 (취약목록, risk_score 등)
{
  "192.0.2.1:80": {
    "service": {"ip":"192.0.2.1","port":80,"service_name":"http","service_version":"1.20"},
    "shodan_info": {...},
    "vulnerabilities":[
      {"cve_id":"CVE-2023-XXXX","cvss_score":9.8,"epss_percentile":12.3,"description":"...","risk_score":9.5}
    ]
  },
  ...
}
- 중요: 파일명 및 경로를 정확히 지켜주세요. (build_report.py에서 기본 경로 사용).

# 4. 사용법 — 실행 순서 (최소한의 절차)
- 1. 레포지토리 루트에서 가상환경 활성화 및 의존성 설치
- 2. data/scan_results_raw.json 과 data/mapper_final_results.json 을 data/ 폴더에 넣기
- 3. 리포트 생성
python build_report.py
- 4. 산출물 확인
out/report.html — 브라우저에서 열어 UI/차트/테이블 확인
out/report.png — 전체 페이지 스크린샷 미리보기(자동생성 실패시 수동으로 브라우저에서 캡처 가능)
(선택) out/report.pdf — export_pdf.py 또는 pdfkit을 이용해 생성

# 5. build_report.py가 하는 일
1. 스캐너 JSON에서 열린 포트(open)만 추출
2. 매퍼 JSON에서 ip:port 키로 취약점 데이터 매칭
3. 호스트 단위로 묶어 표준 스키마로 정규화
4. 요약 통계(호스트 수, 포트 수), 차트(심각도 파이 / 상위 포트 / 상위 CVE) 생성 (Plotly)
5. Jinja2로 HTML 렌더링 (템플릿: reporting/report_template.html)
6. Selenium으로 HTML 전체 스크린샷 저장(옵션)

# 6. 출력 결과 확인 중 문제 발생시
python -m http.server 8000로 out/ 폴더를 서빙 후 브라우저로 접속해도 확인 가능

# 7. 설정 / 환경 변수 / 보안 주의
# - vulnerability_mapper.py가 API를 사용한다면 config.ini에 API 키가 필요합니다. 절대 리포지토리에 API 키를 커밋하지 마세요.
config.ini 예시 (매퍼용 — 리포트 모듈은 키 불필요):
[API]
NVD_API_KEY = <YOUR_NVD_API_KEY>
SHODAN_API_KEY =
GITHUB_API_KEY =
OTX_API_KEY =

[SCORING]
CVSS_WEIGHT = 0.8
EPSS_WEIGHT = 0.5
PUBLIC_EXPLOIT_BONUS = 1.0
THREAT_INTEL_BONUS = 0.5
TEMPORAL_WEIGHT_BONUS = 0.2

[DATABASE]
DB_FILE = data/cache.db

[CACHE]
TTL = 86400

- Selenium 사용시 브라우저 드라이버(ChromeDriver) 버전과 설치 경로 확인 필요.