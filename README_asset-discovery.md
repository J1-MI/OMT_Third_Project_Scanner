# OMT Third Project Scanner

자동화된 **자산 식별(Asset Discovery) 모듈**로, 네트워크 대상의 서비스 및 버전을 탐지하고 결과를 데이터베이스에 저장합니다.  
`nmap`을 기반으로 하며, Python 스크립트를 통해 스케줄링/파싱/DB마이그레이션 기능을 제공합니다.



## 🚀 주요 기능
- 지정된 대상(Target)에 대해 `nmap` 스캔 수행
- 서비스/버전 정보(-sV) 탐지 및 결과 XML 저장
- 스캔 결과를 SQLite 데이터베이스(`assets.db`)에 기록
- 변경 탐지(Change Detection) 및 자산 식별 로그 관리
- 스케줄러/워커 기반 반복 실행 지원



## 📂 프로젝트 구조
OMT_Third_Project_Scanner/
├── scripts/
│ ├── scan_runner.py # nmap 실행기 (프로파일 기반 실행)
│ ├── quick_scan_demo.py # 빠른 실행 wrapper (테스트용)
│ ├── nmap_parser.py # nmap XML 파싱
│ ├── alerts.py # 알림 처리 모듈
│ └── scheduler.py # 스케줄러 (워크플로 관리)
│
├── migrate_db.py # DB 마이그레이션 실행기
├── migrate_scan_tables.sql # DB 테이블 정의
├── check_tables.py # DB 테이블 상태 확인
├── policy.yaml # 스캔 정책/프로파일 정의
├── requirements.txt # Python 의존성
├── LICENSE
└── README.md

## ⚙️ 설치 방법
1. 가상환경 생성 및 활성화 (Windows PowerShell)
bash
python -m venv venv
.\venv\Scripts\Activate.ps1

3. 의존성 설치
bash
pip install --upgrade pip
pip install -r requirements.txt

🗄️ 데이터베이스 초기화
bash
python migrate_db.py
migrate_scan_tables.sql 파일을 읽어 assets.db 생성

🔍 스캔 실행
1. 데모 사이트 스캔
bash
python .\scripts\quick_scan_demo.py --profile safe_operational --target demo.testfire.net --run

2. 스캔 프로파일 (policy.yaml에서 정의 가능)
safe_operational : 안정적이고 보수적인 스캔
recon_aggressive : 더 많은 서비스와 상세 정보 수집

3. 스캔 결과 확인
XML 파일: nmap_outputs/ 폴더에 저장
DB: assets.db SQLite 파일
