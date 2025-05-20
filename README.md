# TimeOff Manager

TimeOff Manager는 기업의 휴가 관리 시스템으로, 직원들의 연차와 반차를 효율적으로 관리할 수 있는 웹 애플리케이션입니다.

## 주요 기능

### 직원 관리
- 직원 정보 등록/수정/삭제
- 연차 일수 관리
- 권한 관리 (관리자/일반 사용자)
- 마지막 관리자 계정 보호

### 휴가 관리
- 연차/반차 신청
- 휴가 승인/거절
- 휴가 취소 요청
- 휴가 이력 조회

### 시스템 기능
- 실시간 로깅
- CSRF 보호
- 세션 관리
- 공휴일 자동 계산

## 기술 스택

- **Backend**: Python/Flask
- **Database**: SQLite
- **Frontend**: HTML, CSS, Bootstrap
- **Security**: bcrypt, CSRF Protection
- **Timezone**: pytz (KST)

## 설치 방법

1. 저장소 클론
```bash
git clone https://github.com/yourusername/leave-tracker.git
cd leave-tracker
```

2. 가상환경 생성 및 활성화
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. 의존성 설치
```bash
pip install -r requirements.txt
```

4. 데이터베이스 초기화
```bash
flask db upgrade
```

5. 애플리케이션 실행
```bash
flask run
```

## 프로젝트 구조

```
leave-tracker/
├── app/
│   ├── __init__.py          # 애플리케이션 초기화
│   ├── config.py            # 설정 파일
│   ├── extensions.py        # Flask 확장
│   ├── models/             # 데이터베이스 모델
│   ├── routes/             # 라우트 핸들러
│   ├── utils/              # 유틸리티 함수
│   └── templates/          # HTML 템플릿
├── logs/                   # 로그 파일
└── requirements.txt        # 의존성 목록
```

## 보안 기능

- 비밀번호 해싱 (bcrypt)
- CSRF 토큰 보호
- 세션 관리
- 입력값 검증
- 관리자 계정 보호

## 사용 방법

1. 관리자 계정으로 로그인 (기본 계정: admin/admin)
2. 직원 정보 등록
3. 휴가 신청 및 관리

## 주의사항

- 마지막 관리자 계정은 삭제하거나 권한을 변경할 수 없습니다.
- 연차는 0.5일 단위로 신청 가능합니다.
- 주말과 공휴일에는 연차를 신청할 수 없습니다.

## 라이선스

MIT License

## 기여 방법

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 문의

문제가 발생하거나 기능 개선을 제안하고 싶으시다면 이슈를 생성해주세요.
