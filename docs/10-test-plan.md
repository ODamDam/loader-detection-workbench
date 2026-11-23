# 테스트 계획

## 1. 테스트 목표

- 핵심 파이프라인이 AI와 VM 자동화 없이도 동작함을 증명한다.
- 실제 악성 샘플 사용 전 시뮬레이터로 안전성과 재현성을 검증한다.
- 룰 검증 결과가 데이터셋과 버전에 따라 재현됨을 확인한다.
- 실패 상황에서도 부분 산출물과 오류 원인이 보존됨을 확인한다.

## 2. 테스트 계층

### 단위 테스트
- 파일 해시
- PE 결과 파싱
- Sysmon 이벤트 파싱
- 정규화 스키마
- 룰 상태 전이
- 지표 계산
- 경로 정규화
- 비식별화 함수

### 통합 테스트
- 프로젝트 생성부터 Case 등록
- Case Bundle 가져오기
- YARA 검사
- Sigma 이벤트 재현
- Markdown·HTML 생성
- SQLite와 파일 무결성
- Publication Bundle 생성

### 시스템 테스트
- VirtualBox 스냅숏 복원 (향후, ADR-018)
- 샘플 전달·해시 재검증
- PowerShell 오케스트레이터
- 타임아웃
- 결과 회수
- VM 복원
- `disabled`·`simulated` 네트워크 모드

### 인수 테스트
- 시뮬레이터 사례 1개 전체 완주
- 실제 악성 사례 1개 전체 완주
- 6개 케이스 정량 목표 충족
- 독립형 HTML과 정적 사이트 열람
- 공개 번들 민감 자료 점검

## 3. 핵심 테스트 시나리오

### 정상 경로
- 유효한 Sysmon 로그
- 유효한 YARA·Sigma
- 악성 탐지, 정상 비탐지
- 보고서 생성 성공

### 오류 경로
- 손상된 XML
- 중복 파일 등록
- YARA 문법 오류
- Sigma 지원하지 않는 필드
- VM 시작 실패
- 로그 회수 실패
- 스냅숏 복원 실패
- AI Provider 오류
- 보고서 템플릿 오류

## 4. 회귀 테스트

- 룰 수정 전후 동일 데이터셋 재검증
- 정규화 스키마 변경 시 기존 케이스 재처리
- 보고서 템플릿 변경 시 6개 케이스 일괄 빌드
- Publication Bundle에 금지 파일이 포함되지 않는지 검사

## 5. 테스트 데이터

- 무해한 시뮬레이터 프로필
- 정상 시뮬레이터 프로필
- 정제된 Sysmon 예제
- 정상 Windows 활동 로그
- 작은 정상 PE 파일 모음
- 공개 가능한 샘플 메타데이터

## 6. Schema v2와 수동 증거 회귀

- 신규 v2 Project 생성과 v1/v2 version-aware validation
- 명시적 v1→v2 migration, 반복 실행, 주입 오류 rollback과 원본 v1 검증
- 정상·중복 등록, 잘못된 Case와 Closed Case 차단
- 수동 전용 확장자와 4 MiB 경계, generic Artifact Store 비회귀
- Artifact/provenance 동일 transaction과 publish 후 DB 실패 보상
- cleanup 실패의 명시적 오류 및 잔여 orphan 보고
- Bundle v1 provenance 제외와 generic Evidence Artifact/content 호환
- 기존 Case·Artifact·Bundle·Sysmon·Timeline·Report의 v1/v2 회귀

## 7. Flask 기본 플랫폼 UI 회귀

- 빈 Project, Case 목록·상세, 없는 Case와 Closed Case 표시
- provenance가 있는 Manual Evidence와 provenance가 없는 Evidence 표시
- 수동 업로드 결과와 기존 Service/CLI 조회 데이터 일치
- 같은 bytes 반복 업로드의 distinct row/canonical content 정책 유지
- v1 Case·Artifact·Timeline 조회와 Evidence migration-required 차단
- 공개 합성 Collection과 Manual Evidence가 같은 Case에 공존하고 Event ID 1/11 표시
- CSRF 누락, 신뢰하지 않는 Host/Origin, XSS payload 거부 또는 escaping
- 4 MiB Service 제한, multipart 요청 제한, invalid extension/metadata
- 성공·실패 후 임시 디렉터리 정리와 evidence bytes/path 비노출
- Timeline command line, image, target path와 ProcessGuid 비노출
- Waitress IPv4 loopback bind, debug 비활성화, invalid Project의 bind 전 실패
- build wheel 안의 Jinja template와 CSS 리소스 포함·로딩
