# CLI와 로컬 웹 UI 설계

## 1. 기본 원칙

CLI가 핵심 제품 인터페이스이다. 로컬 웹 UI는 별도 비즈니스 로직을 가지지 않고 동일한 Application Service를 호출한다.

## 2. CLI 기능 그룹

```text
workbench project ...
workbench vm ...
workbench case ...
workbench collect ...
workbench analyze ...
workbench hypothesis ...
workbench rule ...
workbench validate ...
workbench report ...
workbench publish ...
```

## 3. 예시 사용자 흐름

```text
workbench project init <path>
workbench vm register
workbench case create
workbench case import-bundle
workbench analyze static
workbench analyze normalize
workbench hypothesis create
workbench rule add-yara
workbench rule add-sigma
workbench validate run
workbench report build
workbench publish build
```

실제 명령 이름은 구현 단계에서 조정할 수 있으나, 기능 경계는 유지한다.

## 4. 로컬 웹 UI 화면

### 프로젝트 대시보드
- 정량 목표 달성 현황
- 케이스별 상태
- YARA·Sigma 검증 상태
- 보고서 생성 상태

### 케이스 상세
- 샘플 메타데이터
- 수집 범위
- 프로세스 트리
- 초기 실행 타임라인
- 정적 특징
- IOC
- 근거 이벤트

### 탐지 가설
- 가설 설명
- 연결된 근거
- YARA·Sigma 룰
- 정상 반례
- 한계점
- 사용자 승인

### 검증 결과
- 데이터셋별 TP·FP·FN
- 룰 버전 비교
- 오탐 원인
- 재검증 이력

### 보고서
- Markdown 미리보기
- 독립형 HTML 생성
- 정적 사이트 빌드
- 공개 번들 점검

## 5. UI 구현 순서

1. CLI 완성
2. Application Service 안정화
3. 읽기 전용 웹 화면
4. 룰 편집·승인 화면
5. VM 실행 승인 화면
6. AI 제안 검토 화면
