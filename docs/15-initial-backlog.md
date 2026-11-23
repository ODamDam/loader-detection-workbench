# 초기 개발 백로그

## M0. 저장소 및 개발 부트스트랩

- [x] M0-001 Private GitHub repository 생성
- [x] M0-002 초기 문서 기준선 `main` push
- [x] M0-003 `AGENTS.md`, `PLANS.md`, 개발 워크플로와 ADR 기준선 작성
- [x] M0-004 M0 Python 도구 체인 결정 승인
- [x] M0-005 Python 프로젝트 메타데이터와 `uv.lock` 구성
- [x] M0-006 최소 package와 `workbench` CLI 진입점 구현
- [x] M0-007 선택적 TOML 설정 로딩과 안전한 오류 처리 구현
- [x] M0-008 기본 `INFO` 콘솔 로깅과 `--log-level` 구현
- [x] M0-009 pytest, Ruff, strict mypy 구성과 smoke/error-path 테스트
- [x] M0-010 `.gitignore`, 줄바꿈 정책과 로컬 개발 안내 정리
- [x] M0-011 M0-local 필수 검증 및 자체 리뷰 완료
- [x] M0-012 초기 GitHub Issue 생성
- [x] M0-013 Milestones 및 Project Board 또는 동등한 추적 구조 구성

M0-local의 상세 범위와 Codex 인수인계는 `PLANS.md`와
`docs/18-m0-codex-handoff.md`를 따른다. M0-local 구현은 GitHub Issue #1에서,
M0-remote 작업 관리 기준선은 GitHub Issue #4에서 추적했으며 모두 완료되었다.

## Epic A. 프로젝트·케이스 코어 — M1

- [ ] A-001 프로젝트 생성 CLI
- [ ] A-002 SQLite 초기 스키마
- [ ] A-003 상대 경로·SHA-256 유틸리티
- [ ] A-004 Case 생성·조회·상태 변경
- [ ] A-005 Artifact 등록과 중복 검사
- [ ] A-006 Case Bundle 가져오기·내보내기

M1 구현 전에는 Project/Case/Artifact, ID/status 규칙, SQLite v1,
`project.json`, Case Bundle 및 CLI contract를 확정한다.

## Epic B. 분석 데이터

- [ ] B-001 정적 PE 결과 스키마
- [ ] B-002 PE 기본 메타데이터 수집
- [ ] B-003 Sysmon XML 가져오기
- [ ] B-004 이벤트 정규화 스키마
- [ ] B-005 프로세스 트리 생성
- [ ] B-006 초기 실행 타임라인 생성
- [ ] B-007 Evidence 선택·연결
- [ ] B-008 수집 상태와 미수집 사유 관리

## Epic C. 탐지 가설과 룰

- [ ] C-001 Detection Hypothesis 모델
- [ ] C-002 YARA 룰 등록·버전 관리
- [ ] C-003 YARA 문법 검사
- [ ] C-004 YARA 악성·정상 파일 평가
- [ ] C-005 Sigma 룰 등록·버전 관리
- [ ] C-006 Sigma 문법·구조 검사
- [ ] C-007 Sigma 이벤트 평가기
- [ ] C-008 ValidationRun 저장
- [ ] C-009 TP·FP·FN·지표 계산
- [ ] C-010 룰 승인·반려 흐름

## Epic D. 정상 데이터셋

- [ ] D-001 Dataset 모델
- [ ] D-002 공통 정상 파일 모음 등록
- [ ] D-003 공통 정상 로그 등록
- [ ] D-004 정상 시뮬레이터 프로필
- [ ] D-005 사례별 정상 대응 케이스 연결
- [ ] D-006 데이터셋 버전 관리

## Epic E. 보고서와 공개

- [ ] E-001 Report Model
- [ ] E-002 Markdown 템플릿
- [ ] E-003 독립형 HTML 생성
- [ ] E-004 정적 사이트 인덱스
- [ ] E-005 케이스 페이지
- [ ] E-006 룰·검증 페이지
- [ ] E-007 정제 이벤트·IOC 내보내기
- [ ] E-008 Publication Manifest
- [ ] E-009 공개 금지 파일 검사

## Epic F. 시뮬레이터

- [ ] F-001 실행 파일 골격
- [ ] F-002 내장 프로필 인터페이스
- [ ] F-003 프로세스 생성 프로필
- [ ] F-004 파일 생성·실행 프로필
- [ ] F-005 레지스트리 변경 프로필
- [ ] F-006 모의 네트워크 프로필
- [ ] F-007 정상 모드
- [ ] F-008 결과 매니페스트
- [ ] F-009 JSON 프로필 스키마
- [ ] F-010 JSON 실행 엔진 전환

## Epic G. VirtualBox 자동화 (향후, ADR-018)

- [ ] G-001 VM 등록 설정
- [ ] G-002 준비 상태 검사
- [ ] G-003 Clean Snapshot 복원
- [ ] G-004 VM 시작·종료
- [ ] G-005 Guest Additions 파일 전달
- [ ] G-006 게스트 해시 재검증
- [ ] G-007 PowerShell 오케스트레이터
- [ ] G-008 Sysmon 회수
- [ ] G-009 선택 Procmon·PCAP 회수
- [ ] G-010 타임아웃과 강제 종료
- [ ] G-011 결과 번들 무결성 검사
- [ ] G-012 복원 실패 안전 잠금

## Epic H. AI와 웹 UI

- [ ] H-001 AIProvider 인터페이스
- [ ] H-002 ManualProvider
- [ ] H-003 MockProvider
- [ ] H-004 외부 API Provider
- [ ] H-005 Local LLM Provider
- [ ] H-006 구조화 출력 검증
- [ ] H-007 AI 룰 초안
- [ ] H-008 실험적 자동 수정 반복
- [ ] H-009 로컬 웹 대시보드
- [ ] H-010 케이스 상세
- [ ] H-011 룰 검증·승인 화면
- [ ] H-012 VM 실행 승인 화면

## Epic I. 평가 케이스

- [ ] I-001 시뮬레이터 케이스 1
- [ ] I-002 시뮬레이터 케이스 2
- [ ] I-003 실제 사례 1
- [ ] I-004 실제 사례 2
- [ ] I-005 실제 사례 3
- [ ] I-006 실제 사례 4
- [ ] I-007 실제 사례 5
- [ ] I-008 실제 사례 6
- [ ] I-009 Evidence Coverage Matrix
- [ ] I-010 정량 목표 최종 점검
