# 문서 체계

## 1. 문서 목적

본 프로젝트는 기획, 설계, 구현, 검증, 안전 관리가 함께 필요한 개인 개발 프로젝트이다. 모든 내용을 하나의 계획서에 넣지 않고 목적별 문서로 분리한다.

## 2. 권장 읽기 순서

1. 루트 `README.md`
2. `01-project-brief.md`
3. `02-requirements.md`
4. `03-mvp-scope.md`
5. `04-architecture.md`
6. `05-data-model.md`
7. `06-cli-and-ui-design.md`
8. `07-vm-orchestration.md`
9. `08-detection-validation.md`
10. `09-reporting-and-publication.md`
11. `10-test-plan.md`
12. `11-security-and-safety.md`
13. `12-roadmap-and-milestones.md`
14. `13-definition-of-done.md`
15. `14-decision-register.md`와 `adr/`
16. `15-initial-backlog.md`
17. `16-risk-register.md`
18. `17-development-workflow.md`

## 3. 운영 문서

- 루트 `AGENTS.md`: Codex가 항상 적용할 비협상 저장소 규칙
- 루트 `PLANS.md`: 현재 활성 마일스톤의 실제 상태, 범위와 검증 현황
- `17-development-workflow.md`: 작업 접수, 승인, 구현, 검증과 보고의 상세 절차
- `18-m0-codex-handoff.md`: 현재 M0-local을 Codex에 넘길 때 사용하는 착수 기준과 작업 경계
- `23-virtualbox-sysmon-export-helper-handoff.md`: 현재 VirtualBox demo 수집 helper와 guest 검증 인계
- `24-sysmon-v2-vm-snapshot-procedure.md`: Sysmon v2 설정과 `SYSMON-V2-CLEAN` 스냅샷 생성(사용자 수행)
- `25-vm-execution-runbook.md`: W4 VM 실행 런(`workbench vm`) 사용·실패·잠금 해제 절차
- `26-sample-acquisition-guide.md`: 평가용 실제 샘플 확보·등록·분할 절차(사용자 수행)
- `adr/ADR-025-case-analysis-report-and-views.md`: W5 보고서, 모듈 테이블 검증, W6 읽기 전용 UI
- `adr/ADR-026-ai-assisted-analysis-skeleton.md`: W7 AI 분석 보조의 오프라인 골격과 남은 결정
- `adr/ADR-027-multi-provider-comparison.md`: W8 다중 Provider 분석 비교
- `adr/ADR-028-benign-simulator.md`: M5 무해한 시뮬레이터 실행 파일과 빌드 방식
- `adr/ADR-029-static-report-site.md`: M4 비식별화한 정적 보고서 사이트
- `adr/ADR-030-sealed-sample-storage.md`: 봉인 샘플 저장과 암호 ZIP 메모리 가져오기

## 4. 현재 활성 작업을 읽는 순서

현재 활성 마일스톤이 M0인 동안 Codex는 전체 문서 세트를 처음부터 모두 읽기보다
다음 순서를 우선한다.

1. 루트 `AGENTS.md`
2. 루트 `PLANS.md`
3. `17-development-workflow.md`
4. 관련 ADR
5. 활성 마일스톤 handoff 문서
6. 적용 가능한 테스트·안전·완료 정의 문서

제품 기능의 배경이나 경계가 필요할 때 프로젝트 brief, requirements, MVP와 architecture를 추가로 읽는다.

## 5. 문서 관리 원칙

- 프로젝트 목표, 정량 목표, 안전 원칙은 기준선으로 고정한다.
- 실제 현재 상태는 `PLANS.md`가 관리하고, 장기 계획은 roadmap/backlog가 관리한다.
- 구현 방식이 달라지면 관련 ADR을 추가하거나 기존 ADR을 대체한다.
- 진행률은 작성한 코드량이 아니라 완료된 사용자 흐름으로 판단한다.
- 각 이슈는 목적, 산출물, 완료 조건, 의존성을 포함한다.
- 주간 일지에는 완료 사항, 문제, 결정, 다음 작업을 기록한다.
- 저장소 작업은 루트 운영 문서와 `17-development-workflow.md`를 따른다.
- Notion은 프로젝트 맥락·조사·일정·기록의 운영 허브로 사용할 수 있으나, Codex가 구현해야 하는 확정 결정은 GitHub 문서·ADR·Issue에도 반영한다.
