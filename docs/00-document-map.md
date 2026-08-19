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
- 루트 `PLANS.md`: 현재 활성 마일스톤의 범위, 상태와 검증 현황
- `17-development-workflow.md`: 작업 접수, 승인, 구현, 검증과 보고의 상세 절차

## 4. 문서 관리 원칙

- 프로젝트 목표, 정량 목표, 안전 원칙은 기준선으로 고정한다.
- 구현 방식이 달라지면 관련 ADR을 추가하거나 기존 ADR을 대체한다.
- 진행률은 작성한 코드량이 아니라 완료된 사용자 흐름으로 판단한다.
- 각 이슈는 목적, 산출물, 완료 조건, 의존성을 포함한다.
- 주간 일지에는 완료 사항, 문제, 결정, 다음 작업을 기록한다.
- 저장소 작업은 루트 운영 문서와 `17-development-workflow.md`를 따른다.
