# Windows 악성코드 로더 초기 실행 분석·탐지 룰 검증 프로젝트

## 1. 프로젝트 개요

공식 과제명은 **「Windows 악성코드 로더의 초기 실행 행위 분석 및 탐지 룰 검증 프레임워크 구축」**이다.

본 저장소의 소프트웨어 산출물은 가칭 **Local Detection-as-Code Workbench**이다. 이 도구는 Windows 악성코드 로더 또는 다운로더의 초기 실행 구간을 정적·동적으로 분석하고, 탐지 가설과 YARA·Sigma 룰을 작성·검증하며, 케이스별 Markdown·HTML 보고서를 생성하는 로컬 분석 워크벤치이다.

공식 과제명은 유지하며, Workbench는 해당 과제에서 구축하는 구체적 프레임워크 구현체로 취급한다.

## 2. 정량 목표

| 지표 | 목표 |
|---|---:|
| 분석 케이스 | 6개 이상 |
| YARA 룰 | 6개 이상 |
| Sigma 룰 | 6개 이상 |
| 개별 분석 보고서 | 6편 이상 |
| 최종보고서 | 1편 |
| 논문 초안 | 1편 |

Workbench의 자동 생성 범위는 **개별 분석 보고서의 Markdown·HTML 출력**까지이다. 최종보고서와 논문 초안은 케이스별 결과를 바탕으로 사용자가 직접 통합 작성한다.

## 3. 핵심 원칙

1. AI가 없어도 전체 핵심 파이프라인이 작동해야 한다.
2. 실제 악성 샘플보다 무해한 시뮬레이터로 프레임워크를 먼저 완성한다.
3. 정적 PE 분석과 Sysmon은 모든 케이스의 필수 증거이다.
4. Procmon과 PCAP은 행위 특성에 따라 조건부로 수집한다.
5. YARA·Sigma는 악성 데이터와 정상 비교 데이터에서 반복 검증한다.
6. AI는 탐지 룰의 최종 결정자가 아니라 분석 보조자이다.
7. 모든 자동 실행은 사용자 승인, 시간 제한, VM 복원을 전제로 한다.
8. 공개 산출물에는 실제 악성 샘플과 민감한 원본 로그를 포함하지 않는다.

## 4. 문서 안내

- `docs/00-document-map.md`: 문서 체계와 읽는 순서
- `docs/01-project-brief.md`: 문제 정의, 목표, 성공 기준
- `docs/02-requirements.md`: 기능·비기능 요구사항
- `docs/03-mvp-scope.md`: MVP 범위와 제외 범위
- `docs/04-architecture.md`: 시스템 구조와 데이터 흐름
- `docs/05-data-model.md`: 주요 엔터티와 작업공간 구조
- `docs/06-cli-and-ui-design.md`: CLI 우선 및 로컬 웹 UI 구조
- `docs/07-vm-orchestration.md`: VMware 기반 분석 VM 자동화
- `docs/08-detection-validation.md`: YARA·Sigma 검증 기준
- `docs/09-reporting-and-publication.md`: 보고서와 공개 정책
- `docs/10-test-plan.md`: 테스트 전략
- `docs/11-security-and-safety.md`: 악성코드 취급 안전 원칙
- `docs/12-roadmap-and-milestones.md`: 구현 순서와 마일스톤
- `docs/13-definition-of-done.md`: 완료 정의
- `docs/14-decision-register.md`: 결정 사항 요약
- `docs/15-initial-backlog.md`: 초기 개발 백로그
- `docs/16-risk-register.md`: 위험과 대응 방안
- `docs/adr/`: Architecture Decision Record
- `docs/templates/`: 이슈·주간일지·보고서·ADR 템플릿

## 5. 권장 개발 순서

핵심 전략은 **수직적 슬라이스를 먼저 완성한 뒤 자동화 범위를 확장하는 것**이다.

```text
수동 Case Bundle 등록
→ 정적 PE 분석
→ Sysmon 이벤트 정규화
→ 탐지 가설 작성
→ YARA·Sigma 등록
→ 악성·정상 데이터 검증
→ Markdown·HTML 보고서 생성
→ 시뮬레이터 자동 실행
→ VMware 자동화
→ AI Provider
→ 로컬 웹 UI
```

## 6. 문서 상태

본 문서 세트는 현재까지의 요구사항 인터뷰에서 합의한 내용을 기준으로 작성한 초기 기준선이다. 실제 구현 과정에서 변경이 필요한 경우 ADR과 변경 이력을 함께 갱신한다.

## 7. 로컬 개발 환경

M0-local 개발 기준은 CPython 3.12와 uv이다. 저장소 루트에서 다음 명령으로
개발 환경을 구성하고 최소 CLI를 실행한다.

```powershell
uv sync
uv run workbench --help
uv run workbench --version
```

설정 파일은 선택 사항이다. 지정하지 않으면 콘솔 로그 레벨 `INFO`를 사용한다.
현재 지원하는 최소 설정은 다음과 같다.

```toml
[workbench]
log_level = "INFO"
```

CLI의 `--log-level`은 설정 파일 값을 덮어쓴다. 전체 로컬 검증은 다음 명령으로
실행한다.

```powershell
uv lock --check
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src
```

저장소는 소스 코드용이며 분석 프로젝트 작업공간, 실제 샘플 및 원본 분석
로그를 저장하는 위치로 사용하지 않는다.
