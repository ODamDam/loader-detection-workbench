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

M1 Case Bundle v1 CLI:

```text
workbench bundle export CASE-NNNN OUTPUT.zip
workbench bundle validate BUNDLE.zip
workbench bundle import BUNDLE.zip
```

## 6. 문서 상태

### Sysmon Event ID 1·11 최소 정규화

Case에 `sysmon` kind로 등록한 단일 XML Event ID 1 또는 11을 Application Service로
정규화할 수 있다. 다음 예시는 저장소의 합성 fixture만 읽으며 실행하지 않는다.
`workspace_root`는 소스 저장소 밖에 생성한 기존 Project 경로이다.

```python
from pathlib import Path

from loader_detection_workbench.artifact.service import ArtifactService
from loader_detection_workbench.sysmon.service import SysmonService

source = Path("tests/fixtures/public/sysmon/process-create.xml")
artifact = ArtifactService(workspace_root).add("CASE-0001", source, "sysmon")
events = SysmonService(workspace_root).normalize(
    "CASE-0001", artifact.artifact_id.display_id
)
assert len(events) == 1
assert events[0].source_artifact_id == artifact.artifact_id
assert events[0].source_record_id == "42"

file_source = source.with_name("file-create.xml")
file_artifact = ArtifactService(workspace_root).add("CASE-0001", file_source, "sysmon")
file_events = SysmonService(workspace_root).normalize(
    "CASE-0001", file_artifact.artifact_id.display_id
)
assert len(file_events) == 1
assert file_events[0].event_id == 11
assert file_events[0].source_record_id == "43"
```

결과는 메모리로 반환하며 DB나 산출물 파일에 저장하지 않는다. ArtifactId와
XML EventRecordID로 원본 record를 추적한다. Case/Artifact 조회는 기존 API를
사용한다. 지원 입력, 필드와 오류는 `docs/05-data-model.md`, 작업 인계와 검증은
`docs/20-sysmon-event11-handoff.md`를 참조한다. 복수 이벤트 XML과 EVTX는
지원하지 않는다.

### Case Timeline 및 데모 Markdown 보고서

현재 Project 디렉터리에서 실행한다. 두 명령은 같은 read-only Case timeline
query 결과를 사용한다. 기존 `case show`의 metadata 출력은 유지한다.

```text
workbench case timeline CASE-0001
workbench report build CASE-0001 reports/demo.md
```

attached Sysmon Artifact를 모두 정규화하고 timestamp, event_id, Artifact display
ID, EventRecordID 순으로 정렬한다. 문자열 tie-breaker는 사전순이다. 하나라도
손상되면 전체 query가 실패하며 부분 timeline/report를 내보내지 않는다.
Sysmon이 없으면 0건으로 성공하며 closed Case도 읽을 수 있다.

보고서는 UTF-8 Markdown이며 기존 파일은 덮어쓰지 않는다. Case 개요, evidence 수,
timeline, 원본 참조와 한계를 포함하는 시연용 subset이다. 전체 분석 보고서나 악성
판정이 아니다. 정상화 이벤트·report metadata의 DB 저장은 추가하지 않는다.
새 PC에서 합성 fixture로 재현하는 명령과 검증은
`docs/21-case-timeline-report-handoff.md`를 참조한다.

본 문서 세트는 현재까지의 요구사항 인터뷰에서 합의한 내용을 기준으로 작성한 초기 기준선이다. 실제 구현 과정에서 변경이 필요한 경우 ADR과 변경 이력을 함께 갱신한다.

## 7. 로컬 개발 환경

M0-local 개발 기준은 CPython 3.12와 uv이다. 저장소 루트에서 다음 명령으로
개발 환경을 구성하고 최소 CLI를 실행한다.

```powershell
uv sync
uv run workbench --help
uv run workbench --version
```

M1 Project workspace는 비어 있거나 존재하지 않는 디렉터리에 생성한다. `show`와
`validate`의 경로를 생략하면 현재 디렉터리를 사용하며 상위 디렉터리는 검색하지
않는다.

```powershell
uv run workbench project create .\workspace --name "Analysis Project"
uv run workbench project show .\workspace
uv run workbench project validate .\workspace
```

일반 `workbench sample` 명령은 현재 Project workspace의 `project.db`를 사용한다.
기존 `.workbench/sample-intake.db`는 자동으로 가져오거나 삭제하지 않는다.

Project workspace 디렉터리에서 Case를 생성하고 관리한다. Case는 Artifact 없이
생성 가능한 분석 컨테이너이며, `closed`는 읽기 전용 상태를 뜻한다. 분석 완료나
Definition of Done 충족 여부를 나타내지 않는다.

```powershell
workbench case create --name "Example" --kind benign
workbench case list
workbench case show CASE-0001
workbench case rename CASE-0001 --name "Renamed"
workbench case close CASE-0001
workbench case reopen CASE-0001
```

이름은 필수이며 공백만 있는 값은 거부한다. `--kind`는 `malware`, `simulator`,
`benign` 중 하나이며 `--description`은 선택 사항이다. 입력 문자열은 자동으로
trim하지 않는다. 자세한 동작과 오류는 `docs/06-cli-and-ui-design.md`를 참조한다.

Case에 로컬 파일을 Artifact로 등록할 수 있다. 개발과 검증에는 benign 임시
파일만 사용한다.

```powershell
workbench case artifact add CASE-0001 .\benign.txt --kind evidence
workbench case artifact list CASE-0001
workbench case artifact detach CASE-0001 ART-000001
```

내용은 SHA-256 기반 `artifacts/sha256/<앞 2자리>/<해시>`에 보존한다. 같은 bytes는
파일 하나를 공유하며, 매 add마다 별도 provenance 행과 Artifact ID를 발급한다.
detach는 Case 연결만 제거하고 행과 bytes를 유지한다. 닫힌 Case에서는 list만
허용한다. kind, 오류, 동시성 및 실패 복구 제한은
`docs/06-cli-and-ui-design.md`의 Issue #10 설명을 참조한다.

Project 검증은 기본적으로 구조와 관계를 검사하며, `--full`을 지정하면 Artifact
파일의 존재·크기·SHA-256과 orphan/staging 경고까지 확인한다. 검증은 읽기 전용이며
자동 복구·migration·cleanup을 수행하지 않는다.

```powershell
workbench project validate .\workspace
workbench project validate .\workspace --full
```

finding이 없으면 기존 `valid` 출력과 exit code 0을 유지한다. warning만 있어도
exit code 0이며 finding을 출력하고, error finding은 exit code 1, workspace를
안전하게 열 수 없는 실행 오류는 exit code 2이다.

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
