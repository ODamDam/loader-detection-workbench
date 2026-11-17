# 다중 증거 기반 Windows 악성코드 분석 지원 플랫폼

## 1. 프로젝트 개요

공식 과제명은 **「다중 증거 기반 Windows 악성코드 분석 지원 플랫폼 구축」**이다(2026-10-25 과제명 변경 신청, ADR-022). 변경 전 과제명은 「Windows 악성코드 로더의 초기 실행 행위 분석 및 탐지 룰 검증 프레임워크 구축」이며, 저장소 이름 `loader-detection-workbench`는 당분간 유지한다.

본 저장소의 소프트웨어 산출물은 **Local Detection-as-Code Workbench**이다. 다양한 Windows 악성코드 패밀리의 정적·동적 증거를 Case 단위로 수집·구조화하고, 탐지 가설과 YARA·Sigma 룰을 작성해 악성·정상 데이터에서 반복 검증하며, 케이스별 보고서를 생성하는 로컬 분석 플랫폼이다.

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
- `docs/07-vm-orchestration.md`: VirtualBox 기반 분석 VM 설계 (ADR-018)
- `docs/25-vm-execution-runbook.md`: VM 실행 런 사용·잠금 해제 절차 (ADR-024)
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
→ VirtualBox 자동화 (향후)
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

### Case Timeline 및 Case 보고서(Markdown·HTML)

현재 Project 디렉터리에서 실행한다. 두 명령은 같은 read-only Case timeline
query 결과를 사용한다. 기존 `case show`의 metadata 출력은 유지한다.

```text
workbench case timeline CASE-0001
workbench report build CASE-0001 reports/demo.md
workbench report build CASE-0001 reports/demo.html
```

attached Sysmon Artifact를 모두 정규화하고 timestamp, event_id, Artifact display
ID, EventRecordID 순으로 정렬한다. 문자열 tie-breaker는 사전순이다. 하나라도
손상되면 전체 query가 실패하며 부분 timeline/report를 내보내지 않는다.
Sysmon이 없으면 0건으로 성공하며 closed Case도 읽을 수 있다.

보고서는 UTF-8 Markdown 또는 독립형 HTML이며 기존 파일은 덮어쓰지 않는다. 출력
이름이 `.html`이면 HTML을 만들고 `--format markdown|html`로 바꿀 수 있다. Case 개요,
evidence 수, timeline, 원본 참조와 한계를 항상 포함한다. Case에 기록이 있으면 정적 PE
증거, VM 실행 런, 탐지 가설, 룰 버전과 본문, 검증 결과(분모 포함, development·
evaluation·tuning 분리)를 더한다. 악성 판정은 내리지 않는다. 정상화 이벤트·report
metadata의 DB 저장은 추가하지 않는다.
새 PC에서 합성 fixture로 재현하는 명령과 검증은
`docs/21-case-timeline-report-handoff.md`를 참조한다.

Windows PowerShell 5.1에서 보고서는 `Get-Content .\demo.md -Encoding UTF8`로
읽거나 UTF-8 editor를 사용한다. 기본 `Get-Content`의 표시 문제 때문에 파일의
UTF-8 encoding을 변경하지 않는다.

### VirtualBox guest Sysmon demo helper

현재 VM 기준은 VirtualBox + Windows 11 x64 + Guest Additions이며 clean snapshot은
`SYSMON-DEMO-CLEAN`이다 (ADR-018). 사용자가 실제 manual E2E 성공을 확인했다.
준비된 **guest 내부**에서 `scripts/vm/Invoke-SysmonDemoCollection.ps1`을 실행하면
고유 marker의 benign child PowerShell/text file과 동일 ProcessGuid/PID의 Event
1/11 쌍을 수집한다. 출력 디렉터리는 새 경로여야 하며 raw XML/metadata는 Git 밖에
둔다. Shared Folder는 선택 사항이다.

2026-10-13 사용자 수동 검증으로 첫 helper 수집의 VM → Workbench E2E가 PASS했다.
두 번째 독립 수집은 guest 출력 단계만 PASS했으며 두 번째 E2E는 미검증이다.
단일 실행 E2E의 기존 차단은 해소됐고 VM lifecycle 자동화는 미구현이다.
Host 모의 검증과 실제 guest 검증을 구분하며, 환경별 명령과 검증 결과는
[`docs/23-virtualbox-sysmon-export-helper-handoff.md`](docs/23-virtualbox-sysmon-export-helper-handoff.md)를 참조한다.

완료된 benign collection의 **host 처리**는
`scripts/Invoke-SysmonHostDemo.ps1 -CollectionDirectory '<명시한 수집 디렉터리>'`로
자동화할 수 있다. 기본 Workbench 실행 파일은 저장소의 `.venv/Scripts/workbench.exe`다.
원본을 변경하지 않고 저장소 밖의 새 임시 디렉터리로 복사하여 검증한 뒤,
기존 CLI로 Project/Case/Artifact, timeline, Markdown을 생성한다.
실패하면 후속 처리를 중단하고 부분 산출물과 안전한 진단을 보존한다.
입력·출력 데이터 경로의 링크/reparse point는 거부하며 실행 정책을 변경하지 않는다.
합성 fixture/mocked CLI 검증에 더해, Native 종료 코드 수정 후 사용자가 실제 completed
collection으로 Host 자동화 E2E 1회 성공(`success / complete / OK`, exit 0)을 확인했다.
Collection/Project, 안전한 진단, timeline과 필수 섹션 4개를 포함한 Markdown 보고서가
생성됐다. 반복 Host 자동화 E2E는 미검증이며 실제 산출물은 Git 밖에 둔다.

동일한 명시적 collection의 반복 Host 검증은 다음처럼 실행한다. 반복기는 기존 Host
스크립트를 독립 Windows PowerShell process로 최소 2회 실행하고, 각 Project의 full
validation, 원본/복사본/Artifact SHA-256 연결, timeline 재조회, provenance와 보고서의
의미적 일관성을 검사한다. Project/Case/Artifact ID, run 경로와 보고서 생성 시각만
비결정적 값으로 정규화한다. 실패 시 후속 회차를 중단하고 모든 run을 보존한다.

```powershell
powershell.exe -NoProfile -NonInteractive `
  -File .\scripts\Invoke-SysmonHostDemoRepeat.ps1 `
  -CollectionDirectory '<명시한 기존 benign collection>' `
  -OutputParent '<저장소 밖의 기존 로컬 디렉터리>' `
  -Iterations 2
```

공개 합성 Sysmon fixture와 실제 설치된 Workbench CLI를 사용한 독립 Host 반복 2회는
통과했다. 첫 private VM collection 반복 시도는 분석 실행 전 진입점의 빈 script-root
처리 오류로 실패했고, 필수 경로 선검증과 단일 JSON 실패 응답을 추가한 뒤 합성 반복을
다시 통과했다. 이후 사용자가 기존 benign VM collection을 재사용한 독립 Host 처리 2회를
실행했고 `success / complete / OK`와 모든 무결성·일관성 검사를 확인했다. 이는 새로운
Guest 수집이나 서로 다른 collection 2개에 대한 검증이 아니다. 상세 계약과 안전한 증빙
절차는 `docs/23-virtualbox-sysmon-export-helper-handoff.md`를 참조한다.

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

## 8. SQLite v2와 수동 증거 등록

SQLite v1 Project의 수동 증거 기능 사용 전에는 Project 디렉터리를 별도 위치에
백업하고 명시적으로 v2로 migration한다. 새 Project는 이미 v2이다.

```powershell
workbench project migrate ./workspace --to 2
workbench case evidence add CASE-0001 ./notes.txt --origin "analyst" --type analyst_note --description "review notes"
workbench case evidence list CASE-0001
workbench case evidence show CASE-0001 ART-000001
```

수동 증거는 Open Case에만 등록하며 허용된 텍스트·구조화 확장자와 4 MiB 제한을
적용한다. `ArtifactKind.EVIDENCE` 등록은 검증된 관측 사실이나 Sysmon Observation을
자동 생성하지 않는다. Case Bundle v1은 Artifact와 bytes는 포함하지만 원래 파일명,
출처, 설명, evidence type provenance는 보존하지 않는다. 상세 계약은
`docs/manual-evidence-contract-v2.md`를 참고한다.

## 9. Existing Case Sysmon Collection ingestion

기존 Project 작업공간에서 완료된 무해한 3파일 Collection을 기존 Open Case에
등록한다.

```powershell
workbench case collection import CASE-0001 '<collection-directory>'
```

명령은 세 파일을 모두 검증한 뒤 XML 두 개를 `sysmon`, metadata를 `other`로
저장한다. 재시도에서는 일치하는 Artifact를 재사용하므로 Timeline observation이
중복되지 않는다. SQLite v1/v2를 migration 없이 지원하며 Manual Evidence
provenance를 만들지 않는다. 검증, 오류, 안전 및 rollback 계약은
`docs/sysmon-collection-ingestion-contract.md`를 참고한다.

## 10. 로컬 Flask 기본 플랫폼 UI

기존 v1 또는 v2 Project를 CLI에서 하나 선택해 loopback 전용 UI를 실행한다.

```powershell
workbench ui serve .\workspace --port 8080
```

브라우저에서 `http://127.0.0.1:8080/cases`를 연다. UI는 Case 목록·상세,
Artifact와 Manual Evidence provenance, 수동 Evidence 등록, 안전한 Event ID 1/11
Timeline을 제공한다. 수동 등록은 Open v2 Case에서만 가능하며 기존 4 MiB와 확장자
정책을 그대로 사용한다. v1 Project의 조회는 가능하지만 등록 전에 별도 백업 후
명시적인 `project migrate --to 2`가 필요하다.

Case 상세의 **Evidence and detection analysis**(`/cases/<CASE>/analysis`)는 증거 →
가설 → 룰 → 검증 관계 그래프, 가설, 검증 결과, 프로세스·파일 관계 그래프와 VM 실행
런을 읽기 전용으로 보여준다. 상단 **Detection**(`/detection`)에서 룰, 벤치마크, 검증
실행 목록을 보고, 룰 페이지에서 버전별 결과를 비교한다. 검증 수치는 항상 분모와 함께
표시하고 development·evaluation·tuning 실행을 나눠서 보여준다. 가설·룰·벤치마크·검증의
생성과 수정은 CLI에서만 한다.

서버는 `127.0.0.1`에만 바인딩하고 debug/reloader를 사용하지 않는다. UI에는 원본
증거 다운로드·미리보기, Markdown 보고서 미리보기, VM·AI 실행 기능이 없다.
내부 ID와 저장 경로, Sysmon command line 및 실행·대상 경로도 표시하지 않는다.
프로세스·파일 그래프는 경로의 마지막 요소(파일 이름)만 표시한다.
원격 bind, port forwarding 또는 reverse proxy로 노출하지 않는다. 전체 route,
오류 및 보안 계약은 `docs/local-platform-ui-contract.md`를 참조한다.

## 11. 탐지 가설·YARA/Sigma 룰·벤치마크 검증 (ADR-023)

Project 루트에서 실행한다. 룰 파일은 UTF-8 텍스트이며 최대 256 KiB이다.

```powershell
uv run workbench rule check rule.yml --format sigma      # 컴파일만 확인
uv run workbench rule add rule.yml --format sigma --name "hidden encoded powershell"
uv run workbench rule revise RULE-0001 rule-v2.yml --note "add -nop"
uv run workbench rule freeze RULE-0001                   # 최신 draft 버전 동결
uv run workbench hypothesis add CASE-0001 --title "..." --statement "..." --evidence ART-000002
uv run workbench hypothesis link HYP-0001 RULE-0001
uv run workbench benchmark create --name realworld-v1
uv run workbench benchmark add BMK-0001 CASE-0001 --role dev          # dev|unseen|benign_common|benign_matched
uv run workbench benchmark freeze BMK-0001
uv run workbench validate run RULE-0001 BMK-0001                      # 기본: dev + benign 역할
uv run workbench validate run RULE-0001 BMK-0001 --role unseen        # 동결 룰·동결 벤치마크 필요
uv run workbench validate show RUN-0001
```

- 평가 단위는 Benchmark 구성원 Case이다. YARA는 Case의 `sample` Artifact를, Sigma는 `sysmon`
  Artifact의 모든 이벤트(Event ID 무관)를 평가한다. 대상 Artifact가 없으면 `not_evaluable`이다.
- 결과는 TP·FP·FN·TN을 분모와 함께 출력하고, 각 Case의 매치 근거(YARA 문자열 위치,
  Sigma 매치 EventRecordID)를 저장한다.
- 같은 룰에 대한 두 번째 이후 Unseen 실행은 `tuning`으로 기록되어 최초 평가와 구분된다.
- Sigma는 `product: windows`와 Sysmon 대응 category 또는 `service: sysmon`만 지원한다.
  지원하지 않는 수정자·값 유형은 `UNSUPPORTED_SIGMA_FEATURE`로 실패한다.
- `yara-python`은 Python 3.14용 휠이 없으면 소스 빌드되므로 C 빌드 도구가 필요할 수 있다.

## 12. VM 실행 런과 클린 스냅샷 복원 (ADR-024)

승인한 실행만 분석 VM을 움직인다. 복원 → 격리 재확인 → 실행 → 실행 구간 Sysmon 전체 회수·
해시 검증 → 복원 → Case 등록 순서이며, 복원을 확인하지 못하면 안전 잠금이 다음 실행을 막는다.
상세 절차와 실패 표는 [`docs/25-vm-execution-runbook.md`](docs/25-vm-execution-runbook.md)를 참조한다.

```powershell
uv run workbench vm preflight --profile sample                          # 읽기 전용 점검
uv run workbench vm scenario CASE-0001 --scenario registry-probe --dry-run
uv run workbench vm run CASE-0002 --sample ART-000001 --timeout 180 --approve
uv run workbench vm show VMR-0001
uv run workbench vm status
uv run workbench vm unlock --note "VM verified by hand"
```

- 게스트 계정은 `WORKBENCH_GUEST_USER`·`WORKBENCH_GUEST_PASSWORD` 환경 변수로만 받는다.
- sample 실행은 NIC 케이블 분리, 공유 폴더 없음, 클립보드·드래그 앤 드롭 비활성화를 요구한다.
- 2026-11-12 기준 실제 VM 실행 검증은 하지 않았다(모의 VBoxManage·PowerShell mock만 통과).

## 13. AI 분석 보조 골격 (ADR-026, 오프라인 전용)

AI 분석 보조는 선택 기능이다. 쓰지 않아도 나머지 기능은 그대로 동작한다. 현재는 이
PC 안에서만 도는 `offline-template` Provider만 있다. 이 Provider는 언어 모델이 아니라
고정 템플릿이며, API 키와 네트워크 없이 전체 흐름을 동작시키기 위한 것이다. 외부
Provider(Claude·GPT·Gemini)는 구현되어 있지 않고, 외부로 증거를 보내는 Provider는
호출 전에 거부된다.

```text
workbench ai providers
workbench ai preview CASE-0001          # Provider에 전달될 입력만 출력, 호출 없음
workbench ai analyze CASE-0001          # 제안을 pending 상태로 저장
workbench ai show AIA-0001
workbench ai accept AIA-0001 2 --note "부모 프로세스 확인"
workbench ai reject AIA-0001 1
workbench ai list --case CASE-0001
workbench ai compare CASE-0001         # 같은 입력의 Provider별 분석 비교(W8)
```

- Provider 입력은 구조 요약(`structural`)뿐이다. 개수, 종류, API·파일 **이름**, 표시
  ID만 담고 샘플 바이트, 원본 로그, 추출 문자열, 지표 값, 명령줄, 디렉터리 경로, 해시,
  Case 이름 같은 자유 서술은 담지 않는다. 입력은 SHA-256과 함께 저장된다.
- 제안(요약 1개, 가설 후보, 검토 항목)은 관측 사실이 아니다. 별도 테이블에 저장하고
  보고서와 UI에서 추론임을 표시한다.
- 제안은 사람이 수락하기 전에는 아무것도 바꾸지 않는다. 가설 후보를 `ai accept`하면
  `proposed` 상태의 Detection Hypothesis가 만들어진다. 가설의 상태 판단과 룰 채택은
  계속 사람이 한다.
- Case에 없는 Artifact를 인용하는 등 계약을 벗어난 Provider 출력은 전체를 거부하고
  저장하지 않는다.
- `ai compare`는 같은 입력(SHA-256)을 받은 Provider별 분석을 공통 의견과 개별 의견으로
  나눈다. Provider를 호출하지 않는다. 같은 의견인지는 인용 Artifact와 문구 유사도로 정하는
  휴리스틱이다(ADR-027). 보고서에도 같은 비교 표가 붙는다.

## 14. 무해한 시뮬레이터 (ADR-028)

sample 실행 경로를 실제 악성 샘플 없이 확인하기 위한 무해한 실행 파일이다. 소스는
`tools/simulator/WorkbenchSimulator.cs`이고, Windows에 기본으로 있는 .NET Framework 4.x
C# 컴파일러로 빌드한다. 실행 파일은 `build/simulator/`에 생기며 커밋하지 않는다.

```text
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\simulator\Build-WorkbenchSimulator.ps1
uv run workbench case create --name "simulator" --kind simulator
uv run workbench case artifact add --kind sample CASE-0002 build\simulator\workbench-simulator.exe
uv run workbench vm run CASE-0002 --sample ART-NNNNNN --approve
```

- 기본 프로필 `loader-like`: `%TEMP%` 파일 드롭, HKCU Run 값 쓰기, 자식 `cmd.exe`,
  `.invalid` 이름 조회, TEST-NET-1(192.0.2.1) 연결 시도. 종료 전에 모두 되돌린다.
- **호스트에서 실행하지 않는다.** 분석 VM에서 승인 후 `vm run`으로만 실행한다.
- 리허설용 YARA·Sigma 룰은 `tools/simulator/rules/`에 있다(최종 채택 룰 아님).
