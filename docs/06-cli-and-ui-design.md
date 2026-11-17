# CLI와 로컬 웹 UI 설계

## 1. 기본 원칙

CLI가 핵심 제품 인터페이스이다. 로컬 웹 UI는 별도 비즈니스 로직을 가지지 않고 동일한 Application Service를 호출한다.

## 2. CLI 기능 그룹

### 구현된 Case timeline / Markdown report

```text
workbench case timeline CASE-NNNN
workbench report build CASE-NNNN OUTPUT [--format markdown|html]
```

- 현재 디렉터리를 Project root로 사용한다. 상위 탐색이나 `--database` override는
  사용하지 않는다. 기존 `case show`와 다른 Case/Artifact 명령은 그대로 유지한다.
- 두 명령은 `CaseTimelineQuery.query()`의 동일 contract를 사용한다. 결과는 frozen
  `CaseTimeline(case, observations, sysmon_artifact_count)`이며 observations는 기존
  ProcessCreateEvent/FileCreateEvent 객체의 tuple이다. 별도 DTO나 DB 저장은 없다.
- attached `sysmon` Artifact만 기존 `SysmonService.normalize()`로 처리한다.
  timestamp ASC → event_id ASC → Artifact display ID 사전순 → EventRecordID
  사전순으로 정렬한다. 따라서 같은 마지막 key에서 `"10"`은 `"2"`보다 앞선다.
- timeline summary는 `case`, `sysmon_artifacts`, `observations`를 표시한다.
  각 event는 UTC 시각, EventID, process_create/file_create, image, PID,
  command_line 또는 target, `ART-NNNNNN#record`를 표시한다. ULID는 표시하지 않는다.
- 0건은 성공이며 `No normalized Sysmon observations.`를 표시한다. closed Case도
  조회·보고서 생성이 가능하다. Case metadata와 DB는 변경하지 않는다.
- 한 Artifact 오류도 silent skip하지 않는다. 미존재 Case는 CASE_NOT_FOUND,
  변조는 ARTIFACT_INTEGRITY_MISMATCH 등 기존 오류를 surface한다. stdout의 부분
  timeline이나 report 파일을 생성하지 않는다. 성공 exit 0, 오류 exit 2와
  `error: CODE: safe message` 형식을 사용한다.
- `report build`는 timeline 결과에 정적 PE 결과, VM 실행 런, 가설, 룰, 검증 결과를
  더한다(`CaseAnalysisQuery`). 출력 이름이 `.html`·`.htm`이면 HTML을 만들고
  `--format`으로 바꿀 수 있다. 기록이 없는 섹션은 생략하므로 Sysmon만 있는 Case의
  Markdown은 이전과 같다. 섹션과 escape 규칙은 `09-reporting-and-publication.md`를 따른다.
- report 성공 stdout은 `report: created`이다. 상대 OUTPUT은 현재 Project 기준이며
  명시적인 절대 OUTPUT도 허용한다. 부모 디렉터리는 필요한 만큼 생성한다.
  기존 파일/디렉터리/링크는 REPORT_OUTPUT_EXISTS로 거부한다. 쓰기·게시·cleanup
  실패는 REPORT_WRITE_FAILED이며 원본 OS 예외나 로컬 경로를 출력하지 않는다.
- Report는 전체 query와 rendering 성공 후 같은 디렉터리의 임시 파일에 UTF-8/LF로
  작성하고 flush/fsync한다. Windows no-replace rename, POSIX no-replace link로
  완성된 파일만 게시한다. 경쟁 writer의 파일도 덮어쓰지 않는다.
- 통상 실패에서 staging은 정리한다. 빈 부모 디렉터리는 남을 수 있다. 강제 종료,
  cleanup 자체 실패나 hostile filesystem race까지 복구·sandbox를 보장하지 않는다.
  cleanup 실패 시 성공을 출력하지 않으며 이미 게시된 완성 report는 남을 수 있다.
- query 전체의 DB snapshot/장기 잠금은 없다. 조회 중 detach는 기존 service 오류로
  실패할 수 있고, 이후 추가된 Artifact는 다음 query에서 반영된다.

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
workbench bundle import BUNDLE.zip
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

### M1 Issue #9 Case CLI

현재 디렉터리의 Project를 사용하며 상위 디렉터리를 검색하지 않는다.
Case 명령은 Sample Intake용 숨김 `--database` override를 사용하지 않는다.

```text
workbench case create --name NAME --kind KIND [--description TEXT]
workbench case list
workbench case show CASE-NNNN
workbench case rename CASE-NNNN --name NAME
workbench case close CASE-NNNN
workbench case reopen CASE-NNNN
```

- Case는 Artifact가 없어도 생성 가능한 분석 컨테이너이다.
- kind는 `malware`, `simulator`, `benign`이며 생성 이후 변경할 수 없다.
- 이름은 필수이고 빈 문자열/공백만 있는 이름은 거부한다. 이름과 설명은 trim하지
  않으며 생략한 설명은 SQLite NULL이다.
- selector는 Project-local display ID이다. ULID 직접 조회는 지원하지 않는다.
- 번호는 `CASE-0001`부터 시작하며 재사용하지 않는다. 목록은 숫자순으로 정렬하여
  `CASE-9999` 다음에 `CASE-10000`이 온다. 빈 목록은 출력 없이 성공한다.
- create/show/rename/close/reopen은 Case 필드를 `field: value` 형식으로 출력한다.
  NULL은 `NULL`로 표시한다. list는 display ID, kind, status, name을 탭으로 구분한다.
- open에서만 rename할 수 있다. close는 open → closed, reopen은 closed → open이다.
  closed는 읽기 전용 상태이며 분석 완료 또는 Definition of Done 완료가 아니다.
- 생성 시 created_at과 updated_at은 같고 closed_at은 NULL이다. close는 updated_at과
  closed_at을 같은 값으로 저장한다. reopen은 closed_at을 NULL로 비운다.
- 시간은 UTC 초 단위이며 같은 초의 변경은 허용한다. 시간이 역행하면
  `INVALID_TIMESTAMP`로 거부한다. 실패한 변경은 행과 counter를 변경하지 않는다.
- 오류는 stderr에 `error: CODE: message`로 출력한다. 성공과 domain 오류의 exit
  behavior는 기존 Project CLI 관례(각각 0과 2)를 따른다.
- 입력 오류: `INVALID_CASE_NAME`, `INVALID_CASE_KIND`, `INVALID_DISPLAY_ID`.
  미존재: `CASE_NOT_FOUND`. 닫힌 Case rename: `CASE_CLOSED`.
  같은 상태 전이: `INVALID_CASE_TRANSITION`.
- 저장된 Case의 identity/association/lifecycle/timestamp 손상은
  `INVALID_CASE_RECORD`이다. Project 자체의 identity 불일치와 counter 손상에는
  기존 workspace/SQLite 오류를 사용한다. SQLite 예외 원문은 출력하지 않는다.

### M1 Issue #10 Artifact CLI

```text
workbench case artifact add CASE-NNNN SOURCE --kind KIND
workbench case artifact list CASE-NNNN
workbench case artifact detach CASE-NNNN ART-NNNNNN
workbench case artifact import-zip CASE-NNNN ARCHIVE [--password P] [--member NAME]
```

- 현재 Project만 사용한다. 상위 디렉터리 검색과 Sample Intake의 숨김
  `--database` override를 사용하지 않는다.
- kind는 정확한 소문자 `sample`, `static`, `sysmon`, `procmon`, `network`,
  `normalized`, `evidence`, `rule`, `report`, `other` 중 하나이다.
- #10 brief의 `ART-NNNN`은 selector 표기로 해석한다. 기존 #7 FINAL과
  `ArtifactId`의 최소 6자리 계약을 보존해 `ART-000001`부터 발급한다.
- add/list/detach 결과는 `display_id`, `kind`, `sha256`, `size_bytes`,
  `relative_path`를 탭으로 구분한다. list는 숫자 ID 순이며 빈 결과는 출력 없이
  성공한다. 성공 exit code는 0, 오류는 2이고 stderr 형식은 `error: CODE: message`다.
- filename과 source 절대 경로는 저장하지 않는다. canonical relative path는
  `artifacts/sha256/<sha256 앞 2자리>/<sha256>`이며 extension이 없다.
- 동일 bytes의 이름·kind·Case가 달라도 파일 하나를 공유한다. 같은 Case에서
  반복 add해도 별도의 ULID와 display ID를 가진 provenance 행을 생성한다.
- detach는 해당 Case에 연결된 행의 `case_id`만 NULL로 변경한다. 이미 detached인
  행이나 다른 Case의 행은 거부한다. 행과 content는 삭제하지 않으며 reattach,
  hard delete, garbage collection은 제공하지 않는다.
- closed Case의 add/detach는 `CASE_CLOSED`, list는 허용한다. Artifact 작업은
  기존 Case lifecycle timestamp를 변경하지 않는다.
- `INVALID_ARTIFACT_KIND`, `ARTIFACT_SOURCE_INVALID`, `ARTIFACT_NOT_FOUND`,
  `ARTIFACT_NOT_ATTACHED`, `INVALID_ARTIFACT_RECORD`로 입력·관계·저장 행 오류를
  구분한다. 기존 Case/ID/Project 오류도 유지한다.
- ADR-030: `sample` kind 내용은 봉인 형태(`LDWSEAL1` 헤더 + 공개 키스트림 XOR)로
  저장한다. 기록하는 SHA-256·크기는 봉인 전 기준이다. `import-zip`은 비밀번호 ZIP(기본
  `infected`)의 멤버 하나를 메모리로만 읽어 `sample`로 추가하고, 디스크에 풀지 않는다.
  멤버가 여러 개면 `--member`가 필요하다. 오류는 `ARCHIVE_INVALID`,
  `ARCHIVE_PASSWORD_REJECTED`, `ARTIFACT_SIZE_LIMIT_EXCEEDED`(64 MiB)다.
- `PATH_ESCAPE`로 symlink/reparse point 경로를 거부하고 기존 canonical bytes의
  hash/size가 다르면 `ARTIFACT_INTEGRITY_MISMATCH`로 거부한다. 덮어쓰지 않는다.
- 같은 filesystem에 임시 파일을 staging하고 hash/size 재검증 및 fsync 후
  Windows에서는 원자적 no-replace rename으로 publish한다. POSIX에서는 기존
  파일 덮어쓰기를 방지하는 atomic link 후 staging unlink를 사용한다.
- SQLite `BEGIN IMMEDIATE`로 add와 Case 변경을 조율한다. hash/copy 동안에도
  writer lock을 보유하므로 큰 파일은 다른 쓰기를 지연시킬 수 있다. lock timeout을
  포함한 DB 실패는 `ARTIFACT_PERSISTENCE_FAILED`, 파일 작업 실패는
  `ARTIFACT_STORE_FAILED`로 보고한다. counter와 행 insert는 함께 rollback된다.
- publish 후 DB 실패는 새 writer lock 안에서 committed 참조(분리된 행 포함)가
  없고 파일 identity가 현재 작업 소유와 같을 때만 content를 정리한다. 기존
  dedup 파일이나 다른 작업의 파일은 삭제하지 않는다. staging도 작업 소유만 정리한다.
- cleanup 실패는 `ARTIFACT_CLEANUP_FAILED`이며 성공으로 보고하지 않는다.
  orphan content/staging 또는 빈 디렉터리가 남을 수 있다. 강제 종료·전원 장애에
  대한 filesystem/SQLite 분산 원자성이나 자동 복구/GC는 제공하지 않는다.
- containment 검사는 기존 링크를 거부한다. 신뢰할 수 없는 프로세스가 경로를
  동시에 교체하는 hostile filesystem race에 대한 sandbox 보장은 제공하지 않는다.
  전체 content validator와 Bundle은 각각 #11/#12 범위이다.

### M1 Issue #11 Project validator

```text
workbench project validate [WORKSPACE]
workbench project validate [WORKSPACE] --full
```

- `WORKSPACE`를 생략하면 현재 디렉터리를 사용한다. 상위 디렉터리를 검색하지
  않는다.
- 기본 검증은 Tier 1 structural + Tier 2 relational/cross-contract를 수행한다.
  `--full`은 Tier 3 materialized Artifact content 검증을 추가한다.
- 검증은 report-only다. DB, manifest, Artifact bytes와 filesystem을 수정하지
  않으며 repair, migration, cleanup, garbage collection을 하지 않는다.
- 완전히 유효한 결과는 기존처럼 stdout에 `valid`, exit code 0을 출력한다.
  warning finding만 있으면 warning을 stderr에 출력하고 exit code 0, error finding이
  있으면 exit code 1, workspace를 안전하게 해석할 수 없는 runtime/domain failure는
  exit code 2다.
- finding line은 `severity CODE [scope/subject]: safe message` 형식이며 tier,
  scope, subject, code, message 순으로 deterministic하게 정렬한다. 절대 경로,
  source path, secret와 민감한 content를 출력하지 않는다.
- 기존 exact semantics는 `INVALID_PROJECT_MANIFEST`,
  `UNSUPPORTED_CONTRACT_VERSION`, `INVALID_SQLITE_SCHEMA`,
  `WORKSPACE_IDENTITY_MISMATCH`, `INVALID_CASE_RECORD`,
  `INVALID_ARTIFACT_RECORD`, `INVALID_RELATIVE_PATH`, `PATH_ESCAPE`를 재사용한다.
  validator-specific codes는 `DATABASE_MISSING`, `COUNTER_INVALID`,
  `BROKEN_CASE_REFERENCE`, `ARTIFACT_PATH_INVALID`, `ARTIFACT_MISSING`,
  `ARTIFACT_SIZE_MISMATCH`, `ARTIFACT_SHA256_MISMATCH`,
  `ORPHAN_ARTIFACT_CONTENT`, `STALE_STAGING_CONTENT`이다.
- 모듈 소유 테이블(ADR-023 detection, ADR-024 execution)은 해당 schema 표식 테이블이
  있을 때만 Tier 2에서 검사한다(`project.module_validator`). scope는 `detection`,
  `execution`이다. 모듈을 한 번도 쓰지 않은 Project에는 finding이 없다.
  - 구조: `MODULE_SCHEMA_UNSUPPORTED`(지원하지 않는 버전이면 그 모듈 검사를 멈춘다),
    `MODULE_SCHEMA_INCOMPLETE`(테이블 또는 불변 trigger 누락).
  - detection: `DETECTION_COUNTER_INVALID`, `DETECTION_RECORD_INVALID`(표시 ID, 버전
    연속성, 본문과 SHA-256 불일치, 구성원 역할과 Case 종류 불일치),
    `DETECTION_REFERENCE_BROKEN`(없는 Case·Artifact·Rule·Benchmark, 다른 Case의 근거
    Artifact), `DETECTION_FREEZE_VIOLATION`(동결 상태와 시각 불일치, 동결되지 않은 룰
    버전·Benchmark로 기록된 Unseen 실행), `DETECTION_RESULT_INCONSISTENT`(역할과 매치에서
    나올 수 없는 결과, 동결 Benchmark 구성원이 아닌 결과).
  - execution: `EXECUTION_COUNTER_INVALID`, `EXECUTION_RECORD_INVALID`,
    `EXECUTION_REFERENCE_BROKEN`.
  - warning: `EXECUTION_RUN_UNFINISHED`, `EXECUTION_SAFETY_LOCK_SET`(VM 상태를 사람이
    확인해야 함을 알린다), `ARTIFACT_REFERENCE_DETACHED`(참조된 Artifact가 Case에서
    분리됨).
- 기본 검증은 Artifact bytes를 rehash하지 않는다. `--full`에서만 모든 persisted
  Artifact(분리된 행 포함)를 검사하며, 같은 SHA-256은 한 run에서 hash 결과를
  재사용한다.
- filesystem scan ownership은 `artifacts/sha256/<two-hex>/<64-hex>` canonical
  content와 shard 내부 `.artifact-*.tmp` staging residue로 제한한다. orphan
  content와 staging residue는 warning이며 삭제하지 않는다. 참조된 content의
  missing/size/hash 오류는 error다. 그 밖의 workspace/noncanonical 파일은 무시한다.

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

### M1 Issue #12 Case Bundle v1

```text
workbench bundle export CASE-NNNN OUTPUT.zip
workbench bundle validate BUNDLE.zip
workbench bundle import BUNDLE.zip
```

- Bundle은 단일 Case 내부 증거 교환 패키지이며 `project.json`과 SQLite를 포함하지 않는다.
- ZIP은 `manifest.json`과 `artifacts/sha256/<두 자리>/<sha256>`만 허용한다.
- export는 attached Artifact만 포함하고, 같은 SHA-256 바이트는 한 번만 저장한다.
- import는 Case/Artifact ID와 lifecycle timestamp를 보존하고 target Project ID로 rebinding한다.
- 기존 ID 또는 display ID 충돌, manifest·경로·크기·SHA-256 불일치는 fail closed한다.
- import는 staging, SQLite transaction, operation-owned rollback/cleanup을 사용한다.

1. CLI 완성
2. Application Service 안정화
3. 읽기 전용 웹 화면
4. 룰 편집·승인 화면
5. VM 실행 승인 화면
6. AI 제안 검토 화면

## 6. Schema v2 + Manual Evidence Registration

수동 증거 등록과 명시적 Project migration의 현재 CLI·서비스·오류·호환성 계약은
`docs/manual-evidence-contract-v2.md`를 따른다. CLI는 Application Service만 호출하며,
수동 증거를 Sysmon Observation으로 자동 변환하지 않는다. Case Bundle v1에는 generic
Evidence Artifact와 content만 포함되고 provenance는 보존되지 않는다.

## 7. Flask 기본 플랫폼 UI

```text
workbench ui serve [ROOT] [--port PORT]
```

- CLI에서 지정한 단일 Project를 서버 시작 전에 검증하고 `127.0.0.1`에만
  Waitress를 바인딩한다. 브라우저 Project 선택, `--host`, debug와 reloader는 없다.
- Case 목록·상세, path-safe Artifact/provenance, Manual Evidence 등록, Event ID
  1/11 Timeline을 server-rendered HTML로 제공한다.
- UI는 Project, Case, Artifact, Manual Evidence, Timeline Application Service만
  사용하며 SQLite나 CLI subprocess를 직접 사용하지 않는다.
- v1 Project는 읽을 수 있지만 Evidence 등록은 명시적 migration-required로
  거부한다. 자동 migration이나 schema 변경은 없다.
- Timeline은 timestamp, Event ID, PID, Artifact display ID, EventRecordID만
  표시한다. command line, image, target path, ProcessGuid와 raw content는 숨긴다.
- W6(ADR-025): `/cases/<CASE>/analysis`, `/detection`, `/rules/<RULE>`,
  `/validation/<RUN>`은 읽기 전용 조회 화면이다. 관계 그래프는 서버에서 배치한 inline
  SVG이며 script와 외부 자원을 쓰지 않는다. 프로세스·파일 그래프는 파일 이름(경로의
  마지막 요소)만 표시한다. 가설·룰·벤치마크·검증의 생성과 수정은 CLI에서만 한다.
- `other` Artifact에는 Collection identity가 없으므로 중립적인 Other Artifact로
  표시한다. 전체 route, 오류와 보안 계약은 `docs/local-platform-ui-contract.md`를
  따른다.

## 8. AI 분석 보조 CLI (ADR-026)

```text
workbench ai providers
workbench ai preview CASE-NNNN
workbench ai analyze CASE-NNNN [--provider offline-template]
workbench ai list [--case CASE-NNNN]
workbench ai show AIA-NNNN
workbench ai accept AIA-NNNN N [--note TEXT]
workbench ai reject AIA-NNNN N [--note TEXT]
workbench ai compare CASE-NNNN [--analysis AIA-NNNN ...]
```

- 현재 디렉터리를 Project root로 쓴다. 성공 exit 0, 오류 exit 2와
  `error: CODE: safe message` 형식을 따른다.
- `preview`는 Provider를 호출하지 않고 입력 범위, SHA-256, 크기, 구조 요약 JSON을
  출력한다. `analyze`가 저장하는 입력과 같다.
- `analyze`는 제안을 `pending`으로 저장한다. 출력에는 제안이 추론이라는 안내가 항상
  포함된다. `accept`·`reject`는 `pending` 제안에 한 번만 적용된다.
- 오류 코드: `AI_PROVIDER_UNAVAILABLE`(모르는 Provider, 외부 전송이 필요한 Provider),
  `AI_PROVIDER_FAILED`, `AI_OUTPUT_INVALID`, `AI_ANALYSIS_NOT_FOUND`,
  `AI_SUGGESTION_ALREADY_REVIEWED`, `INVALID_AI_REQUEST`, `AI_PERSISTENCE_FAILED`.
- `compare`(W8, ADR-027)는 저장된 분석만 읽는다. 같은 Case, 같은 입력 SHA-256,
  Provider당 하나여야 하며 아니면 `INVALID_AI_REQUEST`다. 기본값은 가장 최근 입력의
  Provider별 최신 분석이다. 출력은 공통 의견(두 Provider 이상)과 개별 의견, Provider별
  요약이며 묶음의 구성원을 모두 보여준다.
- `project validate`는 AI 테이블도 검사한다(scope `ai`): 저장된 입력과 SHA-256 불일치
  (`AI_INPUT_TAMPERED`), 검토 상태와 검토 필드 불일치, 없는 가설·분석 참조, 카운터.
- UI는 저장된 제안을 읽기 전용으로만 보여준다. 검토는 CLI에서만 한다.

## 9. 정적 보고서 사이트 (ADR-029)

```text
workbench report site OUTPUT_DIR
```

- 현재 디렉터리를 Project root로 쓴다. 출력은 `index.html`, `rules.html`,
  `cases/CASE-NNNN.html`이다. 성공 시 페이지 수, Case 수, 비식별화 치환 수를 출력한다.
- 대상이 이미 있으면 `REPORT_OUTPUT_EXISTS`, 쓰기 실패는 `REPORT_WRITE_FAILED`(exit 2).
- 아무것도 공개하지 않는다. 공개 전 검토는 사람이 한다.
