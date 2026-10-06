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
