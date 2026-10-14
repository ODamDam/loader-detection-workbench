# Schema v2 + Manual Evidence Registration 계약

## 1. SQLite 버전 계약

- `project.json`은 schema version `1`, Case Bundle은 version `1`을 유지한다.
- SQLite의 현재 생성 버전은 `2`이며 읽기 가능한 이력은 정확히 `[1]` 또는
  `[1, 2]`이다. 새 Project는 v2로 생성한다.
- 기존 v1 Project를 열거나 Case·Artifact·Sysmon·Timeline·Report 기능을 사용하는
  동작은 DB를 자동으로 변경하지 않는다.
- 수동 증거 기능은 v2만 지원한다. v1에서 호출하면
  `PROJECT_MIGRATION_REQUIRED`로 실패한다.
- 마이그레이션은 `workbench project migrate [ROOT] --to 2`로만 실행한다.
  실제 연구 데이터는 명령 실행 전에 Project 디렉터리 전체를 별도 위치에 백업하고,
  백업을 복원할 수 있는지 확인해야 한다. Workbench는 백업을 자동 생성하지 않는다.
- v1→v2는 하나의 `BEGIN IMMEDIATE` transaction에서 테이블 생성과 migration row
  기록을 수행한다. 실패하면 rollback한 뒤 v1 구조와 이력이 그대로인지 검증한다.
  이미 v2이면 `already-current`를 반환하며 재적용하지 않는다.

## 2. `artifact_provenance` 계약

`artifacts`와 기존 `Artifact` 모델은 바꾸지 않는다. v2는 다음 optional 1:1 테이블만
추가한다.

| 필드 | 계약 |
|---|---|
| `artifact_id` | TEXT primary key, `artifacts.internal_id`를 `ON DELETE RESTRICT`로 참조 |
| `original_filename` | 1~255자, 단일 파일명 |
| `source` | trim 후 1~512자인 분석가 제공 출처 label |
| `description` | NULL 또는 1~2000자 |
| `evidence_type` | `analyst_note`, `event_export`, `configuration`, `tool_output`, `indicator_list`, `other` |

provenance가 있는 Artifact는 `ArtifactKind.EVIDENCE`여야 한다. 수동 등록은 원래
파일명과 메타데이터를 기록하지만 로컬 입력 절대 경로는 DB나 CLI 출력에 기록하지
않는다.

## 3. 등록 서비스 계약

`ManualEvidenceService.register(case_display_id, source_path, *, source,
evidence_type, description=None, original_filename=None)`는 `ManualEvidence`를 반환한다.
반환값은 변경하지 않은 `Artifact`와 별도 `ArtifactProvenance`의 조합이다.

- Open Case만 등록할 수 있다. Case 확인 후 입력 파일을 연다.
- 허용 확장자는 대소문자 구분 없이 `.txt`, `.log`, `.json`, `.xml`, `.csv`,
  `.md`, `.yml`, `.yaml`이다.
- 최대 크기는 4 MiB이며 빈 파일은 허용한다. 이 제한은 수동 증거 등록에만 적용한다.
- symlink/reparse-point 입력은 거부한다. 저장 중 SHA-256과 크기를 다시 검증한다.
- 같은 bytes를 반복 등록하면 canonical 파일은 재사용하고 매번 새 Artifact와
  provenance를 만든다.
- Artifact와 provenance row는 같은 SQLite transaction에서 commit한다. DB 실패 시
  현재 작업이 새로 게시한 미참조 content를 보상 삭제한다. 삭제 자체가 실패하면
  `ARTIFACT_CLEANUP_FAILED`를 반환하며 orphan 가능성을 숨기지 않는다.
- 등록만으로 Sysmon Observation 또는 검증된 관측 사실을 만들지 않는다.

## 4. CLI 계약

```text
workbench project migrate [ROOT] --to 2
workbench case evidence add CASE-NNNN FILE --origin TEXT --type TYPE [--description TEXT]
workbench case evidence list CASE-NNNN
workbench case evidence show CASE-NNNN ART-NNNNNN
```

`add`는 파일 basename을 `original_filename`으로 사용한다. `list`는 Artifact ID,
evidence type, 원래 파일명, SHA-256, 크기를 tab으로 구분한다. `show`는 generic
Artifact 필드와 provenance를 출력하며 로컬 입력 절대 경로는 출력하지 않는다.

## 5. Case Bundle v1 호환성

Bundle v1의 manifest shape은 변경하지 않는다. 수동 증거의 generic Evidence Artifact와
content는 기존 방식대로 포함되고 `restricted`로 분류되지만, `artifact_provenance`는
포함되지 않는다. 따라서 Bundle v1 round trip 후 원래 파일명, 출처, 설명, evidence
type은 복원되지 않으며 `case evidence list`에도 나타나지 않는다.
