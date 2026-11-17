# Sample Intake CLI / Workflow Contract v1

`CandidateSample`은 `Case`가 아닌 사전 연구 워크플로 객체다. `sample_id`는 불변 연구 식별자이고 SHA-256은 파일 바이트의 동일성을 나타낸다.

## 명령과 전이

`workbench sample`은 `add`, `show`, `list`, `screen`, `eligible`, `exclude`, `validate`, `assign`, `split`, `freeze`, `eval-open`을 제공한다. `add`는 정규 파일을 1 MiB 청크로 읽어 SHA-256만 계산한다. 실행, 심층 검사, 문자열·PE 분석, 복사, 외부 조회 및 Case 생성은 하지 않는다. `add FILE --zip [--password P] [--member NAME]`은 FILE을 비밀번호 ZIP으로 보고 멤버 하나를 메모리로만 읽어 SHA-256을 계산한다(ADR-030). 디스크에 풀지 않고, 압축 오류는 `ARCHIVE_INVALID`·`ARCHIVE_PASSWORD_REJECTED`로 종료 코드 2다. `screen`은 일곱 사실을 기록할 뿐 eligibility를 바꾸지 않는다.

Eligibility는 일곱 criterion pass, unique duplicate status, SHA-256 및 provenance를 요구한다. 배정은 eligible+unique만 허용되고 freeze 뒤에는 변경할 수 없다. Split은 sample ID 순으로 얻은 pool에 seeded shuffle을 적용하며 behavior metadata는 입력으로 쓰지 않는다. family/source가 한쪽에 과반 집중되면 경고한다.

Freeze는 배정된 모든 멤버를 한 트랜잭션으로 고정한다. Eval 멤버는 상세 접근·실행·검증 이력이 없어야 한다. 평가 무결성은 수동 boolean이 아니라 role, freeze 및 exposure timestamps에서 파생한다. `eval-open`은 실행 명령이 아니며 최초 상세 접근 시각과 `evaluation_exposed`만 기록한다.

## 저장소 경계

SQLite schema v1은 stdlib `sqlite3`, `PRAGMA user_version=1`과 명시적 트랜잭션을 사용한다. 일반 `workbench sample` 명령은 현재 디렉터리의 유효한 Project workspace를 열고 `project.json`의 상대 `database.path`가 가리키는 `project.db`를 사용한다. 상위 디렉터리를 검색하거나 기존 `.workbench/sample-intake.db`로 fallback·migration하지 않는다. Sample-owned schema는 처음 사용할 때 같은 DB에 생성되며 Project core schema와 version 기준을 변경하지 않는다. 테스트는 숨김 전역 `--database FILE` 옵션으로 repository 경계를 격리할 수 있다.

## 출력과 종료 코드

Show/list는 text와 JSON을 지원한다. UTC 시각은 초 정밀도의 `YYYY-MM-DDTHH:MM:SSZ`로 저장한다. 검증 성공은 0, 계약 위반은 1, 입력·런타임 실패는 2다. 오류에는 파일 내용이나 절대 경로를 포함하지 않는다.
