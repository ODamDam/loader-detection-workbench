# ADR-023: 탐지 가설·룰·벤치마크·검증 실행 모듈

## 상태

승인 — 2026-11-11 (사용자 승인 범위: 11월 최종 구현 계획 W1·W2).

## 결정

- `detection` 모듈이 Detection Hypothesis, 버전 관리되는 YARA/Sigma Rule, Case 단위
  Benchmark, Validation Run을 담당한다.
- 테이블은 `project.db` 안에 두되 Sample Intake와 같이 **모듈 소유 테이블**로 관리한다.
  핵심 Project/Case/Artifact SQLite 스키마 버전(v2)과 검증기는 변경하지 않고,
  `detection_schema` 테이블이 별도 버전(1)을 기록한다. 최초 쓰기 작업에서 생성되며
  읽기 전용 조회는 테이블이 없으면 빈 결과를 반환한다.
- Case와 Artifact는 핵심 테이블의 내부 ULID를 외래 키로 참조하고, 도메인과 CLI는
  표시 ID(`HYP-`, `RULE-`, `BMK-`, `RUN-`)만 노출한다.
- 무결성: 동결된 Rule version, 동결된 Benchmark membership, 기록된 Validation run과
  result는 서비스 검사와 SQLite trigger로 변경을 막는다. Rule version은 append-only이다.
- 평가 단위는 Benchmark 구성원 Case이다. 역할 `dev`·`unseen`은 악성, `benign_common`·
  `benign_matched`는 정상 기대값을 가진다. YARA는 `sample` Artifact를, Sigma는
  `sysmon` Artifact의 모든 이벤트를 평가한다. 대상 Artifact가 없으면
  `not_evaluable`로 기록하고 FN/TN으로 세지 않는다.
- Unseen을 포함하는 실행은 동결된 Rule version과 동결된 Benchmark를 요구한다. 같은
  Rule에 이전 evaluation이 있으면 이후 Unseen 실행은 `tuning`으로 기록한다.
- YARA는 `yara-python`으로 `include`를 비활성화한 채 메모리에서 검사한다. Sigma는
  pySigma가 해석한 조건 트리를 Sysmon 레코드 필드에 직접 적용한다. 지원하지 않는
  log source·수정자·값 유형은 `UNSUPPORTED_SIGMA_FEATURE`로 실패한다.
- Sysmon 레코드는 기존 Event ID 1/11 정규화(Timeline 계약)와 별도로, 모든 Event ID의
  EventData 필드를 보존하는 `sysmon.records` 파서로 읽는다.

## 결과

- 핵심 스키마 마이그레이션 없이 기존 v1/v2 Project에서 바로 사용할 수 있다.
- 핵심 cross-contract 검증기는 detection 테이블을 아직 검사하지 않는다. 필요하면 후속
  작업으로 추가한다.
- `yara-python`은 Python 3.14용 배포 휠이 없어 이 환경에서는 소스 빌드되었다.
  다른 환경에서는 C 빌드 도구가 필요할 수 있다.
