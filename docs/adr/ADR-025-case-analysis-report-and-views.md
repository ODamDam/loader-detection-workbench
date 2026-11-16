# ADR-025: Case 분석 조회와 Markdown·HTML 보고서 (W5)

## 상태

승인 — 2026-11-17 사용자 일괄 사전 승인(야간 자율 구현 범위: W5, 핵심 validator 확장, W6
읽기 전용 UI). 근거: ADR-011, ADR-022, ADR-023, ADR-024, 11월 최종 구현 계획 v1의 W5.

## 배경

Case 보고서는 Event ID 1/11 Timeline만 담는 시연용 subset이었다. W1~W4에서 정적 PE
결과, 탐지 가설, 룰 버전, 검증 실행, VM 실행 런이 생겼지만 CLI에서 따로 조회해야 했고,
HTML 출력이 없었다. 학기 목표인 케이스별 보고서 6편은 이 기록을 한 문서로 묶어야 한다.

## 결정

1. **단일 조회 결과:** `report.analysis.CaseAnalysisQuery`가 이미 조회한 `CaseTimeline`을
   받아 같은 Case의 정적 결과, 가설, 연결 룰, 검증 실행, Benchmark 소속, VM 실행 런을
   읽기 전용으로 모은 불변 `CaseAnalysis`를 만든다. 보고서와 웹 UI가 이 결과를 함께
   쓴다. `CaseTimeline`에는 Case에 붙은 전체 Artifact 목록(`artifacts`)을 추가해 Artifact를
   다시 조회하지 않는다. 하나라도 읽지 못하면 조회 전체가 실패한다.
2. **검증 실행 범위:** Case의 가설이 연결한 룰의 모든 실행과, 이 Case가 결과에 포함된
   모든 실행을 싣는다. 룰은 가설 연결 룰과 그 실행들의 룰을 합친 집합이다.
3. **형식 중립 문서:** 보고서는 `report.document`의 블록(제목, 항목, 문단, 표, 코드)으로
   한 번 만들고 Markdown과 HTML 렌더러가 같은 문서를 출력한다. Markdown→HTML 변환
   라이브러리를 추가하지 않는다. 새 의존성은 없다.
4. **호환성:** 기록이 없는 섹션은 생략한다. Sysmon Artifact만 있는 Case의 Markdown은
   이전 출력과 바이트 단위로 같다. `render_markdown(timeline, generated_at)` 호출 형태도
   유지한다.
5. **신뢰 경계:** 블록의 값은 Workbench가 만든 값(`trusted`: 표시 ID, 시각, 개수,
   enum)과 증거에서 온 값으로 나눈다. 증거 값은 두 렌더러가 모두 한 줄로 만들고
   escape한다. 정적 결과 JSON에서 읽은 문자열도 증거 값으로 다룬다. 룰 본문은 코드
   블록으로 싣되 fence 길이를 본문보다 길게 잡는다.
6. **HTML:** inline style만 가진 독립 파일이다. script, 링크, 외부 자원이 없고
   `default-src 'none'; style-src 'unsafe-inline'` CSP meta를 넣는다.
7. **지표 표기:** 탐지 수와 오탐 수는 항상 분모와 함께(`TP/악성 구성원`, `FP/정상
   구성원`) 쓰고 `not_evaluable`은 분모에서 뺀 뒤 따로 센다. development, evaluation,
   tuning 실행은 별도 표로 나눈다. 비율(recall 등)은 보고서에 쓰지 않는다. 구성원 수가
   한 자릿수라 비율이 과하게 읽히기 때문이다.
8. **보고 대상 룰 버전:** 가장 최근 동결 버전, 없으면 최신 초안의 본문을 싣고 어느
   버전인지 명시한다.
9. **VM 실행 런:** 런 상태, VM·스냅샷 이름, 단계 이름과 결과만 싣는다. 단계 상세
   문자열은 하이퍼바이저 오류 원문을 담을 수 있어 보고서에 넣지 않는다.
10. **CLI:** `report build CASE OUTPUT [--format markdown|html]`. 형식을 지정하지 않으면
    출력 이름의 `.html`·`.htm` 여부로 정한다.

## 결과

- 보고서 metadata는 여전히 DB에 저장하지 않는다. 보고서는 판정을 내리지 않는다.
- Unseen 평가의 탐지 판정 단위(룰 단위 vs 가설 단위)는 아직 정하지 않았다. 보고서는 룰
  실행 단위 결과만 싣고 가설 단위 집계를 계산하지 않는다.
- 정적 사이트 생성, Publication Bundle, 공개용 비식별화는 이 결정의 범위가 아니다.
- AI 분석 결과 섹션은 W7에서 관측 사실과 분리해 추가한다.

## 추가 결정: 핵심 validator의 모듈 테이블 검사

ADR-023·024는 detection·execution 테이블을 핵심 cross-contract 검증기 밖에 두었다.
`project validate`가 이 테이블도 읽기 전용으로 검사하도록 `project.module_validator`를
추가한다.

- 각 모듈의 schema 표식 테이블이 있을 때만 검사한다. 핵심 스키마 버전과 기존 finding의
  의미는 바꾸지 않는다. `ValidationScope`에 `detection`, `execution`을 추가한다.
- 원시 행을 SQL로 읽어 검사하고, 도메인 객체 복원 실패에 의존하지 않는다. 손상된 행
  하나가 나머지 검사를 막지 않게 하기 위해서다.
- 동결 불변은 두 층으로 확인한다. 불변 trigger가 남아 있는지, 그리고 저장된 값이
  서로 맞는지(룰 본문과 SHA-256, 실행에 기록된 해시와 룰 버전, Unseen 실행의 동결
  전제, 역할·매치와 결과)이다.
- 끝나지 않은 VM 실행 런과 안전 잠금은 데이터 손상이 아니라 사람이 확인할 VM 상태이므로
  warning이다. Case에서 분리된 Artifact를 가리키는 참조도 warning이다.

## 추가 결정: 읽기 전용 분석·탐지 화면 (W6)

- **범위:** `/cases/<CASE>/analysis`, `/detection`, `/rules/<RULE>`, `/validation/<RUN>`
  네 개의 GET 화면을 추가한다. 가설·룰·벤치마크·검증의 생성과 수정은 CLI에만 둔다.
  11월 계획의 축소 규칙(W6은 읽기 전용 관계 그래프를 최소로 유지)에 따른 것이다.
- **그래프 구현:** 서버에서 열 단위로 노드를 배치하고 곡선 간선을 계산해 inline SVG로
  그린다(`web.graph`). JS 그래프 라이브러리와 CDN을 쓰지 않아 새 의존성이 없고, UI의
  Content-Security-Policy(`default-src 'self'`)를 바꾸지 않는다. 사례당 노드가 수십 개
  수준이라 교차 최소화 같은 자동 배치는 넣지 않았다.
- **프로세스·파일 관계:** `sysmon.relations`가 Event ID 1의 `ParentProcessGuid`와 Event
  ID 11의 `TargetFilename`으로 관계를 만들고, 그 밖의 Event ID는 프로세스별 개수로만
  센다. 기존 Timeline 정규화 계약은 바꾸지 않는다.
- **표시 범위 확장:** 기존 UI는 Image와 대상 파일 이름을 전혀 표시하지 않았다. 관계
  그래프는 노드를 구분해야 하므로 **경로의 마지막 요소(파일 이름)만** 표시한다.
  디렉터리, 명령줄, ProcessGuid, 원본 XML은 계속 숨긴다. 그래프는 프로세스 60개,
  프로세스당 파일 8개까지만 그린다.
- **버전 비교 기준:** Benchmark별로 룰 버전마다 종류별 최신 실행 하나를 쓴다. Case별
  결과 비교는 development 실행만 사용해 Unseen 구성원이 반복 비교에 섞이지 않게 한다.
- **실패 처리:** 읽을 수 없는 기록이 하나라도 있으면 화면 전체가 안전한 오류 코드로
  실패한다.

파일 이름 표시가 과하다고 판단되면 `leaf_name` 한 곳에서 PID만 남기도록 줄일 수 있다.
