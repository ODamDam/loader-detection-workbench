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
