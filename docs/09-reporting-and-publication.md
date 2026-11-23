# 보고서와 공개 정책

## 1. 자동 생성 범위

### 현재 구현: Case Markdown·HTML 보고서 (W5, ADR-025)

`workbench report build CASE-NNNN OUTPUT [--format markdown|html]`은 CLI timeline과
같은 `CaseTimelineQuery` 결과에 `CaseAnalysisQuery` 결과를 더해 보고서를 만든다.
출력 이름이 `.html`·`.htm`이면 HTML, 그 밖에는 Markdown이며 `--format`이 우선한다.

보고서는 한 번 만든 블록 문서(`report.document`)를 두 형식으로 렌더링한다. 따라서
두 형식의 내용은 항상 같다.

**본문은 분석가가 확정한 내용만으로 만든다(ADR-031).** `Confirmed Findings` 섹션에는
`workbench finding`으로 확정한 가설(판정 포함)과 그 연결 근거, 확정 증거 표, 작동 원리
단계만 들어간다. 확정 사항이 없으면 "No finding has been confirmed for this Case."만 쓴다.
초안·취소된 항목과 AI 제안은 본문에 들어가지 않는다.

그 아래 "Appendix A — Recorded Data"에 도구가 기록·계산한 내용이 아래 순서로 이어지고,
AI 분석이 있으면 "Appendix B — AI-Assisted Analysis (inference, not confirmed)"가 붙는다.
기록이 없는 섹션은 생략한다.

1. Case Overview
2. Evidence Summary — Artifact 종류별 수, 기록 수, Benchmark 소속과 동결 여부
3. Static Evidence — 정적 PE 결과(헤더 요약, 섹션 엔트로피·권한, Import, 문자열 지표,
   분석 단서). 서명은 존재 여부만 표시하고 검증하지 않는다. 단서는 판정이 아니다.
4. Timeline / Other Sysmon Events — 기존 Event ID 1/11 관측과 그 밖의 Event ID
5. VM Execution Runs — 런 상태와 단계 이름·결과. 단계 상세 문자열은 싣지 않는다.
6. Detection Hypotheses — 상태, 진술, 정상 대응, 근거 Artifact, 연결 룰
7. Detection Rules — 버전 이력(SHA-256, 동결 시각)과 보고 대상 버전의 본문. 동결된
   버전이 있으면 가장 최근 동결 버전, 없으면 최신 초안을 싣는다.
8. Validation Results — development·evaluation·tuning을 별도 표로 나눈다. 탐지 수는
   `TP/악성 구성원 수`, 오탐 수는 `FP/정상 구성원 수`로 분모와 함께 표시하고,
   `not_evaluable`은 따로 센다. 이 Case의 매치 근거(Artifact·문자열 위치 또는
   Artifact#EventRecordID)를 덧붙인다.
9. Collection / Analysis Limits

Sysmon Artifact만 있는 Case는 개요, 확정 사항, Appendix A의 요약·타임라인, 한계만
나온다. Generated
At은 renderer 인자로 전달해 테스트할 수 있다. 조회 중 하나라도 실패하면(손상된 정적
결과 등) 보고서 파일을 만들지 않는다.

신뢰하지 않는 문자열(Case·가설·룰 이름, XML 값, 샘플에서 추출한 문자열)은 한 줄로
만들고 Markdown 구두점과 HTML 메타문자를 escape한다. 룰 본문은 본문 안의 가장 긴
backtick 연속보다 긴 fence로 감싼다. HTML은 inline style만 쓰는 독립 파일이며
script·링크·외부 자원이 없고 `default-src 'none'` CSP meta를 포함한다. 이 escaping은
공개용 개인정보 비식별화를 대신하지 않는다.

결과는 memory-only projection이며 report metadata를 DB에 저장하지 않는다. 보고서는
악성 판정을 내리지 않는다. Publication Bundle과 자동 공개는 아직 지원 범위가 아니다.

### 현재 구현: 비식별화한 정적 사이트 (M4, ADR-029)

`workbench report site OUTPUT_DIR`은 Project의 모든 Case 보고서와 `index.html`(개요,
정량 목표, Case 목록, 룰별 최신 검증), `rules.html`(룰 버전·본문·검증 실행)을 새 디렉터리에
만든다. 모든 페이지에서 사용자 프로필 이름, 도메인 SID, Sysmon `Computer`·`User` 필드에서
배운 호스트·사용자 이름을 `<user>`·`<host>`·`S-1-5-21-<sid>`로 바꾼다. 페이지 사이 링크는
Workbench가 만든 상대 `.html` 경로만 허용한다. 대상 디렉터리가 이미 있으면 거부하며,
공개는 별도 승인 단계다. 비식별화는 패턴 기반이므로 공개 전에 사람이 검토한다. 파일 게시 정책과 오류는 `06-cli-and-ui-design.md`를 따른다.

### 포함
- 케이스별 Markdown 보고서
- 케이스별 독립형 HTML 보고서
- 전체 케이스 정적 보고서 사이트
- 공개용 정제 데이터 번들

### 제외
- 최종보고서 자동 통합
- 논문 초안 자동 통합

## 2. 보고서 생성 흐름

```text
구조화 분석 데이터
→ 공통 Report Model
→ Markdown
→ 독립형 HTML
→ 정적 사이트
```

Markdown과 HTML은 같은 Report Model을 사용하여 내용 불일치를 방지한다.

## 3. 출력 구조

```text
reports/
├─ markdown/
│  ├─ CASE-001.md
│  └─ ...
├─ standalone/
│  ├─ CASE-001.html
│  └─ ...
└─ site/
   ├─ index.html
   ├─ cases/
   └─ assets/
```

## 4. 케이스 보고서 필수 항목

1. 개요
2. 분석 환경
3. 샘플 메타데이터
4. 정적 PE 분석
5. 초기 실행 타임라인
6. 프로세스·파일·레지스트리·네트워크 행위
7. IOC
8. 정상 대응 비교
9. 탐지 가설
10. YARA 룰과 검증
11. Sigma 룰과 검증
12. 오탐·미탐 분석
13. 한계점
14. 결론

## 5. 정적 사이트 기능

- 프로젝트 개요
- 정량 목표 달성 현황
- 케이스 목록
- 행위·ATT&CK 태그 필터
- YARA·Sigma 검증 상태
- 개별 보고서
- 룰 버전과 검증 결과
- 안전한 공개 자료 다운로드

## 6. 공개 범위

### 기본 공개
- 보고서 전문
- YARA 룰
- Sigma 룰
- 정제된 주요 이벤트
- IOC 요약
- 검증 결과
- 룰 버전 정보

### 비공개
- 실제 악성 샘플
- 드롭된 실행 파일
- 원본 EVTX
- 원본 Procmon 로그
- 원본 PCAP
- 사용자명·호스트명·절대 경로
- API 키·인증정보
- 실제 악성 인프라 재접속 설정
- 재배포 권한이 없는 정상 파일

## 7. Publication Bundle

```text
publication/
├─ reports/
├─ site/
├─ rules/
├─ events/
├─ iocs/
├─ validation/
└─ publication-manifest.json
```

`publication-manifest.json`은 자료별 공개 여부, 비식별화 여부, 해시, 제외 사유를 기록한다.
