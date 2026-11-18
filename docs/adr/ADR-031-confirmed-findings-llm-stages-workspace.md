# ADR-031: 확정 사항 기반 보고서, LLM 2단계 의견, Case 작업 공간

## 상태

승인 — 2026-11-18 사용자 승인("승인, 착수"). 범위는 같은 날 "우선 모두 진행한다고
보자"(동결 최대 2일 연장 허용). 5절 Provider 연결은 아래 "사용자 결정"이 정해진 뒤
구현한다. 근거: ADR-022(범위),
ADR-025(블록 문서 보고서), ADR-026(AI 골격), ADR-027(다중 Provider 비교).

## 배경

중간보고용 UI와 보고서는 수집된 모든 기록과 모든 가설을 그대로 보여준다. 최종 버전의 요구는
다음과 같다.

- Case 단위로 모든 가설과 증거를 관리하고, 같은 화면에서 LLM 3종의 의견을 받는다.
- 보고서는 사람 분석가가 승인·수정해 **확정한 내용만으로** 만든다. 확정 사항을 따로 모아
  관리·확인하는 곳이 필요하다.
- LLM은 의견만 낸다. 수집·분석 중에는 가설 후보, 증거 연결 근거, 추가 분석 지점을 내고,
  증거가 충분히 모인 뒤에는 주요 가설과 근거 목록, 관찰로 알 수 있는 작동 원리 정리를 낸다.
  LLM은 보고서를 쓰지 않는다.

## 결정

### 1. 일정

기능 동결을 2026-11-22에서 최대 2026-11-24로 미룰 수 있다. 이후 Unseen 평가·버그 수정·
문서화 기간은 2026-11-29까지 유지한다.

### 2. 확정 사항(Finding) 모듈 — 새 모듈 소유 테이블

- `findings`(현재 값)와 `finding_revisions`(모든 변경 기록, 추가 전용)를 둔다. 표시 ID는
  `FND-0001`.
- 종류:
  - `hypothesis`: 확정 가설. 제목, 서술, 판정(`supported`·`weakened`·`rejected`). 기존 탐지
    가설(HYP)과 연결할 수 있다.
  - `evidence`: 확정 증거. Artifact(필요하면 EventRecordID)와 그 증거가 보여주는 것에 대한
    분석가의 서술
  - `link`: 증거와 가설을 잇는 근거. 확정 증거 1개 이상과 가설 1개를 참조한다.
  - `mechanism`: 작동 원리 단락. 확정 증거 1개 이상을 인용해야 한다.
- 상태: `draft` → `confirmed` → (`withdrawn`). 확정과 취소는 사람만 한다. 내용을 수정하면
  다시 `draft`가 되고 재확정해야 한다. 모든 전이는 시각과 메모를 남긴다.
- 출처: `analyst` 또는 `ai:AIA-NNNN#n`. AI 제안을 "채택"하면 그 내용으로 `draft`가 만들어지고,
  분석가가 고쳐서 확정한다. 출처는 확정 후에도 남는다.
- 확정할 때 참조하는 Artifact·이벤트·가설·다른 확정 사항이 실제로 존재하고 같은 Case에
  속하는지 검사한다(실패하면 거부). `project validate --scope finding`이 같은 검사를 한다.

### 3. 보고서

- 본문(`Confirmed Findings`)은 확정 사항만으로 만든다. 순서: 개요 → 주요 가설과 판정
  (가설마다 연결 근거와 인용한 확정 증거) → 확정 증거 표 → 작동 원리(How It Works)
- 도구가 기록하거나 계산한 내용은 "Appendix A — Recorded Data"에 둔다. 증거 요약, 정적
  분석, 타임라인, VM 실행, 작업 중인 탐지 가설(HYP), 탐지 룰, 검증 결과가 여기에 들어간다.
  분석가의 결론이 아니므로 확정 대상이 아니다. 동결한 룰은 룰 모듈의 동결 절차가 별도로
  관리한다.
- AI 의견은 "Appendix B — AI-Assisted Analysis (inference, not confirmed)"와 Provider 비교
  표에만 둔다. 확정 사항이 된 내용은
  본문에 분석가의 문장으로 들어가고 출처 표시만 남는다.
- 확정 사항이 없으면 본문에 "확정된 내용 없음"만 쓰고 부록은 그대로 만든다.
- 정적 사이트(ADR-029)도 같은 문서를 쓴다.

### 4. LLM 2단계 의견

`workbench ai analyze CASE --stage collection|synthesis --provider NAME[,NAME...]`

| 단계 | 입력 | 출력 종류 |
| --- | --- | --- |
| `collection` | 구조 요약(ADR-026) | `hypothesis_candidate`(제목·서술·인용), `evidence_link`(주장·인용 2개 이상), `next_step`(무엇을·왜·인용) |
| `synthesis` | 구조 요약 + 확정 사항 목록 | `key_hypothesis`(제목·서술·근거 인용 목록), `mechanism`(단계별 서술, 단계마다 인용) |

- 출력은 단계별 JSON 형식으로 받는다. 형식 위반, 존재하지 않는 인용, 길이 초과, URL·명령 실행
  지시가 있으면 그 분석 전체를 버린다(fail-closed, ADR-026과 같음).
- 같은 입력 SHA-256으로 여러 Provider를 호출하므로 ADR-027 비교가 그대로 동작한다. 비교 기준에
  새 종류를 추가한다.
- 기존 `summary`·`hypothesis`·`review_item` 기록은 그대로 읽힌다.
- **구현(2026-11-18):** 단계는 Provider 입력(digest)의 `stage` 필드에 담는다. 그래서 분석
  테이블은 바뀌지 않고, 제안 종류 CHECK만 AI 스키마 v2에서 넓혔다(v1은 읽기 가능, 첫 쓰기에서
  이전). `synthesis` 입력 범위는 `structural+findings`이고 확정 증거가 1개 이상 있어야 한다.
  인용은 Artifact와 확정 사항 ID다(EventRecordID 인용은 아직 없음). `finding adopt`는
  가설형 제안을 가설 draft로, `mechanism`을 인용한 확정 사항을 참조하는 작동 원리 draft로
  옮긴다. `evidence_link`·`next_step`은 채택 대상이 아니다. 오프라인 Provider가 두 단계를
  모두 만든다.

### 5. Provider 어댑터 3종

- Claude(Anthropic Messages API), OpenAI, Gemini. **새 의존성 없이** 표준 라이브러리 HTTPS로
  호출한다. 각 API의 구조화 출력(JSON) 기능을 쓴다.
- API 키는 환경 변수에서만 읽는다(`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`).
  키는 저장·로그·오류 메시지에 남기지 않는다.
- 외부 전송은 기본으로 꺼져 있다. 설정 파일의 `[ai] allow_network = true`와 명령의
  `--allow-network`가 모두 있어야 호출한다. 접속 대상은 세 API 호스트로 고정한다.
- 호출 기록: Provider, 모델, 입력 SHA-256, 시각, 토큰 수, 소요 시간. 원문 응답은 검증을
  통과한 경우에만 기존처럼 저장한다.
- 테스트는 가짜 HTTP 서버로만 한다. 실제 호출은 사용자가 승인한 시점에 한 번 확인한다.
- **사용자 결정(2026-11-18):** Provider는 **OpenAI(GPT), DeepSeek, Gemini** 세 곳이다(Claude
  대신 DeepSeek). 기준은 최소 성능을 보장하는 저가·무료 모델이고, 모델 이름은 설정으로 바꿀 수
  있다(기본값: OpenAI mini 계열, `deepseek-flash`, Gemini Flash 계열 무료 등급). 보낼 데이터는
  **(가) 구조 요약**이다. `collection`은 `structural`, `synthesis`는 여기에 분석가가 쓴 확정
  사항 문장을 더한 `structural+findings`다. 명령줄, 전체 경로, 사용자·호스트 이름, 해시, 추출
  문자열, 샘플, 원본 로그는 보내지 않는다. 키는 사용자가 이 연구용으로 새로 발급해 환경
  변수(`OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY`)로 설정한다.
  - Gemini 무료 등급은 보낸 내용을 Google이 제품 개선에 쓰거나 사람이 검토할 수 있다.
    DeepSeek은 중국 서버에서 처리한다. 위 범위만 보내므로 개인정보·샘플은 나가지 않는다.
  - 외부 전송 활성화(실제 호출)는 키 설정 후 사용자가 다시 승인한다.
- **구현(2026-11-18):** `ai.external`. OpenAI는 Chat Completions + strict JSON Schema,
  DeepSeek은 같은 형식의 JSON 모드(스키마는 시스템 프롬프트로), Gemini는 `generateContent` +
  `responseSchema`. 표준 라이브러리 HTTPS, 고정 호스트 3개, 응답 1 MiB 제한, 120초 시간 제한.
  호출 조건은 설정 `[ai] allow_network`, API 키, 명령 `--allow-network` 셋 모두다. 외부
  Provider는 단계 요청만 받는다. 토큰 수·소요 시간은 저장하지 않는다(테이블 변경을 피함).
  테스트는 가짜 전송과 `urlopen` 대체로만 했다.
- **실제 호출 확인(2026-11-18, 사용자 승인):** CASE-0001(Amadey dev) `collection`, 같은 입력
  SHA-256(`5db20c90…`)으로 Provider당 1회. OpenAI `gpt-5-mini` 의견 11개(37초), DeepSeek
  `deepseek-flash` 12개(24초), Gemini `gemini-3.8-flash` 9개(27초), 모두 검증 통과·저장
  (AIA-0001~0003). `gemini-2.5-flash`는 신규 사용자에게 제공이 끝나(HTTP 404) 기본값을
  `gemini-3.8-flash`로 바꿨다.
  - 입력 품질: 실제 VM 실행의 119개 프로세스 중 앞의 배경 프로세스만 요약에 들어가 샘플이
    빠지는 문제가 있었다. 프로세스 관계에서 시작된 샘플(`target-*.exe`)과 그 자손, 그 트리가 쓴
    파일 이름으로 실행된 프로세스를 먼저 두도록 고쳤다.
  - 비교 한계: 세 Provider가 같은 내용(실행 파일 드롭·자식 실행, 네트워크 기능, 레지스트리)을
    냈지만 같은 의견 기준(인용 집합 동일 + 제목 단어 겹침 0.5)으로는 공통 의견이 0개였다.
  - Workbench 자체 프로세스 제외(2026-11-19): 모델들이 게스트 실행기 PowerShell을 보고 "샘플이
    PowerShell에서 실행됨"이라는 의견을 냈다. 실행기(`Invoke-WorkbenchGuestRun.ps1`를 실행하는
    PowerShell, 대개 캡처 시작 전에 떠 있어 자식의 `ParentCommandLine`으로 식별)와 그것이 띄운
    프로세스(샘플 트리 제외)를 프로세스 관계에서 `workbench`로 표시하고, 요약에서는 빼고 개수
    (`workbench_processes_excluded`)만 남긴다. 실제 기록의 `wevtutil`은 Defender(MsMpEng)가 띄운
    것이라 정상 Windows 동작이며 그대로 둔다.

### 6. Case 작업 공간 UI

`/cases/<CASE>/workspace` 한 화면에 탭으로 둔다(기존 loopback Flask, CSRF 유지).

- 증거: 수집 Artifact·타임라인·정적 분석 요약. 항목에서 "확정 증거로 등록"
- 가설: 탐지 가설과 확정 가설
- AI 의견: 단계 선택, Provider 3종 결과를 나란히 표시, 공통·개별 표시, 제안별 "채택"·"거절"
- 확정 사항: `draft`·`confirmed`·`withdrawn` 목록, 편집, 확정, 취소, 변경 기록
- 보고서: 확정 사항 기반 미리보기와 내려받기(HTML·Markdown)
- AI 호출 버튼은 네트워크 설정과 키가 있을 때만 활성화하고, 누를 때마다 보낼 내용을 보여주고
  확인을 받는다.
- **구현(2026-11-18):** 한 페이지 탭 5개(`web.workspace`). Provider 어댑터가 아직 없어 AI 호출
  버튼은 두지 않고 CLI 명령을 안내한다. 쓰기는 확정 사항 생성·수정·확정·취소와 AI 제안 채택뿐이다.
  보고서 미리보기는 sandbox iframe이다.

## 사용자 결정 (구현 전에 필요)

1. Provider별 모델: Claude, OpenAI, Gemini 각각 어떤 모델을 쓸지
2. 보낼 데이터 범위: 현재 구조 요약(프로세스 이미지 이름, 활동 수, 파일 확장자, 정적 특징)에
   더해 `synthesis`에서 확정 사항 문장을 보낼지. 명령줄·전체 경로·사용자 이름은 보내지 않는
   것을 권한다.
3. API 키 준비: 사용자가 환경 변수에 직접 설정
4. 외부 네트워크 사용 승인: 세 API 호스트로의 HTTPS 호출
5. 보고서 부록 정책: 객관 기록을 부록으로 남기는 위 안을 그대로 쓸지

## 결과

- 보고서의 의미가 "수집된 모든 것"에서 "분석가가 확정한 것"으로 바뀐다. 기존 `report build`
  출력 형식이 바뀌므로 관련 테스트와 문서를 함께 고친다.
- LLM이 없어도 확정 사항·보고서·UI는 모두 동작한다(ADR-004).
- 새 테이블 두 개가 생기지만 기존 테이블과 형식은 바꾸지 않는다.
