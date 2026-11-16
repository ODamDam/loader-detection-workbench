# ADR-026: AI 분석 보조의 오프라인 골격 (W7)

## 상태

승인 — 2026-11-17 사용자 일괄 사전 승인(야간 자율 구현의 여유 항목: W7 오프라인 골격,
실제 API 호출 없음, 모듈 소유 테이블). 근거: ADR-004, ADR-009, ADR-022, 11월 최종 구현
계획 v1의 W7.

**이 결정이 다루지 않는 것:** 외부 AI Provider(Claude·GPT·Gemini) 연결과 외부로 보낼
데이터 범위는 아직 승인되지 않았다. 이 ADR은 그 결정 없이도 동작하는 구조만 정한다.

## 배경

11월 계획은 Case 증거를 입력으로 요약·가설 후보·추가 검토사항을 만들고, 관측 사실과 AI
추론을 분리해 저장하며, 사람이 승인해야 반영되게 하도록 정했다. 또 LLM 키가 없어도
전체 파이프라인이 동작해야 한다(ADR-004).

## 결정

1. **모듈과 경계:** `ai` 모듈을 추가한다. `AnalysisProvider` Protocol(`name`, `model`,
   `requires_network`, `analyze(digest)`) 뒤에 Provider를 둔다. 핵심 기능은 이 모듈을
   import하지 않아도 동작하고, AI 테이블이 없으면 조회는 빈 결과를 돌려준다.
2. **입력은 구조 요약뿐이다:** Provider는 `ai.digest`가 만든 `structural` 범위의 요약만
   받는다. 허용 목록 방식이다. 포함: Case 종류, Artifact 표시 ID와 종류, PE 구조(아키텍처,
   섹션 이름·엔트로피·권한, Import DLL·함수 이름, 분석 단서, 지표 **개수**), Sysmon Event
   ID별 개수, 프로세스 트리(이미지 파일 이름, 부모 관계, 활동 개수, 쓴 파일의 확장자),
   VM 실행 런 상태, 기록 개수. 제외: 샘플 바이트, 원본 XML, 추출 문자열과 지표 값,
   명령줄, 디렉터리 경로, 해시, ProcessGuid, 호스트·사용자 이름, Case 이름과 가설 같은
   분석자 자유 서술. 이름 값은 짧은 평문 패턴에 맞을 때만 싣고 아니면 고정 문구로 바꾼다.
3. **입력을 그대로 남긴다:** 요약은 정규 JSON으로 직렬화해 SHA-256과 함께 분석 기록에
   저장한다. `ai preview`는 Provider를 호출하지 않고 같은 입력을 출력한다. 무엇이
   Provider에 전달됐는지 항상 확인할 수 있다.
4. **외부 전송 차단:** `requires_network`가 참인 Provider는 호출 전에
   `AI_PROVIDER_UNAVAILABLE`로 거부한다. 이 빌드에는 외부 Provider 구현이 없다.
5. **오프라인 Provider:** `offline-template`은 언어 모델이 아니다. 요약에 고정 템플릿을
   적용해 요약 1개, 가설 후보, 검토 항목을 만든다. 목적은 키와 네트워크 없이 입력 →
   검증 → 저장 → 검토 → 보고서 흐름 전체를 동작·시험하는 것이다(ADR-004의
   MockProvider 역할). 출력은 다른 Provider와 같은 검증과 검토를 거친다.
6. **출력 검증은 fail-closed이다:** 형식, 개수(최대 16), 길이, 요약 1개 이하를 검사한다.
   Case에 없는 Artifact를 근거로 인용하면 꾸며낸 참조로 보고 출력 전체를 거부한다.
   거부하면 아무것도 저장하지 않는다. Provider 예외는 `AI_PROVIDER_FAILED`로 바꾸고
   예외 원문은 오류 메시지에 싣지 않는다.
7. **관측 사실과 분리 저장:** `project.db`의 모듈 소유 테이블(`ai_schema` v1,
   `ai_analyses`, `ai_suggestions`)에 저장한다. 핵심 스키마 v2와 Artifact, 가설, 룰
   테이블은 바꾸지 않는다. 분석 기록과 제안 내용은 불변이고, 제안의 검토 상태는
   `pending`에서 한 번만 바뀐다(trigger로 보호).
8. **사람의 검토만 반영한다:** 제안은 `pending`으로 저장되고 그 자체로는 아무것도 바꾸지
   않는다. 사람이 `ai accept`로 가설 후보를 수락하면 기존 `DetectionService`로 Detection
   Hypothesis(`proposed`)를 만들고 제안에 그 ID를 기록한다. 가설의 상태 판단과 룰 채택은
   계속 사람이 한다(ADR-009). 요약·검토 항목의 수락은 확인 기록일 뿐이다.
9. **표시:** 보고서는 검증 결과 뒤에 "AI-Assisted Analysis (inference, not observed
   evidence)" 섹션으로 따로 싣고, UI도 같은 경고와 함께 읽기 전용으로 보여준다. 검토는
   CLI에서만 한다.
10. **CLI:** `workbench ai providers|preview|analyze|list|show|accept|reject`.

## 결과

- 새 의존성이 없다. API 키, 네트워크, 외부 서비스 없이 전체 흐름이 동작한다.
- 수락 처리는 가설 생성과 제안 상태 변경이 서로 다른 트랜잭션이다. 두 번째가 실패하면
  가설만 남을 수 있다. 같은 제안의 중복 수락은 상태 조건으로 막는다.
- `project validate`는 아직 AI 테이블을 검사하지 않는다.

## 남은 결정 (사용자 승인 필요)

- 외부 Provider를 연결할지, 연결한다면 `structural` 요약을 그대로 보낼지 더 줄이거나
  넓힐지(예: 지표 값, 명령줄 포함 여부).
- Provider별 모델, API 키 전달 방식(환경 변수), 호출 기록의 보존 범위.
- W8 다중 LLM 비교의 통합 방식.
