# 구현 계획

> 11월 기준선: Notion「11월 최종 구현 계획 v1 — 2026-11-11~11-22」, ADR-022.
> 기능 동결 2026-11-22, 11/23–29는 Unseen 평가·버그 수정·문서화만 수행한다.

## 2026-11-18 ADR-031 최종 버전 범위 (진행 중)

Status: `in_progress` — 1단계(확정 사항 + 확정 기반 보고서) 완료

- 범위: 확정 사항 모듈, 확정 기반 보고서, LLM 2단계 의견, Provider 3종 어댑터, Case 작업
  공간 UI. 동결은 최대 2026-11-24.
- 1단계 완료: `findings` 모듈(모듈 소유 테이블 `findings`·`finding_revisions`), `workbench
  finding add|edit|confirm|withdraw|list|show|adopt`, `project validate`의 `findings` 범위,
  보고서 본문을 확정 사항으로만 구성하고 기록·계산 결과는 부록 A, AI는 부록 B로 분리.
- 2단계 완료: LLM 2단계 의견(`ai analyze --stage collection|synthesis`, 여러 Provider 한 번에,
  AI 스키마 v2, `finding adopt` 확장, 보고서 AI 부록에 단계 표시). 오프라인 Provider로 동작.
- 3단계 완료: Case 작업 공간 UI(`/cases/<CASE>/workspace`, 탭 5개, 확정 사항 생성·수정·확정·
  취소, AI 제안 채택, 확정 기반 보고서 미리보기·내려받기).
- 4단계 완료(실제 호출 전): Provider 어댑터 3종 — 사용자 결정: OpenAI·DeepSeek·Gemini, 저가·무료
  모델(설정 가능), 데이터 범위 (가) 구조 요약. `ai.external`, `[ai]` 설정, `--allow-network`,
  가짜 전송 테스트.
- 실제 호출 확인 완료(사용자 승인): CASE-0001 `collection`, OpenAI·DeepSeek·Gemini 각 1회 성공
  (AIA-0001~0003, 같은 입력). Gemini 기본 모델을 `gemini-3.8-flash`로 변경(2.5는 신규 사용자 404).
  요약에서 샘플 프로세스가 잘리던 문제 수정(샘플 트리 우선).
- 같은 의견 기준 개정(ADR-027 개정): 겹치는 인용 + 행위 주제 일치, 모든 구성원과 일치해야
  묶음. 실제 3사 결과에서 공통 0개 → 9개.
- 설정 파일 BOM 허용(PowerShell 5.1 `Set-Content -Encoding utf8`) 완료.
- Sigma 초안 5개(평가 Project, 동결 전): dev VM 행위에서 작성.
  - RULE-0003 사용자 폴더 프로그램의 `C:\Windows\Tasks\*.job`(Amadey CASE-0002)
  - RULE-0004 비시스템 부모의 Bypass + 인코딩 PowerShell(PureCrypter CASE-0003)
  - RULE-0005 Windows 밖 `msvcp_win.dll`(HijackLoader CASE-0006)
  - RULE-0006 `%TEMP%\<16진 10자리>\*.exe` 실행(Amadey CASE-0001)
  - RULE-0007 `%APPDATA%` 바로 아래 exe 작성(CASE-0002, 0003)
  - BMK-0002(dev 6 + 정상 VM 시나리오 5): 모두 FP 0/5. dev 커버리지 4/6(CASE-0004는 60초
    안 행위 없음, CASE-0005는 단독 실행 시 충돌).
  - 정상 시나리오 5종(CASE-0009~0013) 실행. 180초 실행 3건은 게스트 작업이 360초 여유도
    넘겨 실패, 60초로 재실행해 성공. 게스트 측 지연 원인은 미확인(게스트 출력이 남지 않음).
- 남은 것: 게스트 지연 진단(실패 시 게스트 출력 일부 기록), 룰 최종 채택(사용자 승인),
  확정 사항 작성과 dev Case 보고서.
- 실제 샘플: dev 6건 Case 등록·정적 분석·YARA 초안 2개(Amadey, PureCrypter) 완료.
  - VM: 게스트 비밀번호 만료(11/17 19:04)로 로그인 거부 → 시계를 되돌려 부팅하고 사용자가
    "만료 없음"으로 고친 뒤 `SYSMON-V2-CLEAN` 재생성(이전은 `SYSMON-V2-CLEAN-pwexpired`).
    화면 표시로 켜진 클립보드·드래그앤드롭은 실행 전 점검이 잡아 끄고 다시 만들었다.
  - 실제 샘플은 실행 창 뒤 게스트 작업(기준선, 정리, 내보내기)이 120초를 넘어 guestcontrol
    제한에 걸렸다. 여유를 360초로 늘렸다(`GUEST_RUN_OVERHEAD_SECONDS`).
  - dev 6건 모두 실제 VM 실행 성공(60초): CASE-0001 Amadey VMR-0006(2,385건), CASE-0002
    Amadey VMR-0012(1,040건), CASE-0003 PureCrypter VMR-0013(3,776건), CASE-0004
    PureCrypter VMR-0009(1,666건), CASE-0005 HijackLoader VMR-0014(3,152건), CASE-0006
    HijackLoader VMR-0011(4,012건). 실패한 시도(VMR-0001~0005, 0007, 0008, 0010)는 모두
    샘플 실행 전후로 정리·복원됐고 안전 잠금은 없었다.

## 2026-11-17 봉인 샘플 저장과 암호 ZIP 가져오기 (ADR-030)

Status: `completed` — 실제 샘플은 아직 없음(사용자 확보 대기)

- `artifact.seal`(공개 키스트림 XOR, `LDWSEAL1` 헤더), `ArtifactStore` 투명 봉인·해제,
  `sample` 종류는 항상 봉인. `artifact.archive`(`pyzipper`)로 비밀번호 ZIP을 메모리에서만 읽는
  `case artifact import-zip`과 `sample add --zip`. 게스트 스크립트가 VM 안에서 봉인 해제 후 해시
  확인. 번들은 봉인 상태로 왕복.
- 확보 절차: `docs/26-sample-acquisition-guide.md`(패밀리 3종 이상, dev 6, eval 4~6, 후보
  16~20).
- 미검증: 실제 VM에서 봉인된 sample 실행(PowerShell 단위 테스트와 fake VBoxManage로만 확인).
  다음 시뮬레이터 VM 실행 때 함께 확인한다.

## 2026-11-17 M4 비식별화한 정적 보고서 사이트

Status: `completed` — 로컬 생성까지. 공개는 하지 않음

- `workbench report site OUTPUT_DIR`(`report.site`), `report.redact`, 문서 모델 `Links` 블록,
  ADR-029.
- 실제 데이터: 검증용 Project에서 5페이지, 치환 6,500건. 게스트 사용자명·호스트명·SID 잔존
  0건, script·외부 링크 0건. 처음 구현은 본문의 `a` 모양을 계정으로 추측해 레지스트리
  경로 조각(`Defender`, `State`)을 호스트로 가렸고, Sysmon 필드에서만 배우도록 고쳤다.
- 남은 작업: Publication Bundle(정제 이벤트·IOC·룰·검증 결과·manifest), 행위·ATT&CK 태그.

## 2026-11-17 YARA 정상 비교 파일 세트

Status: `completed`

- `workbench case benign-files CASE-NNNN [--list]`: 고정 목록 `windows-system32-v1`(28개)을
  benign Case에 `sample` Artifact로 등록한다(`detection.benign_files`). 내용 해시로 중복을
  건너뛰고 benign Case가 아니면 `INVALID_CASE_KIND`로 거부한다.
- 검증용 Project: CASE-0003(시스템 바이너리 28개) + 시뮬레이터 Case로 동결 벤치마크를 만들어
  시뮬레이터 YARA 룰이 TP 1/1, TN 1/1임을 확인했다.
- 남은 제약: 평가 단위가 Case라 28개 파일 묶음이 FP 분모 1이다.

## 2026-11-17 M5 무해한 시뮬레이터와 sample 경로 실제 검증

Status: `completed` — 시뮬레이터 Case가 실제 VM 실행부터 보고서·UI까지 완주

사용자 승인(Windows 내장 C# 컴파일러로 빌드, 실제 VM sample 실행 1회)으로 수행했다.
새 패키지 의존성은 없다.

- `tools/simulator/WorkbenchSimulator.cs`(C# 5), `scripts/simulator/Build-WorkbenchSimulator.ps1`,
  리허설 룰 `tools/simulator/rules/`, ADR-028.
- 실제 VM: VMR-0011 sample 경로 성공(이벤트 2,453건). 프로세스·파일·Run 값·자식 프로세스·
  DNS 조회가 기록됐고 TEST-NET 연결(3)은 네트워크 분리로 기록되지 않았다.
- 파이프라인: 가설 HYP-0002 → Sigma(Run 값)·YARA(마커) 룰 동결 → 동결 벤치마크(dev 1,
  benign_common 1) → 검증 Sigma TP 1/1·TN 1/1, YARA TP 1/1(정상 Case는 파일이 없어
  not_evaluable) → 보고서(1.5초) → UI 7개 화면.
- 테스트: 소스 무해성 검사, 컴파일만 하는 빌드 검사(x64 PE, 마커, YARA 매치).
- 남은 작업: JSON 설정 엔진 전환, 정상 YARA 비교용 Windows 시스템 바이너리 Case.

## 2026-11-17 후속: 실제 데이터 리허설·wevtutil 내보내기·AI 검증·W8 비교

Status: `completed` — 로컬 검증과 바뀐 게스트 스크립트의 실제 VM 실행(VMR-0010 성공) 완료. 외부 Provider는 미사용

사용자 지시("전체 프로젝트의 빠른 구현을 목표로 최대한 진행")로 수행했다. 새 의존성과
스키마 변경은 없다.

- **실제 데이터 리허설:** VMR-0009로 수집한 실제 이벤트에 가설 → Sigma 룰(Event ID 13) →
  벤치마크 → 검증 실행 → Markdown·HTML 보고서 → UI 화면을 검증용 Project에서 끝까지
  돌렸다. 룰이 실제 이벤트에 매치됐고(정상 Case라 FP로 집계), 보고서 1.7초, 분석 화면
  0.6초였다. 코드 수정이 필요한 문제는 없었다.
- **게스트 내보내기:** `wevtutil qe`로 전환(294초 → 11초). PowerShell 모의 테스트에 한글
  보존, 빈 결과, DTD 거부, 내보내기 도구 실패를 추가했다.
- **`project validate` AI 검사:** 입력 SHA-256 변조, 검토 상태 불일치, 없는 가설·분석 참조,
  카운터, 스키마·trigger(scope `ai`).
- **W8 (ADR-027):** `ai compare`와 보고서 "Provider Comparison" 표. 저장된 같은 입력의
  분석만 비교하고 Provider를 호출하지 않는다.
- 실제 VM: 사용자 승인 후 VMR-0010 성공(이벤트 2,487건, 실행 단계 3분 43초).
- 남은 작업: sample 경로 실제 검증(benign
  simulator 필요), 외부 Provider 어댑터(데이터 범위 결정 후), 실제 악성 Case 6건과 Unseen 평가.

## 2026-11-17 W4 실제 VM 검증

Status: `completed` — 정상 시나리오 1회 실제 VM 성공(VMR-0009). sample 실행은 미검증

사용자 승인 후 실제 VM에서 `registry-probe`를 반복 실행하며 문제를 고쳤다. 상세 경위는
`docs/25-vm-execution-runbook.md` 6절.

- 코드: 호스트 교환 폴더 권한(`execution.service.host_exchange_directory`), VBoxManage
  `--target-directory` 끝 구분자, 실패 시 VirtualBox 상태 이름만 오류에 기록, 게스트 종료
  코드를 `workbench-exit: N` 출력으로 전달(`guestcontrol run`은 `--wait-stdout`).
- VM: 게스트 계정을 Event Log Readers에 추가, 2 vCPU, Sysmon v2 설정에서 레지스트리
  CreateKey와 Sysmon 자신의 레지스트리 이벤트 제외(사용자 승인, ADR-022 수집 범위 조정).
  스냅샷 `SYSMON-V2-CLEAN`을 다시 만들고 이전 상태는 이름을 바꿔 보존했다.
- 결과: 14단계 모두 `ok`, 이벤트 4,347건, 실행 후 poweroff와 클린 스냅샷 복원 확인,
  `project validate` 통과.
- 남은 위험: 4 vCPU 멈춤의 원인 미확정, 게스트 내보내기(`Get-WinEvent`)가 초당 약 150건이라
  이벤트가 많은 샘플은 제한 시간을 넘길 수 있음(`wevtutil` 전환 후보), sample 경로 미검증.

## 2026-11-17 W5 보고서·validator 확장·W6 읽기 전용 UI·W7 오프라인 골격

Status: `completed` — 로컬 구현·합성 fixture 검증 완료. 실제 VM·샘플·외부 AI Provider 미사용

사용자의 일괄 사전 승인(야간 자율 구현) 범위에서 수행했다. 새 의존성은 없고 핵심
스키마 v2는 변경하지 않았다.

- **W5 (ADR-025):** `report.analysis.CaseAnalysisQuery`가 정적 결과, 가설, 룰, 검증 실행,
  Benchmark 소속, VM 실행 런을 한 번에 모은다. `report.document`의 블록 문서를 Markdown과
  독립형 HTML로 렌더링한다. `report build CASE OUTPUT [--format markdown|html]`. 검증
  수치는 분모와 함께 표시하고 development·evaluation·tuning을 나눈다. Sysmon만 있는
  Case의 Markdown은 이전과 바이트 단위로 같다.
- **validator 확장:** `project validate`가 detection·execution 모듈 테이블을 읽기 전용으로
  검사한다(`project.module_validator`). 불변 trigger 누락, 카운터, 깨진 참조, 동결된 룰
  버전 변조, 동결 전제 없는 Unseen 실행, 불가능한 결과를 찾는다. 끝나지 않은 VM 런과
  안전 잠금은 warning이다.
- **W6 (ADR-025):** `/cases/<CASE>/analysis`(증거 → 가설 → 룰 → 검증 그래프, 프로세스·
  파일 그래프, VM 런), `/detection`, `/rules/<RULE>`(버전 비교), `/validation/<RUN>`.
  서버에서 배치한 inline SVG이며 script와 외부 자원이 없다. 편집 기능은 넣지 않았다.
  프로세스·파일 그래프는 파일 이름(경로의 마지막 요소)만 표시한다.
- **W7 골격 (ADR-026):** `ai` 모듈. 구조 요약 입력, `offline-template` Provider(언어 모델
  아님), fail-closed 출력 검증, 추론 분리 저장(`ai_schema` v1), 사람이 수락한 가설
  후보만 Detection Hypothesis로 반영. CLI `ai providers|preview|analyze|list|show|accept|
  reject`. 외부 전송이 필요한 Provider는 호출 전에 거부한다.
- 검증: 전체 pytest 597 passed / 1 skipped(신규 63), Ruff lint/format, strict mypy `src`
  94개 파일과 신규 테스트, `uv lock --check`, `git diff --check`. UI는 합성 Project를
  로컬 브라우저에 띄워 분석·룰 비교·검증 실행 화면을 눈으로 확인했다(W7 섹션 추가
  이후의 화면은 자동 테스트로만 확인). PowerShell 테스트는 대상 스크립트를 바꾸지 않아
  재실행하지 않았다.
- 남은 작업: 실제 VM 검증(SYSMON-V2-CLEAN 생성 후 정상 시나리오 1회), 외부 Provider
  연결과 전송 데이터 범위 결정, W8 다중 LLM 비교, AI 테이블의 `project validate` 검사,
  Unseen 탐지 판정 단위 결정, 실제 Case로 보고서 6편 생성.

## 2026-11-12 W4 VM 실행 런·클린 스냅샷 복원

Status: `completed (mock)` — 모의 VBoxManage·PowerShell mock 검증 완료, 실제 VM·샘플 미실행

- ADR-024(D1~D3 승인): `execution` 모듈. `Hypervisor` Protocol + `VBoxManageHypervisor`
  (shell 없는 인자 목록, 비밀번호는 호출별 임시 `--passwordfile`), 모듈 소유 테이블
  `execution_schema` v1(런·단계 append-only, 끝난 런 불변, 안전 잠금 1행·해제 이력).
- 흐름: 승인(`--approve`) → 잠금·미종료 런 확인 → 사전 점검(전원 꺼짐, 스냅샷 존재, NIC
  분리, sample은 공유 폴더·클립보드·DnD 금지) → 복원·확인 → 복원 설정 격리 재확인 →
  headless 시작 → Guest Additions 준비 → 반입 → 제한 시간 실행 → `<Events>`·매니페스트 회수 →
  SHA-256·run ID·대상·EventRecordID 범위 검증 → 전원 끄기 → 복원·확인 → `sysmon`·`other`
  Artifact 등록. 실패 시 전원 끄기·복원, 복원 실패는 잠금과 `SNAPSHOT_RESTORE_FAILED`.
- 게스트 스크립트 `execution/guest/Invoke-WorkbenchGuestRun.ps1`(패키지 데이터): 게스트 해시
  재검증, 전체 제한 시간 관찰 후 프로세스 트리 종료, 기준 이후 모든 Sysmon 이벤트 내보내기.
  고정 정상 시나리오 5개. 데모용 `Invoke-SysmonDemoCollection.ps1`은 변경하지 않았다.
- CLI `vm preflight|scenarios|run|scenario|status|show|list|unlock`, `--dry-run`은 VM 명령 없음.
- 문서: ADR-024, `docs/25-vm-execution-runbook.md`, docs/07·24(스냅샷 전 격리 설정 추가)·14·00, README 12절.
- 검증: pytest 534 passed / 1 skipped(신규 32), PowerShell guest-run 44·demo 53 checks, Ruff
  lint/format, strict mypy `src`+신규 테스트 82개 파일, `uv lock --check`, `git diff --check`.
  host/repeat PowerShell 테스트는 대상 스크립트 미변경으로 재실행하지 않았다.
- 남은 작업: 사용자가 `SYSMON-V2-CLEAN` 생성(현재 VM은 클립보드·DnD 양방향, 공유 폴더 있음 →
  docs/24 5절), 게스트 계정 준비 후 승인받아 정상 시나리오 1회 실제 검증. 실제 VBoxManage의
  `guestcontrol run` 종료 코드 전달 방식은 그때 확인한다. commit/push는 사용자 요청 대기.

## 2026-11-11 W3 정적 PE 확장·다중 Event ID Timeline

Status: `completed` — 로컬 구현·합성 PE/Sysmon fixture 검증 완료, 실제 샘플·VM 미사용

- 정적 분석 결과 schema v2(`workbench-pe` 2): 파일·섹션 엔트로피와 X/W 권한,
  `pefile` 2024.8.26 기반 Import(상한 256 DLL/4096 함수)·imphash·Export·
  compile timestamp·entry point·subsystem·overlay·서명 존재 여부(검증 안 함),
  ASCII/UTF-16LE 문자열(2000개 상한)과 지표(url·ipv4·registry·windows_path·
  executable_name·script_keyword), 분석 단서 flag. flag는 판정이 아니다.
  v1 결과는 그대로 읽힌다. UI는 windows_path 값과 원문 문자열 목록을 노출하지 않는다.
- Timeline: 단일 Event ID 1/11 문서는 기존 정규화·오류 계약을 그대로 쓰고,
  `<Events>` 다중 이벤트나 다른 Event ID는 공통 파서로 읽는다. 컨테이너 안 ID 1/11은
  같은 필수 필드 규칙으로 typed 관측으로 바꾸고, 나머지는 `other_records`로
  CLI·Markdown 보고서·UI Timeline에 표시한다(UI는 실행 파일·대상 경로 제외).
- 검증: pytest 502 passed / 1 skipped(신규 11), Ruff lint/format, strict mypy
  `src`+신규 테스트 80개 파일, `uv lock --check`, `git diff --check` 통과.

## 2026-11-11 W1·W2 탐지 가설·룰·벤치마크·검증 엔진

Status: `completed` — 로컬 구현·무해한 합성 fixture 검증 완료, 실제 샘플·VM 미사용

- 브랜치 `feat/detection-validation-core`(기준 `ef50cf9`). ADR-022(범위),
  ADR-023(모듈 설계)을 추가했다.
- `detection` 모듈: Hypothesis(근거 Artifact·룰 연결, 상태), 버전 관리 YARA/Sigma
  Rule(draft→frozen, append-only), Case 단위 Benchmark(dev·unseen·benign_common·
  benign_matched, 동결), Validation Run(TP/FP/FN/TN·not_evaluable·매치 근거,
  development/evaluation/tuning 구분).
- 테이블은 `project.db`의 모듈 소유 테이블(`detection_schema` v1)이며 핵심
  스키마 v2와 검증기는 변경하지 않았다. 동결·기록 데이터는 trigger로 보호한다.
- `sysmon.records`: 모든 Event ID의 EventData 필드를 보존하는 파서(단일 Event와
  `<Events>` 컨테이너). 기존 ID 1/11 Timeline 정규화는 그대로 둔다.
- YARA `yara-python` 4.5.4(include 비활성, 메모리 검사), Sigma pySigma 1.5.1 해석
  트리 오프라인 평가(수정자 contains/startswith/endswith/all/re/cidr/gt·gte·lt·lte/
  exists/cased, null, 키워드, `1 of`/`all of`/not). 미지원은 fail-closed.
- CLI: `rule`, `hypothesis`, `benchmark`, `validate` 그룹.
- 사용자 VM 작업용 `scripts/vm/sysmon-config-workbench-v2.xml`과
  `docs/24-sysmon-v2-vm-snapshot-procedure.md`를 추가했다(실행은 사용자).
- 검증: 전체 pytest 491 passed / 1 skipped(신규 20), Ruff lint/format, strict mypy
  `src`+신규 테스트 76개 파일, `uv lock --check`, `git diff --check` 통과. 기존 테스트
  일부 파일의 mypy 오류는 이번 변경 이전부터 존재한다.
- 남은 작업: 핵심 validator의 detection 테이블 검사, 보고서·UI 연동(W5·W6),
  Collection helper의 전체 Event ID 내보내기(W4). commit/push는 사용자 승인 대기.

## 2026-10-14 Flask 기본 플랫폼 UI

Status: `completed` — 로컬 구현·공개 합성 검증 완료, 실제 VM/민감 자료 미사용

- Flask/Flask-WTF/Waitress 기반 server-rendered UI를 기존 Application Service
  위에 추가한다. 고정 Project, loopback bind, Case/Artifact/provenance, Manual
  Evidence upload, 안전한 Sysmon Timeline만 범위에 포함한다.
- 직접 SQLite, 신규 schema, 브라우저 Project 선택, evidence download/raw preview,
  Markdown preview, VM·AI·rule UI는 제외한다.
- ADR-021과 `docs/local-platform-ui-contract.md`를 기준으로 CSRF, Host/Origin,
  escaping, 요청 크기, 임시 파일 정리와 경로·명령 비노출을 검증한다.
- `workbench ui serve [ROOT] --port PORT`는 Project를 bind 전에 검증하고
  Waitress를 `127.0.0.1`에만 바인딩한다. v1은 조회만 지원하며 등록은 기존
  `PROJECT_MIGRATION_REQUIRED`로 차단한다.
- 전체 pytest 465건, Ruff lint/format, strict mypy `src` 63개, lock 검사와
  Windows wheel 임시 설치·template/CSS 렌더링 검사가 통과했다. PowerShell guest
  53건·host 415건·repeat 70건도 공개 합성/mock만 사용해 통과했다.
- 기존 DB schema, Artifact/Bundle/Collection 계약과 PowerShell 스크립트는 변경하지
  않았다. commit/push/merge를 수행하지 않았고 보호된 미추적 파일 3개를 보존했다.

## 2026-10-14 Existing Case Sysmon Collection Ingestion

Status: `completed` — 로컬 구현·공개 합성 검증 완료, 실제 VM/Collection 미실행

- Python `CollectionValidator`가 Host demo의 정확한 3파일 layout, metadata,
  SHA-256, Sysmon Event ID 1/11 identity와 correlation을 검증한다. 기존 Sysmon
  normalizer와 XML 1 MiB 제한을 유지하며 검증된 동일 bytes만 저장 단계로 넘긴다.
- `CollectionIngestionService.import_collection(case_id, directory)`는 기존 Open
  Case에 Process/File XML을 `sysmon`, metadata를 `other` Artifact로 등록한다.
  v1/v2를 모두 지원하며 DB schema와 dependency는 변경하지 않았다.
- 동일 Case·kind·SHA-256 후보는 canonical content 무결성과 XML 역할을 재검증한
  뒤 재사용한다. 전체 재시도와 metadata-only 변경 모두 Sysmon Artifact 및 Timeline
  observation을 중복 생성하지 않는다.
- 세 Artifact의 누락 행과 counter 변경은 한 SQLite transaction에서 처리한다. 실패
  시 rollback 후 작업이 새로 게시한 미참조 content만 보상 삭제하며 정리 실패는
  `ARTIFACT_CLEANUP_FAILED`로 보고한다.
- Manual Evidence provenance, Case Bundle v1, Timeline/Report 형식, Host/Repeat
  PowerShell 스크립트는 변경하지 않았다. Collection/Execution Run 영속 모델은 후속
  범위로 남겼다.
- 검증: pytest 450건, Ruff lint/format, mypy `src` 58개, offline lock 검사,
  PowerShell guest 53건·host 415건·repeat 70건이 통과했다. 모든 검증은 공개 합성
  fixture/mock만 사용했고 실제 VM, private Collection, 분석 대상은 실행하지 않았다.
- commit/push/merge와 DB migration은 수행하지 않았고 AI-E3 미추적 문서 2개와
  `migration-note.txt`를 보존했다.

## 2026-10-14 Schema v2 + Manual Evidence Registration Service

Status: `completed` — 로컬 구현·합성 검증 완료, 실제 Project migration 미실행

- 새 Project는 SQLite v2로 생성하고 기존 v1/v2를 모두 읽는다. v1은 열기나 기존
  M0~M2 사용 시 자동 migration하지 않으며 `project migrate --to 2`만 명시적으로
  v2로 올린다. 실패 주입에서 DDL과 migration history rollback 및 원본 v1 검증을
  확인했다. 실제 연구 데이터는 migration 전 별도 백업이 필요하다.
- 기존 Artifact 모델과 Case Bundle v1 shape은 변경하지 않고 optional 1:1
  `artifact_provenance`를 추가했다. Bundle v1은 generic Evidence Artifact와 content를
  유지하지만 provenance는 보존하지 않는다.
- Manual Evidence Service는 Open Case, 허용 확장자, 4 MiB, provenance metadata를
  검증하고 `ArtifactKind.EVIDENCE`로 등록한다. Artifact/provenance는 같은 SQLite
  transaction에서 commit하며 DB 실패 시 새 미참조 content를 보상 정리한다.
- 동일 bytes는 canonical content를 공유하되 Artifact/provenance row는 새로 만든다.
  수동 등록은 Sysmon Observation이나 검증된 관측 사실을 자동 생성하지 않는다.
- `project migrate`, `case evidence add/list/show`, version-aware validator, ADR-019,
  계약·사용자·테스트 문서를 추가했다. production/build dependency 변경은 없다.
- 검증: pytest 426건, Ruff lint/format, mypy `src` 54개, offline lock 검사,
  PowerShell guest 53건·host 415건·repeat 70건이 모두 통과했다. PowerShell 검사는
  합성/mock 경로만 사용했으며 실제 VM, private collection, 분석 대상은 실행하지 않았다.
- 기준 branch와 HEAD는 유지했고 commit/push/merge 및 실제 Project DB migration은
  수행하지 않았다. AI-E3 미추적 문서 2개와 `migration-note.txt`는 변경하지 않았다.

## 2026-10-13 AI-E2 Behavioral Feature Logistic Regression Baseline

Status: `completed` — 단일 고정 Logistic Regression 합성 baseline 구현·실행 완료

- 범위는 `experiments/ai/`의 합성 Case Summary v0.1 실험과 development
  dependency·계획 문서에 한정한다. Workbench core, CLI, parser, DB, VM 및 외부
  AI Provider는 변경하거나 실행하지 않는다.
- 원본 13행에서 완전히 동일한 `C010` 중복 1행만 제거해 12개 고유 Case를 사용한다.
  exact-row 제거 후 Case ID가 중복되면 conflicting record로 fail-closed 처리한다.
- 승인된 8개 behavioral feature만 고정 순서로 사용한다. `case_id`, `pool`,
  `telemetry_quality`는 audit metadata로 분리하고 `label`은 target으로만 사용한다.
- `random_state=42`, `test_size=1/3`, label stratification으로 Case-disjoint split을
  만들고, training 8건에만 median imputer, scaler, 단일 Logistic Regression을 fit한다.
  test 4건은 한 번의 최종 평가에만 사용하며 모델 선택이나 tuning을 수행하지 않는다.
- 실제 합성 fixture 결과: train label 0/1은 5/3, test는 3/1이다. test confusion
  matrix(label 순서 `[0, 1]`)는 `[[2, 1], [1, 0]]`, precision/recall/F1은 모두
  `0.0`이다. 이 실행에서 undefined metric은 없다.
- 결측 `dns_query_count`는 training median으로 대체하되 관찰된 행위 부재나 0으로
  해석하지 않는다. partial telemetry인 `C011`도 유지하며 별도 품질 한계로 기록한다.
- 저장 결과와 동일 환경 재실행 2회의 JSON이 byte-identical이었다. 결과에는 실행
  시각, UUID, 절대 경로가 없으며 원본 fixture SHA-256도 실행 전후 동일했다.
- 이 결과는 12개 합성 Case와 4개 test Case에만 해당한다. 실제 악성코드 탐지 성능,
  일반화 성능 또는 최종 unseen 평가 결과로 해석하지 않는다.
- 별도 미완료 연구 항목: 실제 악성코드 탐지 성능과 최종 unseen dataset 평가는 이번
  최소 구현의 완료 범위에 포함하지 않으며, 별도 연구 결정·데이터·승인 후 검증한다.
- scikit-learn은 기존 선언이 없어 development dependency에만 추가했다. production
  dependency와 Workbench core는 그대로 유지한다.
- AI-E2 전용 pytest 11건과 기존 회귀 392건, lock, Ruff lint/format, 공식 mypy
  `src` 및 AI 파일 strict mypy가 통과했다. 추가 mypy `src tests`에서는 기존
  Artifact 테스트 오류 6건만 재현했다.
- `migration-note.txt`와 원본 CSV를 보존하고 commit/push는 별도 승인 전 수행하지 않는다.

## 2026-10-13 Host-side Sysmon E2E automation

Status: `completed` — 수정 후 단일 실제 Host 자동화 E2E PASS

- 기준선: `d902576f0649fddb0536da36e1230fdc1a5626bc`, 현재 feature branch.
- 사용자 조건부 승인: 원본 collection 읽기 전용, 독립 임시 복사본만 검증·등록,
  복사 전후 원본 구성/해시/크기/수정 시각 비교, CLI 필수 정보 검증, 부분 실패 보존.
- 변경 범위는 `scripts/Invoke-SysmonHostDemo.ps1`,
  `tests/powershell/Test-SysmonHostDemo.ps1`, `PLANS.md`, `README.md`,
  `docs/23-virtualbox-sysmon-export-helper-handoff.md`의 5개 파일이다.
- 새 Project/benign Case, Sysmon Artifact 2개, timeline 및 Markdown을 기존 CLI로
  연결한다. 진단은 상태/단계/안전한 코드로 제한하고 원문 출력은 콘솔에 노출하지 않는다.
- PowerShell 합성 fixture/mocked CLI로 정상·오류·부분 실패를 검증한다.
  pytest, Ruff lint/format, mypy src, 기존/신규 PowerShell 검사와 diff를 확인한다.
- 실제 VM/guest/분석 실행, 네트워크·정책·CLI·parser·DB·dependency 변경은 제외한다.
  `migration-note.txt`를 보존하며 이번 작업의 commit/push는 승인되지 않았다.
- 첫 실제 Host 자동화 실행은 collection 검증과 복사를 통과하고 Project를 생성했으나
  `project` 단계에서 `CLI_FAILED`, `cli_exit: null`로 중단됐다. Project manifest와
  DB가 존재해 CLI 자체는 성공했으며, 부분 산출물은 보존했다.
- 원인은 Windows PowerShell 5.1에서 함수 로컬 `$LASTEXITCODE` sentinel이 native
  process가 기록한 global 값을 가린 것이고, `$?`도 배열 할당 뒤 너무 늦게 읽었다.
  global sentinel과 native 호출 직후 상태 캡처로 수정하고 실제 `cmd.exe` exit 0/7,
  stale code, stdout, 실행 파일 부재와 `workbench.exe --version`을 회귀 검증했다.
- 검증: pytest 392건, 기존 guest helper 모의 검사 53건, 신규 host 검사 415건 PASS.
  lock, Ruff lint/format, mypy src(47 files), PowerShell 구문과 diff 검사 통과.
  추가 mypy src tests는 기존 Artifact 테스트 오류 6건만 재현했다.
- 수정 후 사용자 실제 E2E 확인: `success / complete / OK`, PowerShell exit 0,
  collection/Project 디렉터리, `diagnostic.json`, `timeline.txt`, Markdown 보고서 1개와
  필수 보고서 섹션 4개가 생성됐다. 실제 산출물과 경로는 Git에 포함하지 않는다.
- 자체 리뷰 완료. 자동화의 실제 E2E 성공은 1회이며 반복 실행 신뢰성은 미검증이다.
  입력의 변경 후 원복 경쟁까지 증명하는 원자적 snapshot이나 CLI 강제 timeout은
  제공하지 않는다. 조용한 입력 디렉터리와 신뢰할 수 있는 로컬 출력 위치를 전제로 한다.

## 2026-10-13 Host-side Sysmon repeat validation

Status: `completed` — 합성 및 기존 benign VM collection Host 반복 검증 PASS

- 기존 Host 스크립트의 새 결함은 확인되지 않아 변경하지 않았다. 반복기는 기존
  스크립트를 독립 `powershell.exe` process로 호출하며 회차별 고유 run/Project를 만든다.
- 변경 범위는 `scripts/Invoke-SysmonHostDemoRepeat.ps1`,
  `tests/powershell/Test-SysmonHostDemoRepeat.ps1`, `PLANS.md`, `README.md`,
  `docs/23-virtualbox-sysmon-export-helper-handoff.md`의 5개 파일로 제한한다.
- 반복 전후 원본 snapshot, 실행별 copy, CLI Artifact SHA-256, `project validate --full`,
  저장 timeline 재조회, Artifact/EventRecordID provenance와 보고서 4개 섹션을 검증한다.
- Project/Case/Artifact ID, run 경로와 보고서 `Generated At`만 정규화하고, 나머지
  timeline/report 내용은 메모리 내 canonical digest로 비교한다. digest와 원문은 안전한
  batch diagnostic에 기록하지 않는다.
- 공개 합성 Event ID 1/11 collection으로 설치된 Workbench CLI Host E2E를 독립
  process에서 2회 실행했다. 신규 반복 테스트 70건과 기존 Host 테스트 415건,
  전체 pytest 392건, Ruff, `mypy src`, offline frozen lock 검사가 PASS했다.
- 첫 private collection 반복 시도는 분석 실행 전에 `Split-Path` 빈 문자열 오류로
  종료됐다. 반복 스크립트의 계산식 기본값이 안전한 오류 경계 밖에서 `$PSScriptRoot`를
  사용했고, script-scope Host helper import가 반복 스크립트의 입력 매개변수를 덮어쓰는
  진입점 결함도 확인했다. 계산식 기본값을 제거하고 script root/경로를 선검증하며,
  import 전후 입력을 보존·복원하고 정상·실패 stdout을 단일 JSON으로 고정했다.
- Phase A의 제한된 read-only 확인에서는 보존된 Host run 2개와 유효 collection copy
  2개를 확인했지만 collection fingerprint는 하나였다. 성공 run의 Project full validation,
  timeline 재조회, provenance와 보고서 섹션을 확인했고, 기존 실패 run의 collection과
  Project도 보존돼 있었다. 이는 새 반복 E2E 실행 횟수로 계산하지 않는다.
- 수정 후 사용자가 기존 benign VM collection을 재사용해 반복 Host E2E batch 1개를
  실행했고, 독립 Host 처리 2회가 모두 `success / complete / OK`로 완료됐다. 요청/완료
  횟수는 2/2이고 실패 회차는 없으며, 원본 불변, 복사본·Artifact hash, Project full
  validation, Timeline·provenance 의미적 일관성, 보고서 일관성과 안전한 diagnostic 기록이
  모두 확인됐다. 이는 같은 기존 collection의 Host 재처리이며 새 Guest 수집 2회를 뜻하지
  않는다. 새 Guest/VM 또는 악성 샘플 실행은 없었다.
- 실패한 최초 private 반복 시도는 성공 횟수로 계산하지 않는다. 실제 기록은 기존 단일
  Host E2E 성공 1회와, 수정 후 같은 기존 collection을 사용한 반복 batch 1개/Host 처리
  2회 성공으로 구분한다.
- Core/CLI/DB/parser/dependency와 AI-E2/AI-E3 파일은 변경하지 않고 runtime evidence는
  Git 밖에 둔다. 실패하면 후속 회차를 중단하며 완료·부분 run을 삭제하지 않는다.

## 2026-10-06 VirtualBox Sysmon collection/export helper

Status: `completed` — 단일 helper 수집의 수동 E2E 범위 (2026-10-13)

- 사용자 확인: VirtualBox Windows 11 + Guest Additions에서 실제 benign Event ID
  1/11의 same ProcessGuid/PID 관계, 단일 XML export, Shared Folder 전달,
  Workbench Artifact/timeline/Markdown manual E2E가 성공했다. Parser 수정은 불필요하다.
- ADR-018로 active hypervisor를 VirtualBox로 갱신한다. 과거 VMware 조사 기록은
  보존하며 adapter 추상화도 유지한다. VM/guestcontrol 자동화는 제외한다.
- 승인 범위: guest PowerShell helper, 고유 run/child, baseline 이후 정확한 pair
  선택, atomic no-overwrite export와 metadata, report source-neutral 문구.
- syntax/static 및 합성 모의 검증은 Host에서 수행했다. 2026-10-06의 직접 guest
  접근 부재로 인한 차단은 2026-10-13 사용자 수동 검증으로 단일 E2E 범위에서 해소됐다.
- 인계: `docs/23-virtualbox-sysmon-export-helper-handoff.md`.
- 구현과 host 검증 완료: PowerShell parser 및 모의 검사 53건, targeted Python
  67건 (Sysmon 54건 포함), 전체 pytest 392건 (당시 host 검증 기록).
- 2026-10-13 사용자 확인: 첫 helper 실행 exit 0, 정확히 3개 출력, Event 1/11의
  ProcessGuid/PID 및 record 순서, metadata/XML 해시, 기존 Shared Folder 전달과
  host 복사본 해시 PASS. 임시 Project/benign Case, XML Artifact 2개, provenance가
  있는 timeline 2건, 보고서 섹션/한계, 재생성 거부와 원본 해시 보존, timeline 반복
  결과 동일성을 확인했다. 두 번째 독립 실행은 exit 0/guest 출력 3개까지만 PASS다.
- 첫 guest 수집 당시 사용자는 Process 범위의 임시 ExecutionPolicy Bypass를
  사용했다. 영구 정책 변경은 아니며, 향후 승인되지 않은 정책 우회를 권장하지 않는다.
  정확한 실행 명령과 향후 정책 준수 지침은 위 인계 문서에 구분해 기록한다.
- 두 번째 수집의 전달/Workbench E2E, 반복 전체 E2E와 VM lifecycle 자동화는
  완료로 주장하지 않는다. 자동화는 미구현이며 이번 변경은 문서/데모 명령에 한정한다.
- lock, Ruff lint/format, 공식 mypy src 및 변경 테스트 mypy, diff check 통과.
  전체 mypy는 기존 Artifact 테스트 오류 6건만 재현했고 신규 오류는 없다.

## 2026-10-06 Demo Freeze / VM Sysmon readiness

Status: `verification_blocked`

과거 VMware 조사 시점의 상태다. 이후 VirtualBox 단일 helper E2E 차단 해소는
위 2026-10-13 갱신 및 `docs/23-virtualbox-sysmon-export-helper-handoff.md`를 따른다.

- 기준선 `731026b5e6e21c3c8ed5d823f47a900c8b4df4a0`에서
  `feat/vm-sysmon-collection-20261006` branch로 분리했다.
- 새 임시 Project에서 설치된 CLI로 synthetic Artifact 2개 등록, timeline,
  Markdown section/provenance 확인, overwrite 거부와 원본 byte 보존을 검증했다.
  **OFFLINE DEMO FROZEN**. 제품 코드와 parser는 변경하지 않았다.
- VMware 실행 파일을 PATH/기본 설치 위치에서 찾지 못했고, 설치 등록·서비스·
  프로세스·VM inventory도 확인되지 않았다. 별도 설치 위치 또는 다른 PC의
  Windows VM 환경 확인이 필요하다. VM 자체가 어디에도 없다고 단정하지 않는다.
- VM boot, guest Sysmon 설치/서비스/config/log, export/transfer 및 real-VM
  Workbench E2E는 미실행이다. Level 1의 VM 항목과 Level 2는 미완료다.
- automation은 만들지 않았다. 설치·네트워크 변경·credential 사용·실제 로그
  업로드도 없다. 상세 증거와 다음 기기 시작점은
  `docs/22-vm-sysmon-collection-handoff.md`에 기록한다.

## 2026-10-06 Case Timeline / Markdown Report

Status: `completed`

- 승인 기준선 `b23644c1f8a1b61224e50f0fea959e5ec4d93844`에서
  `feat/case-timeline-report-20261006` branch로 분리했다.
- CaseTimelineQuery가 attached Sysmon을 기존 서비스로 정규화·정렬하며,
  CLI timeline과 Markdown renderer는 같은 immutable query result를 소비한다.
- `case timeline`, `report build`, fail-closed 오류, empty 성공, 안전한 text escaping,
  no-overwrite 파일 게시와 시연 E2E를 구현했다. DB/schema/dependency 변경은 없다.
- 신규 targeted 21개, Sysmon 회귀 54개, 전체 392개 테스트 통과. lock, Ruff lint/format,
  공식 mypy src, 신규 테스트 mypy와 diff check 통과. 전체 mypy의 기존 Artifact
  테스트 오류 6건은 그대로이며 신규 오류는 없다.
- 인계 및 합성 fixture 데모 절차: `docs/21-case-timeline-report-handoff.md`.

## 2026-10-06 Sysmon Event ID 11 후속 구현

Status: `completed`

- 승인 기준선: `15469c1a168460ac2ffa2b59a6c9a4ba68e59e16`.
- 범위: immutable FileCreateEvent, 단일 XML의 ID 1/11 공통 dispatch,
  기존 service 연결, 합성 fixture와 회귀·오류 테스트, 문서 및 commit/push.
- 기존 Event ID 1 전용 함수 호환성, ArtifactId/EventRecordID provenance,
  UTC 규칙, content 무결성, 읽기 전용 Case 보장을 유지한다.
- DB/dependency 변경, 복수 이벤트 XML, 다른 event, CLI/report 구현은 제외한다.
- 다음 구현 시작점은 parser 확장이 아닌 Case aggregation/query → Markdown이다.
- 상세 인계: `docs/20-sysmon-event11-handoff.md`.
- 검증: targeted 54개, 전체 371개 테스트, lock, Ruff lint/format, `mypy src`,
  변경 테스트 mypy 및 diff check 통과. 전체 mypy는 기존 Artifact 테스트 6건만
  실패하며 신규 오류는 없다. 자체 리뷰 완료, feature branch commit/push 인계.

## 2026-10-06 Sysmon Event ID 1 작업 인계

Status: `completed`

- 사용자 승인 범위: Event ID 1 최소 수직 슬라이스 및 안전한 feature branch
  commit/push. main merge, 이력 재작성, VM/분석 대상 실행은 제외한다.
- 기존 미커밋 M1 구현을 `feat/sysmon-normalization-20261006`의 checkpoint
  `9280606a2c807c51c88bf9d19fca25e758ebf832`로 보존하고 origin에 push했다.
- M1 재검증: pytest 317개, lock, Ruff lint/format, 공식 `mypy src` 통과.
  추가 `mypy src tests`는 기존 Artifact 테스트 오류 6건으로 실패했다.
- 기존 normalized event 타입이 없어 제안한 최소 모델을 사용자가 승인했다.
  신규 ProcessCreateEvent, 단일 XML normalizer, 기존 Case/Artifact를 사용하는
  읽기 전용 서비스 및 합성 fixture 기반 테스트를 구현했다.
- Sysmon targeted 30개 및 전체 347개 테스트, lock, Ruff lint/format, 공식
  `mypy src`와 신규 테스트 타입 검사, diff 검사를 통과했다. 추가 전체 테스트
  mypy에는 기존 오류 6건이 남아 있다. 자체 리뷰 완료, Event ID 11은 미구현이다.
- 조사 결과, 제안 필드/파일, 검증 및 다음 기기 명령은
  `docs/19-sysmon-event1-handoff.md`에 기록한다.

## 목적

이 문서는 현재 활성 마일스톤의 목표, 상태, 범위, 승인된 결정, 산출물과
검증 상태를 관리한다. 전체 로드맵은 `docs/12-roadmap-and-milestones.md`를
따르며 여기에서 상세 내용을 반복하지 않는다.

## 계획 규칙

- 한 번에 하나의 구현 마일스톤만 활성화한다.
- 작업을 관련 요구사항, 승인된 ADR, 산출물과 검증 방법에 연결한다.
- 진행률은 코드량이 아니라 완료되고 검증된 사용자 흐름으로 판단한다.
- 실제 샘플 단계 전에는 sanitized fixture와 benign simulator만 사용한다.
- 관련 없는 리팩터링과 후속 마일스톤 기능을 포함하지 않는다.
- 완료 조건을 검증하지 못한 마일스톤은 `completed`로 표시하지 않는다.

## 상태값

- `planned`: 범위와 계획을 작성했으나 구현 승인을 받지 않은 상태
- `approved`: 사용자가 계획과 구현 범위를 승인해 착수 가능한 상태
- `in_progress`: 승인된 구현 또는 검증이 실제로 진행 중인 상태
- `verification_blocked`: 구현은 존재하지만 필수 검증을 완료하지 못한 상태
- `completed`: 모든 적용 가능한 완료 조건과 검증을 충족한 상태

## 마일스톤 상태

### M0 — Repository and development bootstrap

Status: `completed`

M0는 `M0-local`과 `M0-remote`로 나눈다. 두 하위 단계가 모두 완료되어야
전체 M0를 `completed`로 표시한다.

### 현재 기준선 — 2026-08-20

- Private GitHub repository `ODamDam/loader-detection-workbench`가 생성되어 있다.
- 승인된 문서 기준선과 M0-local 구현이 `main`에 병합되어 있다.
- 저장소는 ChatGPT GitHub 연결에서도 읽을 수 있다.
- M0-local 구현을 추적한 GitHub Issue #1은 완료되어 닫혀 있다.
- M0-remote 작업 관리 기준선을 추적한 GitHub Issue #4가 생성되어 있다.
- M0–M4 GitHub Milestones가 생성되어 있다.
- Issue #1과 Issue #4는 `M0 — Repository and development bootstrap` Milestone에 연결되어 있다.
- Issue #4 + Issues + Milestones + `PLANS.md` + backlog 조합을 Project Board와 동등한 원격 추적 구조로 사용한다.
- M0 Python package/bootstrap 구현과 필수 로컬 검증이 완료되었다.
- `pyproject.toml`, `uv.lock`, `src/loader_detection_workbench/`가 존재한다.
- M0-local과 M0-remote가 모두 완료되어 M0 전체가 `completed`이다.

### 목표

제품 기능을 구현하기 전에 저장소 운영 규칙, 로컬 Python 개발 기반과
Private GitHub 작업 관리 기반을 마련한다.

### 관련 기준선

- `README.md`
- `docs/02-requirements.md`
- `docs/03-mvp-scope.md`
- `docs/04-architecture.md`
- `docs/10-test-plan.md`
- `docs/11-security-and-safety.md`
- `docs/12-roadmap-and-milestones.md`
- `docs/13-definition-of-done.md`
- `docs/17-development-workflow.md`
- `docs/18-m0-codex-handoff.md`
- ADR-002, ADR-004, ADR-017

## Approved decisions

- 최소 지원 Python: `>=3.12`
- 로컬 개발 기준: CPython 3.12
- distribution: `loader-detection-workbench`
- import package: `loader_detection_workbench`
- CLI command: `workbench`
- initial version: `0.1.0`
- version source: `pyproject.toml`
- project/dependency manager: uv
- build backend: `uv_build`
- lockfile: `uv.lock`
- M0 runtime dependency: 없음
- CLI parser: 표준 라이브러리 `argparse`
- configuration: 표준 라이브러리 `tomllib`
- logging: 표준 라이브러리 `logging`
- tests: pytest
- lint and format: Ruff
- type check: strict mode mypy
- coverage threshold와 pytest-cov: M1 이후 검토
- 라이선스: 공개 전 별도 결정
- GitHub repository visibility: Private

## M0-local

Status: `completed`

Codex 착수 기준과 작업 경계는 `docs/18-m0-codex-handoff.md`를 함께 따른다.
코드 변경 전에는 `AGENTS.md`와 `docs/17-development-workflow.md`에 따라
구현 계획을 제출하고 승인받는다.

### 포함 범위

- `AGENTS.md`, `PLANS.md`, `docs/17-development-workflow.md`
- M0 Python 도구 체인 ADR과 결정 등록부
- Python 프로젝트 메타데이터와 `uv.lock`
- 기본 디렉터리 구조와 최소 CLI 진입점
- 선택적 TOML 설정 파일과 기본값을 지원하는 설정 로딩 구조
- 잘못된 설정 파일과 값의 명확한 오류 처리
- CLI 전역 `--config` 옵션
- 표준 `logging` 기반 콘솔 로깅
- 기본 로그 레벨 `INFO`와 CLI 전역 `--log-level` 옵션
- pytest, Ruff 및 strict mypy 구성
- `.gitignore`와 줄바꿈 정책
- 로컬 개발·검증 문서

### 제외 범위

- 실제 제품별 설정 항목
- 파일 로깅
- Project·Case 영속성과 SQLite 스키마
- Case Bundle
- PE, Sysmon, YARA, Sigma 및 보고서 기능
- simulator, VMware 및 Guest Orchestrator 구현·실행
- AI Provider와 로컬 웹 UI
- 실제 샘플과 원본 분석 로그
- coverage threshold와 pytest-cov
- 라이선스 확정
- GitHub Issues, Milestones와 Project Board 작업

### 설정 로딩 제약

- 설정 파일은 선택 사항이다.
- 설정 파일 미지정 시 안전한 기본값을 사용한다.
- M0에서는 공통 CLI 설정 외의 제품별 설정을 정의하지 않는다.
- 파일 부재, 읽기 실패, TOML 구문 오류와 지원하지 않는 값은 구분 가능한
  오류로 처리한다.
- 오류 메시지와 로그에 민감정보 또는 로컬 절대 경로를 노출하지 않는다.

### 로깅 제약

- 표준 라이브러리 `logging`만 사용한다.
- 콘솔 출력만 지원한다.
- 기본 로그 레벨은 `INFO`이다.
- 지원하지 않는 `--log-level` 값은 명확한 CLI 오류로 처리한다.
- 파일 로깅, 원격 전송과 민감정보 기록은 포함하지 않는다.

### 예정 산출물

- 운영 문서와 ADR
- `pyproject.toml`과 `uv.lock`
- `.gitignore`와 줄바꿈 정책 파일
- `src/loader_detection_workbench/` 최소 package
- CLI, 설정 및 로깅 골격
- smoke test와 설정·오류 처리 테스트
- unit, integration 및 public fixture 디렉터리 정책
- 로컬 개발 안내

### 구현 순서

1. 관련 운영 문서와 ADR을 다시 읽고 문서 충돌이나 미결 결정을 확인한다.
2. 사용자에게 구현 계획, 변경 예정 파일과 테스트 전략을 제출한다.
3. 승인 후 Python 프로젝트 메타데이터와 lockfile을 구성한다.
4. 기본 디렉터리와 최소 package를 생성한다.
5. CLI 도움말·버전·전역 옵션 골격을 구현한다.
6. 선택적 TOML 설정 로딩과 오류 처리를 구현한다.
7. 콘솔 로깅과 로그 레벨 처리를 구현한다.
8. 테스트와 품질 검사 구성을 추가한다.
9. ignore, 줄바꿈 및 로컬 개발 문서를 추가한다.
10. 승인된 검증을 실행한다.
11. 최종 diff, 범위 이탈과 금지 자료를 자체 검토한다.
12. 결과, 미실행 검증과 잔여 위험을 보고한다.

### 완료 조건

- 운영 문서의 책임이 명확히 구분되어 있다.
- 승인된 Python 프로젝트와 lockfile이 존재한다.
- `workbench --help`와 `workbench --version`이 성공한다.
- `--config` 미지정 시 기본값으로 시작한다.
- 유효한 선택적 TOML 설정을 읽을 수 있다.
- 잘못된 파일과 값이 명확하고 안전한 오류를 생성한다.
- `--log-level`과 기본 `INFO` 콘솔 로깅이 동작한다.
- pytest, Ruff lint, Ruff format check와 strict mypy가 통과한다.
- runtime workspace, secret, 생성물과 restricted artifact 제외 규칙이 있다.
- 저장소와 분석 프로젝트 작업공간의 분리가 문서화되어 있다.
- 실제 제품 기능, 실제 샘플 또는 원본 로그가 포함되지 않는다.
- 필수 검증을 실행하지 못한 경우 상태가 `verification_blocked`이다.

### 검증 명령

```powershell
uv sync
uv lock --check
uv run workbench --help
uv run workbench --version
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src
```

### 완료 기록 — 2026-08-20

- CPython 3.12.10과 uv 0.12.5로 개발 환경을 구성했다.
- `workbench --help`, `workbench --version`, 선택적 TOML 설정과 기본 `INFO`
  콘솔 로깅을 구현했다.
- pytest 19개 테스트와 Ruff lint/format check, strict mypy가 통과했다.
- M0 runtime dependency는 없으며 M1 이후 제품 기능을 포함하지 않았다.
- 실제 샘플, 원본 분석 로그, VMware, Guest Orchestrator와 분석 네트워크를
  사용하지 않았다.

## M0-remote

Status: `completed`

### 현재 완료

- Private GitHub repository 생성
- 승인된 초기 문서 기준선 `main` push
- ChatGPT GitHub 연결에서 Private repository 접근 확인
- M0-local 구현 추적 Issue #1 생성 및 완료
- M0-remote 추적 Issue #4 생성
- M0–M4 GitHub Milestones 생성
- Issue #1과 Issue #4를 M0 Milestone에 연결
- Issue #4 + Issues + Milestones + `PLANS.md` + backlog 기반의 동등한 원격 작업 추적 구조 확정

### 완료 기록 — 2026-08-20

- GitHub의 M0–M4 근접 로드맵 Milestones를 구성했다.
- M0-local Issue #1과 M0-remote Issue #4를 M0 Milestone에 연결했다.
- 별도 GitHub Projects 보드 대신 Issue #4, repository Issues, Milestones,
  `PLANS.md`, `docs/15-initial-backlog.md` 조합을 승인된 동등 추적 구조로 사용한다.
- 원격 작업 관리 과정에서 실제 샘플, 원본 분석 로그, secret 또는 런타임
  작업공간을 업로드하지 않았다.

### 제약

- 원격 작업 관리 구조를 변경하는 작업은 사용자의 별도 승인 범위에서 수행한다.
- 실제 샘플, 원본 분석 로그, secret 또는 런타임 작업공간을 업로드하지 않는다.
- 원격 작업 전에 변경 범위와 공개 가능성을 검토한다.

### 완료 조건

- GitHub repository가 Private으로 생성되어 있다.
- 승인된 로컬 기준선이 원격 저장소에 존재한다.
- 초기 작업을 추적할 Issues와 Milestones가 생성되어 있다.
- Project Board 또는 승인된 동등한 추적 구조가 초기 마일스톤과 작업 상태를 표시한다.
- 원격 저장소에 금지 자료나 민감정보가 없다.

## M0 전체 완료 조건

- `M0-local`과 `M0-remote`가 모두 `completed`이다.
- 두 하위 단계의 완료 기록과 검증 결과가 이 문서에 반영되어 있다.
- 적용 가능한 `docs/13-definition-of-done.md` 항목을 충족한다.
- 미실행 필수 검증이나 해결되지 않은 안전 차단이 없다.

### M0 완료 기록 — 2026-08-20

- M0-local 개발 부트스트랩 구현과 필수 검증을 완료했다.
- M0-remote GitHub 작업 관리 기준선을 구성했다.
- 두 하위 단계의 완료 조건을 충족하여 M0를 `completed`로 종료한다.
- 다음 단계는 M1 제품 구현 전에 Project/Case/Artifact, ID/status 규칙,
  SQLite v1, `project.json`, Case Bundle 및 CLI contract를 확정하는 것이다.

## 후속 마일스톤

### Issue #10 — M1-impl-4: Artifact store and deduplication

Status: `completed`

- 기준: Notion `Issue #10 Implementation Brief v1 — FINAL / Codex handoff-ready`
  (2026-09-17) 및 현재 사용자의 구현 승인. 로컬 #7–#9를 기준으로 한다.
- 범위: Artifact domain, 기존 SQLite v1 행/counter, streaming SHA-256/size,
  canonical content store, add/list/detach, rollback/cleanup 및 동시성 검증.
- 기존 #7의 Artifact ID 최소 6자리(`ART-000001`)를 그대로 재사용한다.
- schema/dependency 변경, #11 validator, #12 Bundle, 분석 실행 및 Git/원격 변경은
  포함하지 않는다. Issue #10과 M1 완료 판정은 별도 승인 범위로 유지한다.
- 2026-09-17: 구현, 299개 테스트, 필수 품질 검사와 최종 소스/diff 리뷰를
  완료했다. 초기 `verification_blocked`는 Windows Device Guard/Application
  Control이 `.venv` launcher를 일시 차단한 사건이며, 이후 정확한 `uv run pytest`
  및 `uv run mypy src`가 변경 없이 통과했다. 사용자 승인에 따라 Issue #10을
  approved/completed로 동기화한다.

### Issue #11 — M1-impl-5: Cross-contract validator

Status: `completed`

- Issue #10 완료 후 다음 구현 항목이다.
- 범위와 현재 로컬 계약의 reconciliation은 FINAL brief에서 확정했다.
- Tier 1 구조 검증, Tier 2 관계 검증, Tier 3 materialized Artifact 전체 검증,
  report-only CLI와 fail-closed findings를 포함한다.
- 2026-09-17: FINAL brief 승인 후 read-only Tier 1/2/3 validator, deterministic
  findings, `project validate --full`, benign corruption fixtures 및 no-mutation
  회귀 검증을 구현했다. 311개 테스트, 필수 quality gate와 최종 source review를
  통과했고 blocking findings는 0개였다. 사용자 승인에 따라 Issue #11을
  approved/completed로 동기화한다.

### Issue #12 — M1-impl-6: Case Bundle v1

Status: `completed`

- Issue #11 완료 후 진행한 구현 항목이다.
- 2026-09-17: FINAL brief 승인 후 root-level Bundle CLI, strict manifest,
  canonical ZIP validation, cross-project ID-preserving import와 M1 E2E 검증을
  구현했다. 최종 회귀 기준선은 317개 테스트이며 모든 required quality gate와
  source review를 통과했고 blocking findings는 0개였다. 사용자 승인에 따라
  Issue #12를 completed로 동기화한다.

### M1 — Project and Case Core

Status: `completed`

- Issue #7–#12의 승인된 Project/Case/Artifact foundation, validator와 Case Bundle
  구현을 완료했다. 최종 회귀 기준선은 317개 테스트이며 모든 required quality
  gate와 source review를 통과했고 blocking findings는 0개였다.

### Issue #9 — M1-impl-3: Case persistence and lifecycle

Status: `completed`

- 기준: Issue #9 Implementation Brief v1 — FINAL 및 승인된 구현 계획/clarification.
- 범위: Case create/list/show/rename/close/reopen, SQLite v1 영속성 및 원자적 변경.
- 기존 Issue #7/#8, Sample Intake, AI Experimental Track 로컬 변경을 보존한다.
- 검증: 오프라인 pytest, lock check, Ruff lint/format, strict mypy (`src tests`),
  diff 및 미추적 소스 자체 리뷰를 완료했다.
- Artifact 저장, Bundle, 전체 validator, 분석 실행 및 Git/원격 변경은 포함하지 않는다.
- 2026-09-08: 구현 전 기준선 132개 테스트 및 품질 검사 통과. 구현 후 227개
  테스트(추가 95개), 필수 품질 검사 및 최종 소스/diff 리뷰 통과. Issue #9
  implementation 승인·완료 기록과 동기화했으며 M1 전체 완료 상태는 변경하지 않는다.

M1 이후의 범위와 순서는 `docs/12-roadmap-and-milestones.md`를 따른다.
M1 구현 전에는 Project/Case/Artifact, ID/status 규칙, SQLite v1,
`project.json`, Case Bundle 및 CLI contract에 필요한 결정을 확정한다.
후속 마일스톤을 활성화할 때 별도 상세 계획과 사용자 승인을 추가한다.
