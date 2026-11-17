# 26. 평가용 샘플 확보 절차

이 문서는 상세 분석(dev)과 Unseen 평가(eval)에 쓸 실제 샘플을 확보하는 절차다. 샘플
다운로드, 계정, API Key는 사용자가 직접 처리한다. Workbench와 Codex·Claude는 다운로드하거나
샘플 저장 위치를 탐색하지 않는다. 저장 방식은 ADR-030, 선정·분할 규칙은
`sample-intake-cli-contract-v1.md`와 Protocol v1을 따른다.

## 1. 목표 수량

| 항목 | 목표 | 비고 |
| --- | --- | --- |
| 패밀리 | 3종 이상 | 한 패밀리가 dev·eval 한쪽에 몰리지 않게 |
| dev(상세 분석) | 6건 | 정량 목표 "분석 악성 Case 6" |
| eval(Unseen) | 4~6건 | 동결 전 상세 분석 금지 |
| 후보 | 16~20건 | 제외(무효 PE, DLL, 중복 등)를 감안한 여유분 |

## 2. 출처와 선정 기준

- **출처:** MalwareBazaar(`bazaar.abuse.ch`). 다운로드에는 무료 계정의 Auth-Key가 필요하고,
  파일은 비밀번호 `infected`인 AES ZIP으로 내려온다.
- **메타데이터로만 고른다.** 행위(실행 결과, 샌드박스 보고서의 동작)를 보고 고르지 않는다
  (Protocol v1). 쓸 수 있는 정보는 파일 형식, 크기, 첫 관측일, 태그·signature, 출처 링크다.
- **조건:**
  - Windows PE 실행 파일(EXE, ADR-016). DLL·스크립트·문서·설치 패키지는 제외한다.
  - 64 MiB 이하
  - 태그나 signature로 로더·다운로더 계열 패밀리가 표시된 것
  - 같은 패밀리에서 너무 많이 고르지 않는다. 패밀리당 후보 5건 이하를 권장한다.
- **기록할 출처 정보:** SHA-256, 출처 URL(`https://bazaar.abuse.ch/sample/<sha256>/`),
  보고된 패밀리와 그 근거(MalwareBazaar signature 또는 태그), 확인 날짜

## 3. 보관

- 받은 ZIP은 **풀지 않고** 저장소 밖 폴더 하나에 그대로 둔다. Git에 추가하지 않는다.
- 호스트에서 ZIP을 열거나 멤버를 실행하지 않는다. Workbench는 ZIP을 메모리에서만 읽는다.
- Workbench Artifact 저장소에는 봉인된 형태로만 저장된다(ADR-030). 호스트 백신 예외 설정은
  필요 없다.

## 4. 후보 등록과 심사

Project 디렉터리에서 실행한다. `<...>`는 실제 값으로 바꾼다.

```text
uv run workbench sample add <ZIP> --zip --source MalwareBazaar \
  --source-reference https://bazaar.abuse.ch/sample/<sha256>/ \
  --reported-role loader --role-label-source MalwareBazaar-tag \
  --role-label-confidence medium \
  --reported-family <family> --family-label-source MalwareBazaar-signature \
  --family-label-confidence medium
```

- 등록된 SHA-256이 MalwareBazaar 표기와 같은지 확인한다.
- 일곱 기준을 메타데이터로 심사한다. 상세 분석으로 확인하지 않는다.

```text
uv run workbench sample screen SMP-NNNNNN --real-world pass --windows-target pass \
  --loader-downloader pass --provenance pass --binary-valid pass \
  --supported-analysis pass --duplicate-clear pass
uv run workbench sample eligible SMP-NNNNNN
```

- 맞지 않는 후보는 `sample exclude SMP-NNNNNN --reason <reason> --detail <설명>`으로 남긴다.

## 5. 무작위 분할과 동결

```text
uv run workbench sample split --dev-count 6 --eval-count 6 --seed <seed> --split-id SPLIT-001
uv run workbench sample validate --gate freeze
uv run workbench sample freeze --benchmark-id UNSEEN-V1 --benchmark-version 1
```

- seed는 분할 전에 정해 기록한다. 결과를 보고 다시 분할하지 않는다.
- 패밀리·출처 편중 경고가 나오면 기록하고, 필요한 경우에만
  `manual_balance_adjustment` 사유로 조정한다.

## 6. dev 샘플을 Case로

```text
uv run workbench case create --name "<family> dev 1" --kind malware
uv run workbench case artifact import-zip CASE-NNNN <ZIP>
```

- 이후 정적 분석, 룰 작성, 승인받은 VM 실행을 진행한다. VM 실행은 실행 직전 사용자 승인이
  필요하고, 분석 VM은 외부 네트워크에 연결하지 않는다.

## 7. eval 샘플

- 동결 전후 모두, 평가를 시작할 때까지 상세 분석·실행·룰 작성에 쓰지 않는다.
- 평가를 시작할 때 `sample eval-open SMP-NNNNNN`으로 처음 접근 시각을 남긴 뒤 Case를 만든다.

## 8. 기록 표

| sample_id | SHA-256 | 패밀리(근거) | 출처 URL | 확인 날짜 | 상태 | 배정 |
| --- | --- | --- | --- | --- | --- | --- |
| SMP-000001 | | | | | | |
