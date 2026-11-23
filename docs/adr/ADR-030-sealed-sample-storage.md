# ADR-030: 봉인 샘플 저장과 암호 ZIP 메모리 가져오기

## 상태

승인 — 2026-11-17 사용자 승인("이 계획과 pyzipper 추가를 승인한다"). 근거: AGENTS.md
악성코드 안전 규칙(호스트에서 샘플을 열거나 실행하지 않음), ADR-001(내용 주소 저장),
ADR-024(VM 실행 런), sample-intake-cli-contract-v1.

## 배경

평가용 실제 샘플은 MalwareBazaar 같은 공개 저장소에서 사용자가 직접 받는다. 이 샘플들은
비밀번호 `infected`로 보호한 ZIP(대부분 AES)으로 배포된다. 기존 `case artifact add`는 원본
파일을 받아 Artifact 저장소에 원본 그대로 복사했다. 그래서 두 가지 문제가 있었다.

- 샘플을 등록하려면 호스트 디스크에 먼저 압축을 풀어야 한다.
- 저장소 안의 원본 실행 파일은 호스트 백신이 격리하거나 지울 수 있고(무결성 오류),
  실수로 실행될 수도 있다.

Python 표준 `zipfile`은 AES ZIP을 풀지 못한다.

## 결정

1. **봉인 형식** (`artifact.seal`): 저장 파일 = `LDWSEAL1` 헤더 + (내용 XOR 공개 고정 4 KiB
   키스트림). 키스트림은 `SHA-256("loader-detection-workbench/seal/v1" ‖ 카운터)` 128블록이다.
   - **암호화가 아니다.** 키는 소스에 있다. 목적은 원본 바이트 패턴이 호스트 디스크에 남지
     않게 하는 것(백신 격리 방지, 실수 실행 방지)뿐이다.
   - 식별은 언제나 봉인 전 내용이다. DB의 SHA-256·크기, 정규 경로
     `artifacts/sha256/xx/<sha>`, 모든 무결성 검사는 원본 기준이다.
2. **저장소가 투명하게 처리:** `ArtifactStore`의 `verify`·`read_verified`·`publish`와
   `project validate --full`은 헤더가 있으면 메모리에서 봉인을 풀어 원본으로 검사한다.
   YARA·정적 분석·보고서는 코드 변경 없이 원본 바이트를 받는다.
   - `sample` 종류는 새로 저장할 때 항상 봉인한다. 다른 종류는 원본 그대로 둔다.
   - 봉인된 원본(번들 멤버 등)을 저장하면 봉인 상태를 유지한다. 봉인을 풀어 쓰는 경로는
     없다.
   - 헤더가 없는 기존 원본 샘플은 그대로 읽힌다(마이그레이션 없음).
   - 같은 내용이 이미 저장돼 있으면 그 형태 그대로 재사용한다. 따라서 이 결정 이전에 원본으로
     저장된 내용은 원본으로 남는다.
   - 봉인하지 않을 내용이 헤더로 시작하면(`publish_bytes`) `ARTIFACT_SOURCE_INVALID`로
     거부한다. 파일 원본이 헤더로 시작하면 봉인된 내용으로 해석한다.
3. **암호 ZIP 가져오기** (`artifact.archive`, 새 production 의존성 `pyzipper`):
   - `workbench case artifact import-zip CASE ARCHIVE [--password P] [--member NAME]`:
     멤버 하나를 메모리로만 읽어 봉인 `sample` Artifact로 저장한다. 디스크에 풀지 않는다.
   - `workbench sample add ARCHIVE --zip ...`: 같은 방식으로 멤버의 SHA-256만 계산해 후보로
     등록한다(`SampleService.register`).
   - 멤버가 여러 개면 `--member`가 필요하다. 멤버 이름은 경로로 쓰지 않는다. 크기 제한은
     64 MiB다.
   - 오류: `ARCHIVE_INVALID`(열 수 없음, 무결성 실패, 멤버 선택 오류),
     `ARCHIVE_PASSWORD_REJECTED`, `ARTIFACT_SIZE_LIMIT_EXCEEDED`
4. **VM 실행:** 호스트는 봉인된 파일을 그대로 게스트로 복사한다. 게스트 스크립트가 VM
   안에서 봉인을 풀고(같은 키스트림, PowerShell 구현) 원본 SHA-256을 확인한 뒤 실행한다.
   해제나 해시 확인에 실패하면 종료 코드 13(`SAMPLE_HASH_MISMATCH`)이다. 키스트림 일치는
   PowerShell 테스트가 호스트 값으로 검사한다.
5. **번들:** Case Bundle에는 저장된 형태(봉인)가 그대로 들어가고, manifest 해시는 원본
   기준이다. 가져온 Project에서도 봉인 상태로 저장된다.

## 결과

- 샘플 원본이 호스트 디스크에 기록되는 경로가 없다. 사용자가 받은 ZIP은 그대로 둔다.
- 봉인·해제 비용은 메모리 XOR 한 번이다. 게스트 PowerShell 해제는 바이트 루프라 수 MB
  샘플에 몇 초가 걸린다.
- 새 의존성: `pyzipper` 0.3.6(MIT)과 그 의존성 `pycryptodomex`.
- 메모리 안의 원본 바이트는 Python 프로세스가 갖는다. 실행하지 않으며, 외부 AI Provider로
  보내지 않는 기존 규칙도 그대로다.
- 실제 샘플의 VM 실행은 이 결정과 별개로 실행 직전 사용자 승인을 받는다.
