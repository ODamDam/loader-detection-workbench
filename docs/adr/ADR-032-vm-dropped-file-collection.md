# ADR-032: VM 실행에서 샘플이 만든 파일 회수(봉인 상태로)

## 상태

승인 — 2026-11-19 사용자 승인("승인, 구현 시작"). 사용자 결정: YARA 방향 (가) 압축 해제 →
방식 (가-2) "VM에서 드롭 파일 회수". 근거: ADR-024(VM 실행 런), ADR-030(봉인 저장),
ADR-031(프로세스 관계, Workbench 프로세스 제외), AGENTS.md 악성코드 안전 규칙.

## 배경

dev HijackLoader 3건은 모두 정상 설치기·런처 껍데기 안에 담겨 온다(CASE-0005 Squirrel 런처,
CASE-0006·0016 Inno Setup, CASE-0015 7-Zip SFX). 껍데기 파일만 보는 정적 분석과 YARA로는
실제 구성 요소(side-loading DLL, 암호화된 데이터 파일)가 보이지 않아 YARA가 2/6에 머문다.

호스트에서 껍데기를 직접 푸는 방식은 형식마다 파서가 필요하다. 7z는 `py7zr`(하위 의존성이
많음)로 가능하지만, Inno Setup은 헤더 형식이 버전마다 달라 동결(11/22) 전에 안정적으로
구현하기 어렵다. 반면 VM 실행에서는 설치기가 이미 구성 요소를 `%TEMP%`에 풀어 놓았고
(CASE-0006: `ClusteCompiler16.exe`, `madHcNet32.dll`, `msvcp_win.dll` 복사본, `texturedef96.bin`),
Sysmon File Create(Event 11)가 그 경로를 기록한다.

## 결정

1. **선택적 기능:** `workbench vm run ... --collect-dropped`. sample 프로필에서만 쓸 수 있고
   정상 시나리오에는 적용하지 않는다. 사용 여부는 실행 메타데이터에 남는다. eval 평가는 dev와
   같은 옵션으로 실행해야 하므로 평가 프로토콜에 이 옵션을 고정해 적는다.
2. **무엇을 회수할지는 호스트가 정한다(검증된 이벤트 기준):** 기존 `verify`를 통과한
   `events.xml`에서 샘플 관련 프로세스(ADR-031: 시작된 target과 그 자손, 그 트리가 쓴 파일로
   나중에 시작된 프로세스. Workbench 프로세스 제외)의 Event 11 `TargetFilename`만 고른다.
   - 허용 위치: 게스트 사용자 프로필의 `AppData\Local\`·`AppData\Roaming\`, `C:\Users\Public\`,
     `C:\ProgramData\`. `C:\WorkbenchRun\`(target 자신), Prefetch, `C:\Windows\`는 제외한다.
   - 경로 검사: 드라이브 절대 경로, `..`·대체 데이터 스트림(`:`)·장치 경로(`\\?\`) 없음,
     260자 이하, 출력 가능한 문자만. 중복은 하나로 합친다.
   - 상한: 파일 32개, 파일당 32 MiB, 합계 64 MiB. 넘으면 앞에서부터 상한까지만 회수하고
     나머지는 개수만 기록한다.
3. **봉인은 게스트 안에서 한다:** 호스트가 경로 목록(`collect-request.json`)을 게스트에 넣고
   게스트 스크립트를 새 모드 `Collect`로 다시 실행한다. 스크립트는 같은 허용 위치·상한을
   다시 검사하고, 각 파일을 ADR-030 봉인 형식(`LDWSEAL1`, 기존 PowerShell 구현)으로
   `out\dropped\NN.bin`에 쓰며, `dropped-manifest.json`(순번, 파일 이름(마지막 요소만), 원본
   SHA-256, 크기, 상태 `collected|missing|too_large|unreadable`)을 남긴다. 원본 바이트는 호스트
   디스크에 한 번도 기록되지 않는다.
4. **호스트 검증과 등록:** 봉인 파일을 회수해 메모리에서 풀고 원본 SHA-256·크기를
   manifest와 대조한다. 맞는 파일만 해당 Case의 `sample` 종류 Artifact로 저장한다(저장소가
   다시 봉인). 출처는 실행 메타데이터 JSON(`other` Artifact)의 `dropped_files`에 남긴다: 각
   파일의 이름(마지막 요소), 상태, SHA-256, 크기, Artifact ID, 근거 이벤트(`ART-…#레코드`).
   같은 내용이 Case에 이미 있으면(예: 샘플 자신의 복사본) 새로 저장하지 않고 기존 Artifact를
   가리킨다(`existing: true`). 봉인 헤더가 없는 회수 파일은 즉시 지우고 단계를 실패시킨다.
5. **런 단계:** `verify` 다음, `power_off` 전에 새 단계 `collect_dropped`를 둔다(단계 이름
   추가만, 스키마 변경 없음). 이 단계가 실패해도 이벤트 수집 결과는 버리지 않는다: 단계는
   `failed`로 기록하고 런은 이벤트만 등록한 채 성공으로 끝난다(오프라인 코어 우선). 복원
   실패 처리와 안전 잠금은 그대로다.
6. **사용처:** 회수 파일은 `sample` 종류라 기존 정적 분석(`case analyze`)과 YARA 검증이 코드
   변경 없이 대상으로 삼는다. YARA는 Case의 sample 중 하나라도 맞으면 그 Case를 맞힌 것으로
   본다(기존 규칙). AI 요약에는 기존처럼 Artifact ID와 종류만 들어간다.

## 구현 메모 (2026-11-19)

- 선택: `execution/dropped.py`(`collectable_path`, `select_dropped`). 샘플 트리 판정은
  `sysmon.relations.sample_related_keys`를 공유한다(AI 요약의 샘플 우선 정렬과 같은 기준).
- 게스트: `Invoke-WorkbenchGuestRun.ps1 -Mode Collect`(`Test-WorkbenchCollectPath`,
  `Get-WorkbenchSealedBytes`, 종료 코드 17 `COLLECT_FAILED`), 제한 시간 600초. 디렉터리는
  `not_file`, 지워진 파일은 `missing`, 상한 초과는 `too_large`, 읽기 실패는 `unreadable`,
  허용 위치 밖은 `rejected`.
- 실제 dev 기록으로 선택만 확인(실행 없음): CASE-0006은 `ClusteCompiler16.exe`,
  `madHcNet32.dll`, `msvcp_win.dll`, `texturedef96.bin` 등 17개 경로(디렉터리 포함), CASE-0002는
  `synchost.exe` 1개(`.job`은 Windows 폴더라 제외), CASE-0003은 PowerShell 정책 검사 임시 파일도
  포함된다.
- 검증: 가짜 VBoxManage 통합 테스트(성공, 단일 항목 manifest, 봉인 없는 파일 거부, 게스트
  실패 시 이벤트 유지, 옵션 없음, 시나리오 거부)와 PowerShell 모의 테스트(실제 임시 파일 봉인이
  호스트 봉인과 같음). 실제 VM 실행은 별도 승인 후.

## 제외 범위

- 프로세스 메모리 덤프, 메모리에서만 복호화되는 최종 페이로드.
- 호스트 쪽 7z·Inno 파서, 레지스트리 내보내기, 네트워크 캡처.
- 정상 시나리오 런의 파일 회수.

## 결과

- 껍데기 형식과 관계없이 설치기가 실제로 내놓은 구성 요소를 정적 분석·YARA에 쓸 수 있다.
  새 의존성은 없다.
- 악성 드롭 파일이 호스트 Project에 들어온다. 저장은 봉인 상태뿐이고 실행하지 않으며 Git과
  외부 AI Provider로는 보내지 않는다.
- dev Case에 Artifact가 추가되므로 이후 YARA·정적 검증 결과가 달라질 수 있다. 이미 기록된
  검증 런은 바뀌지 않는다.
- 회수 파일에는 정상 구성 요소(정상 DLL 복사본 등)도 섞인다. 이를 겨냥한 YARA는 정상 비교
  세트(CASE-0007 시스템 바이너리, CASE-0008)의 오탐 검증으로 걸러야 한다.
- Event 11이 기록하지 않은 파일(이미 지워졌거나 필터된 경로)은 회수되지 않는다. 지워진
  파일은 `missing`으로 남는다.
- 실제 실행: 구현 후 HijackLoader dev 3건(CASE-0006, 0015, 0016)을 이 옵션으로 다시 실행한다.
  실행 직전 사용자 승인을 받는다.
