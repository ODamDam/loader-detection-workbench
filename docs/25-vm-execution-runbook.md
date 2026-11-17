# VM 실행 런 사용 절차 (W4, ADR-024) — 2026-11-12

`workbench vm` 명령은 분석 VM을 클린 스냅샷으로 복원하고, sample Artifact나 고정된
정상 시나리오를 제한 시간 동안 실행한 뒤, 실행 구간의 Sysmon 이벤트 전체를 Case에
`sysmon` Artifact로 등록한다. 모든 명령은 Project 루트에서 실행한다.

> 실제 VM을 움직이는 명령은 `--approve`가 붙은 `vm run`·`vm scenario`뿐이다.
> `vm preflight`는 읽기 전용 조회, `--dry-run`은 VM 명령을 전혀 실행하지 않는다.

## 1. 사전 준비 (한 번)

1. `docs/24-sysmon-v2-vm-snapshot-procedure.md`대로 `SYSMON-V2-CLEAN`을 만든다. 스냅샷을
   찍기 전에 **공유 폴더 제거, 클립보드·드래그 앤 드롭 비활성화, NIC 케이블 분리**를
   마쳐야 sample 실행 사전 점검을 통과한다(정상 시나리오는 네트워크 격리만 확인).
2. 게스트에 비밀번호가 있는 로컬 계정이 있어야 한다(`guestcontrol`은 빈 비밀번호로
   로그온할 수 없다). 실행할 PowerShell 세션에서만 환경 변수를 설정한다. 파일이나
   저장소에 기록하지 않는다.
3. 그 계정은 **Event Log Readers** 그룹(`S-1-5-32-573`)에 있어야 한다. `guestcontrol`
   세션은 UAC로 관리자 권한이 빠진 토큰으로 돌기 때문에, 관리자 그룹만으로는 Sysmon
   로그를 읽지 못하고 게스트 스크립트가 종료 코드 12로 끝난다. 그룹 추가는 다음
   로그온부터 적용되므로 재부팅한 뒤 스냅샷을 찍는다(`docs/24` 5절).

```powershell
$env:WORKBENCH_GUEST_USER = '<게스트 계정>'
$env:WORKBENCH_GUEST_PASSWORD = Read-Host -AsSecureString | ForEach-Object {
    [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)) }
# VBoxManage가 기본 위치가 아니면:
# $env:WORKBENCH_VBOXMANAGE = 'D:\VirtualBox\VBoxManage.exe'
```

## 2. 점검과 계획

```powershell
uv run workbench vm preflight --profile sample          # 상태·스냅샷·NIC·공유 폴더·클립보드
uv run workbench vm scenarios                           # 정상 시나리오 목록
uv run workbench vm scenario CASE-0001 --scenario registry-probe --dry-run
uv run workbench vm run CASE-0002 --sample ART-000001 --timeout 180 --dry-run
```

`--dry-run`은 Case·Artifact 검증 결과와 실행될 VBoxManage 명령(비밀번호 파일과 호스트
경로는 자리표시자)을 보여 준다. 기본값은 VM `WIN11-ANALYSIS`, 스냅샷 `SYSMON-V2-CLEAN`,
제한 시간 180초(10~900초)이며 `--vm`, `--snapshot`, `--timeout`으로 바꾼다.

## 3. 실행 (승인 필요)

```powershell
uv run workbench vm scenario CASE-0001 --scenario registry-probe --approve
uv run workbench vm run CASE-0002 --sample ART-000001 --timeout 180 --approve
uv run workbench vm show VMR-0001          # 단계별 기록
uv run workbench case timeline CASE-0002   # 등록된 이벤트 확인
```

- 정상 시나리오는 benign Case에서만, sample은 malware·simulator Case에서만 실행된다.
- 실행 중에는 외장 SSD를 분리하지 않는다. 명령은 제한 시간 + 부팅·복원 시간 동안 끝나지 않는다.
- 성공하면 `events.xml`(`sysmon`)과 실행 메타데이터 JSON(`other`) Artifact가 Case에 붙는다.

## 4. 실패와 안전 잠금

| 상황 | 결과 |
| --- | --- |
| `--approve` 없음 | `EXECUTION_NOT_APPROVED`, 아무 명령도 실행하지 않음 |
| NIC 케이블 연결(복원 전·후) | `EXECUTION_NETWORK_NOT_ISOLATED`, VM 시작 안 함 |
| 스냅샷 없음, VM 실행 중, sample인데 공유 폴더·클립보드 | `EXECUTION_PREFLIGHT_FAILED` |
| 게스트 준비·반입·실행·회수·검증 실패 | 전원 끄기 → 복원 후 `failed`, Artifact 등록 없음 |
| **복원 실패 또는 복원 확인 실패** | `SNAPSHOT_RESTORE_FAILED`, **안전 잠금 설정** |
| 잠금 또는 끝나지 않은 런이 있음 | `EXECUTION_SAFETY_LOCKED`, 아무 명령도 실행하지 않음 |

잠금 해제는 사람이 VM을 직접 확인한 뒤에만 한다.

```powershell
uv run workbench vm status
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo WIN11-ANALYSIS --machinereadable |
    Select-String '^(VMState|CurrentSnapshotName|cableconnected)'
# 필요하면 수동으로: VBoxManage controlvm WIN11-ANALYSIS poweroff; VBoxManage snapshot WIN11-ANALYSIS restore SYSMON-V2-CLEAN
uv run workbench vm unlock --note "poweroff + SYSMON-V2-CLEAN restored and verified by hand"
```

## 5. 게스트 스크립트 종료 코드

| 코드 | 의미 |
| --- | --- |
| 10 | 잘못된 인자(작업 경로는 `C:\WorkbenchRun\VMR-NNNN`만 허용) |
| 11 | Sysmon 서비스가 실행 중이 아님 |
| 12 | Sysmon Operational 로그를 읽을 수 없음 |
| 13 | 게스트에서 sample 봉인 해제 실패 또는 SHA-256 불일치(실행하지 않음, ADR-030) |
| 14 | 대상 시작 실패 |
| 15 | 출력 디렉터리가 이미 있음 |
| 16 | 내보내기 실패 |

VBoxManage 7.2는 게스트 프로세스의 0이 아닌 종료 코드를 모두 자신의 종료 코드 33으로
바꿔 돌려준다. 그래서 게스트 스크립트는 실패할 때 `workbench-exit: N` 한 줄을 출력하고,
Workbench는 그 줄에서 위 코드를 읽는다. VBoxManage 자체가 실패하면 오류 메시지에
VirtualBox 상태 이름(예: `VBOX_E_IPRT_ERROR`)만 붙고 경로나 메시지 본문은 남기지 않는다.

## 6. 검증 상태

- 2026-11-12: 모의 VBoxManage 기반 pytest와 PowerShell mock(`tests/powershell/Test-WorkbenchGuestRun.ps1`)만
  통과했다. **실제 VM 실행은 아직 하지 않았다.** `SYSMON-V2-CLEAN` 생성 후 사용자 승인을
  받아 정상 시나리오 1회로 실제 경로를 검증한다.
- 2026-11-17: 사용자 승인 후 실제 VM(VirtualBox 7.2.4, Hyper-V 경유 NEM)에서
  `registry-probe`를 실행해 **VMR-0009가 14단계 모두 `ok`로 성공**했다. 이벤트 4,347건
  (약 8MB)이 등록됐고 시나리오의 레지스트리 값 쓰기(13)와 키 삭제(12 DeleteKey)가
  포함됐다. 실행 후 VM은 poweroff, `SYSMON-V2-CLEAN`으로 복원됐다. 전체 소요 약 5분.
  그 전 실행 VMR-0001~0008은 아래 문제로 실패했고, 모두 정리 단계(전원 끄기·복원)는
  정상 동작해 안전 잠금은 걸리지 않았다.
  - 호스트 임시 폴더가 소유자 전용 권한이라 VM 프로세스가 반입 파일을 읽지 못함
    (`VERR_ACCESS_DENIED`) → 사용자 임시 폴더 권한을 물려받는 폴더로 변경.
  - `--target-directory`가 구분자로 끝나지 않으면 VirtualBox 7.2가 폴더로 보지 않음
    (`VBOX_E_IPRT_ERROR`, 반입·회수 모두) → 끝에 구분자를 붙임.
  - 게스트 종료 코드가 33으로 뭉개짐 → `workbench-exit: N` 출력으로 전달.
  - 게스트 계정이 Sysmon 로그를 읽지 못함 → Event Log Readers 추가(1절 3).
  - 4 vCPU VM이 실행 중 반복해서 멈춤 → 2 vCPU로 변경(원인 미확정).
  - Sysmon 설정이 레지스트리 CreateKey를 모두 기록해 유휴 상태에서도 분당
    2,000~36,000건이 쌓이고 내보내기가 제한 시간을 넘김 → CreateKey와 Sysmon 자신의
    레지스트리 이벤트를 제외(적용 후 유휴 분당 약 330건).
- 2026-11-17(후속): 게스트 스크립트의 이벤트 내보내기를 `Get-WinEvent`+`ToXml`에서
  `wevtutil qe /f:xml /e:Events /uni:true`로 바꿨다. 분석 VM에서 같은 4만 4,796건을
  내보내는 데 294초 → 11초였다. 호스트 검증기가 이 형식(이벤트 사이 줄바꿈)을 받는 것은
  VMR-0009 실제 이벤트로 확인했다. 바뀐 스크립트로 실제 VM에서 `registry-probe`를 다시
  실행해 **VMR-0010이 14단계 모두 `ok`로 성공**했다(이벤트 2,487건, 3.3MB, BOM 없는
  UTF-8, 한글 포함 문자 보존, 시나리오의 13 SetValue·12 DeleteKey 포함, 전체 4분 34초).
  수집 파일은 여전히 32MiB 한도(`events.xml exceeds the 32 MiB limit`)를 넘으면 거부된다.
- 2026-11-17: 무해한 시뮬레이터(ADR-028)로 sample 경로를 실제 VM에서 실행해
  **VMR-0011이 14단계 모두 `ok`로 성공**했다(이벤트 2,453건). 게스트에서 SHA-256 확인 후
  `target-<sha256 앞 12자>.exe`로 실행됐고 시뮬레이터 동작이 모두 기록됐다.
- 아직 실제 VM에서 확인하지 않은 것: 다른 시나리오,
  실패 시 게스트 종료 코드가 사람이 읽을 수 있는 이유로 바뀌는 경로(코드 12는 확인).
  `dns-invalid`는 네트워크 분리 상태에서 DNS 이벤트가 남지 않을 수 있다(`docs/24`).
