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
| 13 | 게스트에서 sample SHA-256 불일치(실행하지 않음) |
| 14 | 대상 시작 실패 |
| 15 | 출력 디렉터리가 이미 있음 |
| 16 | 내보내기 실패 |

## 6. 검증 상태

- 2026-11-12: 모의 VBoxManage 기반 pytest와 PowerShell mock(`tests/powershell/Test-WorkbenchGuestRun.ps1`)만
  통과했다. **실제 VM 실행은 아직 하지 않았다.** `SYSMON-V2-CLEAN` 생성 후 사용자 승인을
  받아 정상 시나리오 1회로 실제 경로를 검증한다.
