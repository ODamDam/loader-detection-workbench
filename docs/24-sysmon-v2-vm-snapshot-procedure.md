# Sysmon v2 설정 적용과 새 클린 스냅샷 만들기 — 2026-11-11

다양한 악성코드 패밀리를 분석하려면 Sysmon Event ID 1·11만으로는 부족하다
(ADR-022). 이 절차는 **사용자가 직접** 분석 VM에서 수행한다. 실제 샘플은 이 단계에서
반입하지 않는다.

- 설정 파일: `scripts/vm/sysmon-config-workbench-v2.xml`
- 수집 범위: Event ID 1·2·3·5·6·7(서명 없는 DLL만)·8·10(위험 접근 권한만)·11·12–14·
  15·17–18·19–21·22·23/26·25
- 결과 스냅샷 이름: `SYSMON-V2-CLEAN`(기존 `SYSMON-DEMO-CLEAN` 아래에 생성)

## 0. 사전 확인 (Host)

```powershell
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo WIN11-ANALYSIS --machinereadable |
    Select-String '^(VMState|cableconnected1|CurrentSnapshotName)'
```

- `cableconnected1="off"`여야 한다. 아니면 다음으로 끈다.
  `VBoxManage modifyvm WIN11-ANALYSIS --cable-connected1 off`
- 설정 파일을 공유 폴더로 복사한다:
  `Copy-Item scripts\vm\sysmon-config-workbench-v2.xml C:\WorkbenchVMExchange\`

## 1. VM 안에서 설정 적용 (관리자 PowerShell)

```powershell
# 공유 폴더 경로는 Guest Additions 자동 마운트 문자(예: Z:) 또는 \\VBoxSvr\WorkbenchVMExchange
$config = '\\VBoxSvr\WorkbenchVMExchange\sysmon-config-workbench-v2.xml'
# 실행 파일 이름은 설치 방식에 따라 sysmon.exe 또는 sysmon64.exe이고 PATH에 없을 수
# 있으므로, 설치된 서비스에서 경로를 찾는다(2026-11-17 실제 VM은 Sysmon / sysmon.exe).
$sysmon = (Get-CimInstance Win32_Service -Filter "Name like 'Sysmon%'" |
    Select-Object -First 1).PathName.Trim('"')
& $sysmon -c $config
& $sysmon -c           # 적용된 규칙 출력 확인
```

## 2. 이벤트 생성 확인 (무해한 동작만)

```powershell
reg add HKCU\Software\WorkbenchSysmonCheck /v probe /t REG_SZ /d 1 /f   # 12, 13
reg delete HKCU\Software\WorkbenchSysmonCheck /f                         # 12
Resolve-DnsName example.invalid -ErrorAction SilentlyContinue           # 22 (네트워크 차단 상태여도 기록)
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 30 |
    Group-Object Id | Select-Object Name, Count
```

Event ID 13·12가 보이면 적용된 것이다. 2026-11-17부터 레지스트리 CreateKey는 기록하지
않으므로 `reg add`는 13, `reg delete`는 12(DeleteKey)만 남긴다. 다른 이벤트에 밀려
최근 30건에 안 보이면 `-FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=12,13,22}`로
따로 조회한다. 2026-11-17 설정 수정 전 실제 VM에서는 12·13이 기록됐고, 네트워크 케이블을
분리한 상태의 `Resolve-DnsName example.invalid`는 22번을 남기지 않았다. 다만 같은 날 성공한
실행(VMR-0009)에는 다른 프로세스의 22번이 20건 있었다.

## 3. Windows Update 정리

2026-11-11 이전 PC에서 옮겨 온 VM이 종료하면서 밀린 업데이트를 2시간 넘게 설치했다.
스냅샷 전에 업데이트를 끝내고 일시 중지해 두어야 분석 중 같은 문제가 반복되지 않는다.

- 설정 → Windows 업데이트 → 업데이트 일시 중지(최대 기간)

## 4. 로그 비우고 종료

```powershell
wevtutil cl Microsoft-Windows-Sysmon/Operational
Stop-Computer
```

## 5. 호스트 쪽 격리 설정 (Host, VM이 poweroff인 상태) — 2026-11-12 추가

W4 자동 실행(ADR-024)은 sample 실행 전에 아래 설정을 확인하고, 하나라도 맞지 않으면
실행하지 않는다. 이 설정은 스냅샷에 함께 저장되므로 **스냅샷을 찍기 전에** 바꾼다.
2026-11-12 조회 기준 현재 VM은 클립보드·드래그 앤 드롭이 `bidirectional`이고 공유 폴더
`WorkbenchVMExchange`가 연결되어 있다.

```powershell
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vb modifyvm WIN11-ANALYSIS --cable-connected1 off --clipboard-mode disabled --drag-and-drop disabled
& $vb sharedfolder remove WIN11-ANALYSIS --name WorkbenchVMExchange
& $vb showvminfo WIN11-ANALYSIS --machinereadable |
    Select-String '^(cableconnected|clipboard=|draganddrop|SharedFolderName)'
```

- 1절의 설정 파일 복사에는 공유 폴더가 필요하므로, 이 단계는 1~4절을 마친 뒤 수행한다.
- 게스트에 **비밀번호가 있는 로컬 계정**을 준비해 둔다. 자동 실행은 이 계정으로
  `VBoxManage guestcontrol`에 로그온한다(빈 비밀번호 불가). 계정 정보는 실행 세션의 환경
  변수로만 전달한다(`docs/25-vm-execution-runbook.md`).
- 그 계정을 VM 안 관리자 PowerShell에서 Event Log Readers에 넣고 **재부팅**한다.
  `guestcontrol` 세션은 관리자 권한이 빠진 토큰이라 이 그룹이 없으면 Sysmon 로그를
  읽지 못한다(2026-11-17 실제 실행에서 확인).
  `Add-LocalGroupMember -SID S-1-5-32-573 -Member <게스트 계정>`
- 이 PC(4코어 노트북, Hyper-V 경유 NEM)에서는 4 vCPU VM이 반복해서 멈췄다. VM의 CPU를
  2개로 두고 스냅샷을 찍는다(`VBoxManage modifyvm WIN11-ANALYSIS --cpus 2`). CPU 수는
  스냅샷에 함께 저장된다.
- VM 창을 처음 열 때 "스케일 모드로 전환" 확인 대화상자가 뜨면 부팅이 시작되지 않는다.
  **취소**를 눌러 창 모드를 유지한다.

## 6. 스냅샷 생성 (Host, VM이 poweroff인 상태)

```powershell
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vb snapshot WIN11-ANALYSIS take SYSMON-V2-CLEAN --description "Sysmon config workbench-v2 applied; Operational log cleared; updates paused; network cable off; no shared folders; clipboard and drag-and-drop disabled"
& $vb snapshot WIN11-ANALYSIS list
```

이어서 Project 루트에서 `uv run workbench vm preflight --profile sample`로 `ready: yes`를 확인한다.

## 후속 (Workbench 구현, W4) — 2026-11-12 구현

- 실행 구간의 모든 Sysmon 이벤트는 새 게스트 스크립트
  `src/loader_detection_workbench/execution/guest/Invoke-WorkbenchGuestRun.ps1`이 하나의
  `<Events>` XML로 내보낸다. 데모용 `scripts/vm/Invoke-SysmonDemoCollection.ps1`(Event ID 1·11)은
  중간보고 데모 경로로 그대로 둔다(ADR-024 D3).
- 자동 실행기(`workbench vm run|scenario`)는 `SYSMON-V2-CLEAN`으로 복원한 뒤 실행하고, 종료 후
  다시 복원한다. 사용 절차는 `docs/25-vm-execution-runbook.md`.
