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
sysmon64 -c $config
sysmon64 -c            # 적용된 규칙 출력 확인
```

## 2. 이벤트 생성 확인 (무해한 동작만)

```powershell
reg add HKCU\Software\WorkbenchSysmonCheck /v probe /t REG_SZ /d 1 /f   # 12, 13
reg delete HKCU\Software\WorkbenchSysmonCheck /f                         # 12
Resolve-DnsName example.invalid -ErrorAction SilentlyContinue           # 22 (네트워크 차단 상태여도 기록)
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational -MaxEvents 30 |
    Group-Object Id | Select-Object Name, Count
```

Event ID 12·13·22가 보이면 적용된 것이다.

## 3. Windows Update 정리

2026-11-11 이전 PC에서 옮겨 온 VM이 종료하면서 밀린 업데이트를 2시간 넘게 설치했다.
스냅샷 전에 업데이트를 끝내고 일시 중지해 두어야 분석 중 같은 문제가 반복되지 않는다.

- 설정 → Windows 업데이트 → 업데이트 일시 중지(최대 기간)

## 4. 로그 비우고 종료

```powershell
wevtutil cl Microsoft-Windows-Sysmon/Operational
Stop-Computer
```

## 5. 스냅샷 생성 (Host, VM이 poweroff인 상태)

```powershell
$vb = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
& $vb snapshot WIN11-ANALYSIS take SYSMON-V2-CLEAN --description "Sysmon config workbench-v2 applied; Operational log cleared; updates paused; network cable off"
& $vb snapshot WIN11-ANALYSIS list
```

## 후속 (Workbench 구현, W4)

- `scripts/vm/Invoke-SysmonDemoCollection.ps1`는 아직 Event ID 1·11만 내보낸다.
  W4에서 실행 구간의 모든 Sysmon 이벤트를 하나의 `<Events>` XML로 내보내도록 확장하며,
  이 파일은 `sysmon.records` 파서와 Sigma 평가기가 그대로 읽을 수 있다.
- 자동 실행기는 `SYSMON-V2-CLEAN`으로 복원한 뒤 실행하고, 종료 후 다시 복원한다.
