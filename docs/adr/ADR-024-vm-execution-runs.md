# ADR-024: 승인 기반 VM 실행 런과 클린 스냅샷 복원 (W4)

## 상태

승인 — 2026-11-12 사용자 결정(D1~D3 권장안 승인). 근거: ADR-022 결정 3·4, 11월 최종 구현
계획 v1의 W4.

## 배경

ADR-022는 실제 샘플을 네트워크를 차단한 분석 VM에서만 실행하고, 실행 전후 클린 스냅샷
자동 복원을 구현하며, 복원을 확인할 수 없으면 다음 실행을 막도록 정했다. 정상 비교
데이터도 같은 VM 경로로 수집해야 한다. 기존 `Invoke-SysmonDemoCollection.ps1`은 사용자가
게스트에서 수동 실행하는 Event ID 1·11 데모 도구였고, VM 제어나 Case 등록은 없었다.

## 결정

1. **실행 단위:** `execution` 모듈의 Execution Run(`VMR-NNNN`)이 sample Artifact 하나 또는
   고정된 정상 시나리오 하나를 실행한다. 순서는 승인 → 안전 잠금 확인 → 사전 점검 →
   클린 스냅샷 복원·확인 → 복원된 설정의 격리 재확인 → headless 시작 → 게스트 준비 →
   반입 → 제한 시간 실행 → 회수 → 검증 → 전원 끄기 → 복원·확인 → Case 등록이다.
2. **Hypervisor 경계:** `Hypervisor` Protocol 뒤에 `VBoxManageHypervisor`를 둔다. 명령은
   shell 없이 인자 목록으로 실행한다. 테스트는 VBoxManage를 흉내 내는 모의 실행기로
   어댑터와 서비스를 함께 검증한다. 실제 VM 명령은 `--approve` 실행과 읽기 전용
   `vm preflight`에서만 일어나고, `--dry-run`은 어떤 VM 명령도 실행하지 않는다.
3. **D1 게스트 채널:** `VBoxManage guestcontrol`(mkdir·copyto·run·copyfrom)을 쓴다. 게스트
   계정은 환경 변수 `WORKBENCH_GUEST_USER`·`WORKBENCH_GUEST_PASSWORD`에서만 읽고,
   비밀번호는 호출마다 만드는 임시 파일(`--passwordfile`)로만 전달한 뒤 삭제한다. DB,
   로그, 오류, 명령 기록에 남기지 않는다. sample 실행은 공유 폴더가 하나라도 있거나
   클립보드·드래그 앤 드롭이 켜져 있으면 사전 점검에서 거부한다. 정상 시나리오는 네트워크
   격리만 요구한다.
4. **네트워크:** 모든 NIC가 `none`이거나 케이블이 분리(`cableconnected=off`)되어 있어야 한다.
   스냅샷 복원은 NIC 설정도 되돌리므로 복원 직후 다시 확인하고, 연결되어 있으면 시작하지
   않는다.
5. **D2 저장:** `project.db` 안에 모듈 소유 테이블(`execution_schema` v1)을 둔다. 핵심
   스키마 v2와 검증기는 바꾸지 않는다. 각 단계는 별도 트랜잭션으로 기록하고, 끝난 런과
   단계 기록은 SQLite trigger로 변경·삭제를 막는다.
6. **안전 잠금:** 복원 명령 실패, 또는 복원 후 VM이 꺼진 상태로 지정 스냅샷에 있음을
   확인하지 못하면 잠금 행을 기록한다. 잠금이 있거나 `running` 상태 런(프로세스 중단 등으로
   끝나지 않은 런)이 있으면 모든 실행을 거부한다. 사람이 VM 상태를 확인한 뒤
   `vm unlock --note`로만 해제하고, 해제 이력과 메모를 남긴다. 끝나지 않은 런은 이때
   `abandoned`로 닫는다.
7. **실패 처리:** VM을 건드린 뒤의 모든 실패(게스트 준비 시간 초과, 반입·실행·회수 실패,
   검증 실패, 중단)는 전원 끄기와 복원을 시도한다. 그 복원도 실패하면 잠금을 건다. 실패한
   런은 Artifact를 등록하지 않는다.
8. **D3 게스트 스크립트:** 새 `Invoke-WorkbenchGuestRun.ps1`을 패키지 데이터로 두고 런마다
   반입한다. 기존 `Invoke-SysmonDemoCollection.ps1`과 그 테스트는 중간보고 데모 경로로
   그대로 둔다. 새 스크립트는 sample 해시를 게스트에서 다시 확인하고, 제한 시간 전체 동안
   관찰한 뒤(루트 프로세스가 먼저 끝나도 자식 활동을 수집) 프로세스 트리를 종료하고,
   실행 전 기준 EventRecordID 이후의 **모든 Sysmon 이벤트**를 하나의 `<Events>` XML과
   SHA-256 매니페스트로 내보낸다.
9. **검증과 등록:** 호스트는 매니페스트의 run ID·모드·대상 해시·시나리오·이벤트 파일
   SHA-256과 개수를 확인하고, `sysmon.records` 파서로 모든 이벤트를 읽어 각 EventRecordID가
   기준보다 큰지 확인한다(32 MiB 상한, 이벤트 0건은 실패). 통과하면 복원 후 `events.xml`을
   `sysmon`, 호스트가 만든 실행 메타데이터 JSON을 `other` Artifact로 등록한다. 메타데이터에는
   호스트 절대 경로와 비밀값을 넣지 않는다.
10. **정상 시나리오:** 임의 명령을 받지 않고 고정 ID만 허용한다(`notepad-open-close`,
    `powershell-inventory`, `registry-probe`, `file-write`, `dns-invalid`). 정상
    시나리오는 benign Case에서만, sample 실행은 malware·simulator Case에서만 허용한다.

## 결과

- 실제 VM 검증은 사용자가 `SYSMON-V2-CLEAN`을 만든 뒤, 실행 직전 승인을 받아 정상
  시나리오 1회로 시작한다. 그 전까지 검증 범위는 모의 VBoxManage와 PowerShell mock이다.
- 실행 창에는 Workbench 게스트 스크립트와 Guest Additions 자체 활동도 기록된다. 룰 작성 시
  정상 대응 데이터(정상 시나리오 런)로 이 잡음을 구분한다.
- 잠금은 Project DB 단위이다. 다른 Project에서 같은 VM을 쓰면 그 Project의 잠금은 보이지
  않는다. 대신 모든 런은 시작 전에 복원과 확인을 다시 수행한다.
- `sysmon` Artifact 등록 뒤 메타데이터 등록이 실패하면 `sysmon` Artifact는 남고 런은
  `failed`로 기록된다.
