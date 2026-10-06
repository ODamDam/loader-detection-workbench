# 분석 VM 오케스트레이션 설계

## 1. MVP 환경

- 호스트: Windows 11
- Hypervisor: Oracle VirtualBox (ADR-018, 현재 active target)
- 게스트: Windows 11 x64 VM 한 대
- 자동 실행 대상: Windows PE `.exe`
- 게스트 통합: VirtualBox Guest Additions, 현재 benign 수동 전달은 Shared Folder
- 현재 clean snapshot: `SYSMON-DEMO-CLEAN`
- 향후 자동화 표면: VBoxManage; 이번 구현은 adapter/guestcontrol을 포함하지 않는다.
- 게스트 실행기: 일회성 PowerShell 오케스트레이터
- 상시 서비스와 수신 포트는 사용하지 않는다.

## 2. 실행 흐름

아래는 장기 orchestration 설계이다. 현재는 사용자가 확인한 benign 수동 E2E와
guest collection/export helper가 범위이며 VM start/stop/restore 자동화는 없다.
실제 manual Event ID 1/11 → Workbench 성공과 새 helper 검증 상태는 구분한다.

```text
사용자 승인
→ Clean Snapshot 복원
→ VM 시작
→ 준비 상태 검사
→ 샘플 전달
→ 게스트 해시 재검증
→ 수집기 시작
→ 샘플 실행
→ 제한 시간 감시
→ 수집 종료
→ Case Bundle 생성
→ 호스트 회수와 해시 검증
→ VM 종료
→ Clean Snapshot 복원
```

## 3. 실행 전 확인 항목

- 샘플 파일명
- SHA-256
- 분석 VM
- 초기 스냅숏
- 네트워크 모드
- 실행 명령과 인자
- Sysmon·Procmon·PCAP 수집 여부
- 실행 제한 시간
- 종료·복원 정책

## 4. 네트워크 모드

### `disabled`
- 네트워크 어댑터를 차단한다.
- 프로세스·파일·레지스트리 중심 사례에 사용한다.

### `simulated`
- Host-only 격리망을 사용한다.
- 모의 DNS·HTTP 서비스를 제공한다.
- 실제 인터넷으로 라우팅하지 않는다.
- PCAP 수집 대상 사례에 사용한다.

### 확장 후보
- `restricted_external`
- `custom`

## 5. 실행 제한

- 기본값은 3분이다.
- 케이스별로 5분 등으로 조정할 수 있다.
- 시간 초과 시 샘플 프로세스 종료, 로그 회수, VM 복원을 수행한다.
- 복원 실패는 치명적 안전 오류로 분류한다.

## 6. Guest Orchestrator 책임

- 실행 설정 검증
- 샘플 해시 확인
- 수집 시작 시각 기록
- Procmon·PCAP 선택 수집
- 샘플 실행과 타임아웃
- 로그·메타데이터 수집
- 결과 매니페스트와 해시 생성
- 부분 실패 상태 기록

## 7. 추상화

```text
HypervisorAdapter
├─ VirtualBoxAdapter (active future implementation target)
└─ VMwareAdapter (future/alternative)

GuestAgent
└─ PowerShellGuestOrchestrator
```

ADR-003의 과거 VMware 결정은 ADR-018로 대체했다. 교체 가능한 경계는 유지한다.
Hyper-V와 상시 Guest Agent 등 추가 구현은 현재 범위 밖이다.
VM disk/image/state와 OVA는 Git에 넣지 않는다. OVA는 선택적인 별도 기기 운반 수단이다.

## 8. 현재 benign demo helper

`scripts/vm/Invoke-SysmonDemoCollection.ps1`은 준비된 guest에서 수동 실행한다.
고유 marker와 child PID로 Process Create를 선택하고, 같은 ProcessGuid/PID와
정확한 TargetFilename을 가진 후속 File Create를 연결한다. 출력은 single Event
XML 두 개와 최소 JSON metadata이다. runtime output은 Git 밖에 둔다.
실행 명령, fail-closed 정책과 검증 상태는 `23-virtualbox-sysmon-export-helper-handoff.md`.
