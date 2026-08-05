# 분석 VM 오케스트레이션 설계

## 1. MVP 환경

- 호스트: Windows 11
- Hypervisor: VMware
- 게스트: 사용자가 준비한 Windows 10 또는 11 x64 VM 한 대
- 자동 실행 대상: Windows PE `.exe`
- 게스트 제어: VMware Tools 기반 파일 복사·명령 실행
- 게스트 실행기: 일회성 PowerShell 오케스트레이터
- 상시 서비스와 수신 포트는 사용하지 않는다.

## 2. 실행 흐름

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
└─ VMwareAdapter

GuestAgent
└─ PowerShellGuestOrchestrator
```

향후 Hyper-V, VirtualBox, 상시 Guest Agent 구현을 추가할 수 있으나 MVP 범위에는 포함하지 않는다.
