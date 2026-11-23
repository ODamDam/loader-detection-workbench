# ADR-015-powershell-guest-orchestrator: 일회성 PowerShell Guest Orchestrator

## 상태
승인. VMware Tools-specific integration은 ADR-018로 대체됨 (2026-10-06).
일회성 PowerShell 방향은 유지하며 현재 guest integration은 Guest Additions이다.
아래 VMware Tools 문구는 과거 결정 기록이다.

## 배경
상시 Guest Agent는 구현·보안 부담이 크다.

## 결정
VMware Tools가 분석 시점마다 PowerShell 오케스트레이터를 호출한다.

## 결과
포트 노출 없이 구현할 수 있으나 명령·오류 규격을 명확히 해야 한다.
