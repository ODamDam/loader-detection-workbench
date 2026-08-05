# ADR-015-powershell-guest-orchestrator: 일회성 PowerShell Guest Orchestrator

## 상태
승인

## 배경
상시 Guest Agent는 구현·보안 부담이 크다.

## 결정
VMware Tools가 분석 시점마다 PowerShell 오케스트레이터를 호출한다.

## 결과
포트 노출 없이 구현할 수 있으나 명령·오류 규격을 명확히 해야 한다.
