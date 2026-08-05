# ADR-013-network-modes: MVP 네트워크 모드

## 상태
승인

## 배경
완전 차단만 사용하면 네트워크 행위가 나타나지 않을 수 있고 실제 인터넷 허용은 위험하다.

## 결정
MVP는 disabled와 Host-only simulated 모드를 지원한다.

## 결과
안전하게 DNS·HTTP 행위를 관찰할 수 있다.
