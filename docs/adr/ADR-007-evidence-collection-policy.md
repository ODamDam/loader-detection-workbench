# ADR-007-evidence-collection-policy: 필수·선택 증거 수집 정책

## 상태
승인

## 배경
모든 케이스에서 Procmon과 PCAP을 강제하면 데이터와 운영 부담이 커진다.

## 결정
정적 PE와 Sysmon은 필수, Procmon과 PCAP은 케이스별 조건부로 수집한다.

## 결과
현실적인 수집이 가능하며 미수집 사유를 구조화해야 한다.
