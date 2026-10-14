# 결정 사항 등록부

| ID | 결정 | 상태 |
|---|---|---|
| ADR-001 | SQLite와 파일 시스템 혼합 저장 | 승인 |
| ADR-002 | CLI 우선, 로컬 웹 UI 후속 | 승인 |
| ADR-003 | VMware 기반 단일 Windows 분석 VM (과거) | ADR-018로 대체 |
| ADR-004 | AI 없이 핵심 파이프라인 동작 | 승인 |
| ADR-005 | Sigma 오프라인 이벤트 재현 검증 | 승인 |
| ADR-006 | 시뮬레이터는 내장 프로필에서 JSON 엔진으로 확장 | 승인 |
| ADR-007 | 정적 PE와 Sysmon 필수, Procmon·PCAP 조건부 | 승인 |
| ADR-008 | 공통 정상 데이터와 사례별 정상 대응 데이터 병행 | 승인 |
| ADR-009 | AI 룰 초안·자동 검증·사용자 승인 | 승인 |
| ADR-010 | 검증 완료는 근거·정상 시험·사용자 승인 기준 | 승인 |
| ADR-011 | Markdown·독립형 HTML·정적 사이트 | 승인 |
| ADR-012 | 공개 범위는 보고서·룰·정제 이벤트·IOC·검증 결과 | 승인 |
| ADR-013 | MVP 네트워크 모드는 disabled·simulated | 승인 |
| ADR-014 | 실행 전 승인과 케이스별 시간 제한 | 승인 |
| ADR-015 | PowerShell 일회성 Guest Orchestrator | 승인; integration은 ADR-018로 갱신 |
| ADR-016 | MVP 자동 실행 형식은 Windows PE `.exe` | 승인 |
| ADR-017 | M0 Python 도구 체인 | 승인 |
| ADR-018 | VirtualBox Windows 11 / Guest Additions를 현재 MVP/demo 기준으로 확정 | 승인 |
| ADR-019 | SQLite v2와 수동 증거 provenance, 명시적 v1→v2 migration | 승인 |
| ADR-020 | 기존 Open Case Sysmon Collection 등록과 멱등 재사용 | 승인 |
| ADR-021 | loopback 전용 Flask 기본 플랫폼 UI와 기존 Service 재사용 | 승인 |

## 남은 주요 결정

다음 항목은 구현 착수 또는 해당 마일스톤 직전에 확정한다.

- 프로젝트 및 제품 최종 명칭
- 정적 PE 분석 도구 조합
- Sigma 오프라인 평가 구현 방식
- 모의 DNS·HTTP 서비스 구성
- 실제 샘플 확보·보관·폐기 절차
- 공개 라이선스
- 첫 외부 API Provider와 첫 로컬 LLM Provider
