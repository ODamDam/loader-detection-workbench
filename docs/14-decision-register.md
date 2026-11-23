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
| ADR-022 | 범용 Windows 악성코드 대상과 11월 최종 구현 범위 | 승인 |
| ADR-023 | 탐지 가설·룰·벤치마크·검증 실행 모듈(모듈 소유 테이블, 오프라인 YARA·Sigma) | 승인 |
| ADR-024 | 승인 기반 VM 실행 런, guestcontrol 채널, 클린 스냅샷 복원과 안전 잠금(모듈 소유 테이블) | 승인 |
| ADR-025 | Case 분석 단일 조회, 형식 중립 문서 기반 Markdown·HTML 보고서, 분모를 포함한 검증 지표 표기, 모듈 테이블 검증, 읽기 전용 관계 그래프·버전 비교 UI | 승인 |
| ADR-026 | AI 분석 보조의 오프라인 골격: 구조 요약 입력, 외부 전송 차단, fail-closed 출력 검증, 추론 분리 저장, 사람 수락 시에만 가설 반영(모듈 소유 테이블) | 승인 |
| ADR-027 | 다중 Provider 분석 비교(W8): 저장된 같은 입력의 분석만 비교, 인용·문구 유사도 기반 공통·개별 의견 분리, 보고서 비교 표 | 승인 |
| ADR-028 | 무해한 시뮬레이터 실행 파일: C# 단일 EXE, Windows 내장 .NET Framework 컴파일러로 빌드, 내장 프로필, 종료 전 원상 복구, 호스트 실행 금지 | 승인 |
| ADR-029 | 정적 보고서 사이트: 같은 블록 문서, 상대 링크만 허용, 모든 페이지 비식별화(프로필 이름·SID·Sysmon 호스트·사용자), 새 디렉터리에만 생성 | 승인 |
| ADR-030 | 봉인 샘플 저장(공개 키스트림 XOR, 암호화 아님)과 암호 ZIP 메모리 가져오기(`pyzipper`), 게스트에서만 봉인 해제 | 승인 |
| ADR-031 | 확정 사항(Finding) 모듈과 확정 기반 보고서 본문, LLM 2단계 의견, Provider 3종 어댑터, Case 작업 공간 UI, 동결 최대 11/24 | 승인 |
| ADR-032 | VM 실행에서 샘플 트리가 쓴 파일 회수(`--collect-dropped`): 호스트가 검증된 Event 11로 선택, 게스트에서 봉인, 호스트는 메모리 검증 후 봉인 `sample` 저장, 실패해도 이벤트는 유지 | 승인 |
| ADR-033 | AI 의견 한국어 읽기용 번역(`ai translate`): 의견 제목·본문만 전송(범위 확대), ID 보존 fail-closed 검증, AI 스키마 v3 추가 전용 저장, 작업 공간 hover 표시, 원문만 기록으로 사용 | 승인 |

## 남은 주요 결정

다음 항목은 구현 착수 또는 해당 마일스톤 직전에 확정한다.

- 저장소 이름 변경 여부 (공식 과제명은 ADR-022에서 확정)
- 정적 PE 분석 도구 조합
- Unseen 평가의 탐지 판정 단위(룰 단위 vs 가설 단위)
- 모의 DNS·HTTP 서비스 구성
- 실제 샘플 확보·보관·폐기 절차
- 공개 라이선스
- 첫 외부 API Provider와 첫 로컬 LLM Provider
- 외부 AI Provider에 보낼 데이터 범위(`structural` 요약 그대로, 축소 또는 확대)
- UI 관계 그래프의 파일 이름 표시 유지 여부(ADR-025)
