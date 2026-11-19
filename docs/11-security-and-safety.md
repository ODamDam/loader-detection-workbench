# 보안과 안전 원칙

## 1. 기본 원칙

본 프로젝트는 교육·연구 목적의 방어적 분석 도구이다. 실제 악성 샘플의 실행은 격리된 분석 VM에서만 수행한다.

## 2. 필수 통제

- 호스트에서 악성 샘플을 직접 실행하지 않는다.
- Hypervisor 공유 폴더를 실제 샘플 분석 중 상시 연결하지 않는다.
  ADR-018의 승인된 benign demo는 기존 VirtualBox Shared Folder로 XML을 전달할 수 있다.
- 실행 전 사용자의 명시적 승인을 받는다.
- 모든 실행에 제한 시간을 둔다.
- 기본 네트워크 모드는 차단이다.
- 네트워크 행위가 필요한 경우 Host-only 모의 서비스를 사용한다.
- 실행 후 VM을 Clean Snapshot으로 복원한다.
- 복원 실패 시 다음 실행을 금지한다.
- 원본 악성 샘플은 공개 저장소에 올리지 않는다.
- 외부 AI Provider에 샘플 바이너리를 전송하지 않는다.

## 3. 데이터 분류

### Restricted
- 실제 악성 샘플
- 드롭 파일
- 원본 PCAP
- 원본 EVTX·Procmon
- VM 인증정보
- API 키

### Internal
- 정규화 전 분석 자료
- 상세 환경 정보
- 비공개 정상 데이터셋

### Public
- 비식별화 보고서
- YARA·Sigma
- 정제 이벤트
- IOC 요약
- 검증 통계

## 4. 실패 안전

- VM 준비 상태 검사 실패 시 실행하지 않는다.
- 외부 라우팅 가능성이 발견되면 실행하지 않는다.
- 게스트 해시가 호스트 해시와 다르면 실행하지 않는다.
- 수집 실패는 결과에 명시하고 자동으로 성공 처리하지 않는다.
- 스냅숏 복원 실패는 치명적 오류로 기록한다.

## 5. AI 안전

- AI는 최종 룰 승인자가 아니다.
- 근거 없는 조건은 룰에 자동 채택하지 않는다.
- AI 출력은 원본 증거 참조와 함께 저장한다.
- API Key가 없어도 핵심 기능을 사용할 수 있어야 한다.
- 민감 로그의 외부 전송 여부를 사용자가 통제해야 한다.

## 6. 로컬 웹 UI 안전

- UI는 인증된 원격 서비스가 아니다. Waitress를 `127.0.0.1`에만 바인딩하고
  port forwarding, reverse proxy와 원격 bind를 지원하지 않는다.
- browser에서 Project 경로를 받지 않고 CLI 운영자가 선택한 하나의 workspace만
  연다. Project는 bind 전에 기존 validator로 검증한다.
- state-changing request에는 CSRF와 exact Origin 검사를 적용하고 Host allowlist,
  multipart 크기·form memory·part 개수 제한을 적용한다.
- Jinja escaping과 CSP, frame deny, no-sniff, Referrer-Policy same-origin(다른 사이트로는 보내지 않음), no-store 응답 헤더를
  유지한다. 사용자 문자열을 safe HTML로 표시하지 않는다.
- 업로드 파일명은 경로로 사용하지 않는다. bytes는 OS 임시 디렉터리의 생성된
  이름에 staging하고 기존 Manual Evidence Service에 전달한 뒤 모든 결과에서
  임시 디렉터리를 제거한다.
- Artifact 내부 ID, workspace·content 경로, raw evidence, Sysmon command line,
  executable/target path와 ProcessGuid를 화면에 표시하거나 오류에 기록하지 않는다.
- 다운로드, 원문 미리보기, 자동 migration, VM 실행과 AI 전송 route는 제공하지 않는다.
