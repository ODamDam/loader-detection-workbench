# 보고서와 공개 정책

## 1. 자동 생성 범위

### 현재 구현: 시연용 Case Markdown subset

`workbench report build CASE-NNNN OUTPUT.md`는 CLI timeline과 같은
`CaseTimelineQuery` 결과로 Markdown을 렌더링한다. Case Overview, Evidence Summary,
Timeline, Collection / Analysis Limits만 포함하며 아래 장기 full-report 항목 및
`templates/case-report-template.md`를 삭제하거나 대체하지 않는다.

Case 정보, Event ID 1/11의 시간순 observation, Artifact display ID/EventRecordID를
포함한다. File Create에는 Creation UTC Time도 표시한다. Generated At은 기존 UTC
helper를 사용하며 renderer 인자로 전달해 테스트할 수 있다. 빈 Case는 evidence
0건과 `No normalized Sysmon observations.`를 표시한다.

신뢰하지 않는 Case/XML 문자열의 줄바꿈·제어문자는 공백으로 표시하고 HTML
metacharacter 및 Markdown punctuation을 escape한다. 원본 normalized 값은 변경하지
않는다. 이 escaping은 공개용 개인정보 비식별화를 대신하지 않는다.

결과는 memory-only projection이며 report metadata를 DB에 저장하지 않는다.
보고서는 VM 수집 성공, 탐지 결과 또는 악성 판정을 암시하지 않는다. HTML,
Publication Bundle, 자동 공개는 지원 범위가 아니다. 파일 게시 정책과 오류는
`06-cli-and-ui-design.md`, 재현 명령은 `21-case-timeline-report-handoff.md`를 따른다.

### 포함
- 케이스별 Markdown 보고서
- 케이스별 독립형 HTML 보고서
- 전체 케이스 정적 보고서 사이트
- 공개용 정제 데이터 번들

### 제외
- 최종보고서 자동 통합
- 논문 초안 자동 통합

## 2. 보고서 생성 흐름

```text
구조화 분석 데이터
→ 공통 Report Model
→ Markdown
→ 독립형 HTML
→ 정적 사이트
```

Markdown과 HTML은 같은 Report Model을 사용하여 내용 불일치를 방지한다.

## 3. 출력 구조

```text
reports/
├─ markdown/
│  ├─ CASE-001.md
│  └─ ...
├─ standalone/
│  ├─ CASE-001.html
│  └─ ...
└─ site/
   ├─ index.html
   ├─ cases/
   └─ assets/
```

## 4. 케이스 보고서 필수 항목

1. 개요
2. 분석 환경
3. 샘플 메타데이터
4. 정적 PE 분석
5. 초기 실행 타임라인
6. 프로세스·파일·레지스트리·네트워크 행위
7. IOC
8. 정상 대응 비교
9. 탐지 가설
10. YARA 룰과 검증
11. Sigma 룰과 검증
12. 오탐·미탐 분석
13. 한계점
14. 결론

## 5. 정적 사이트 기능

- 프로젝트 개요
- 정량 목표 달성 현황
- 케이스 목록
- 행위·ATT&CK 태그 필터
- YARA·Sigma 검증 상태
- 개별 보고서
- 룰 버전과 검증 결과
- 안전한 공개 자료 다운로드

## 6. 공개 범위

### 기본 공개
- 보고서 전문
- YARA 룰
- Sigma 룰
- 정제된 주요 이벤트
- IOC 요약
- 검증 결과
- 룰 버전 정보

### 비공개
- 실제 악성 샘플
- 드롭된 실행 파일
- 원본 EVTX
- 원본 Procmon 로그
- 원본 PCAP
- 사용자명·호스트명·절대 경로
- API 키·인증정보
- 실제 악성 인프라 재접속 설정
- 재배포 권한이 없는 정상 파일

## 7. Publication Bundle

```text
publication/
├─ reports/
├─ site/
├─ rules/
├─ events/
├─ iocs/
├─ validation/
└─ publication-manifest.json
```

`publication-manifest.json`은 자료별 공개 여부, 비식별화 여부, 해시, 제외 사유를 기록한다.
