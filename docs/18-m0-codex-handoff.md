# M0 Codex 인수인계

## 1. 목적

이 문서는 Codex가 M0-local 구현을 시작할 때 필요한 현재 기준선과 작업 경계를
한 곳에서 확인할 수 있도록 정리한 인수인계 문서이다. 새로운 프로젝트 목표나
아키텍처를 정의하지 않으며, 충돌이 있을 경우 `AGENTS.md`, 승인된 ADR,
`PLANS.md`와 관련 기준 문서를 우선한다.

## 2. 현재 상태

- 활성 마일스톤: M0 — Repository and development bootstrap
- M0-local: `approved`
- M0-remote: `in_progress`
- GitHub repository: Private, `main` 기준선 push 완료
- GitHub Issues: 아직 생성되지 않음
- Python package/bootstrap 구현: 아직 시작 전
- `pyproject.toml`, `uv.lock`, `src/` package: 아직 없음

즉, 현재 작업은 제품 기능 개발이 아니라 **재현 가능한 Python 개발 기반을
구축하는 M0-local 구현**이다.

## 3. Codex 필독 순서

1. `AGENTS.md`
2. `PLANS.md`
3. `docs/17-development-workflow.md`
4. `docs/adr/ADR-017-m0-python-toolchain.md`
5. `docs/10-test-plan.md`
6. `docs/11-security-and-safety.md`
7. `docs/13-definition-of-done.md`
8. 이 문서

제품 범위를 이해할 필요가 있을 때만 `README.md`, `docs/01-project-brief.md`,
`docs/02-requirements.md`, `docs/03-mvp-scope.md`, `docs/04-architecture.md`를
추가로 참고한다.

## 4. 구현 목표

다음 사용자 관찰 가능 결과를 제공한다.

- `uv sync`로 재현 가능한 개발 환경을 구성할 수 있다.
- `workbench --help`와 `workbench --version`이 동작한다.
- 설정 파일 없이 안전한 기본값으로 시작한다.
- 선택적 TOML 설정 파일을 읽을 수 있다.
- 잘못된 설정 파일이나 값은 구분 가능한 안전한 오류를 생성한다.
- 기본 `INFO` 콘솔 로깅과 `--log-level` 전역 옵션이 동작한다.
- pytest, Ruff lint/format check, strict mypy 검증이 가능하다.

## 5. 포함 범위

- Python `>=3.12`
- distribution: `loader-detection-workbench`
- import package: `loader_detection_workbench`
- CLI command: `workbench`
- initial version: `0.1.0`
- project/dependency manager: uv
- build backend: `uv_build`
- M0 runtime dependency: 없음
- CLI: `argparse`
- config: `tomllib`
- logging: 표준 `logging`
- test: pytest
- lint/format: Ruff
- type check: strict mypy
- `pyproject.toml`, `uv.lock`
- 최소 package/CLI/config/logging 구조
- smoke test 및 설정 오류 처리 테스트
- `.gitignore`, 줄바꿈 정책, 로컬 개발 안내

## 6. 제외 범위

다음은 M0-local에서 구현하지 않는다.

- Project/Case/Artifact 영속성
- SQLite 및 migration
- Case Bundle
- PE 분석
- Sysmon 파싱/정규화
- YARA/Sigma
- 보고서 생성
- simulator
- VMware/Guest Orchestrator
- AI Provider
- 로컬 웹 UI
- 실제 샘플 또는 원본 분석 로그
- 파일/원격 로깅
- coverage threshold와 pytest-cov
- 공개 라이선스 확정
- GitHub Issues/Milestones/Project Board 생성

## 7. 아키텍처 경계

- CLI는 얇게 유지한다.
- 제품 Domain 기능을 선행 설계하거나 구현하지 않는다.
- M0 설정은 공통 CLI/개발 기반에 필요한 최소 범위만 포함한다.
- runtime workspace와 source repository를 분리한다.
- 오류 메시지와 로그에 secret, 민감정보 또는 로컬 절대 경로를 노출하지 않는다.
- 외부 네트워크와 위험 분석 실행이 필요하지 않아야 한다.

## 8. 예상 변경 파일

정확한 내부 파일명은 구현 계획에서 조정할 수 있으나 예상 범위는 다음과 같다.

```text
pyproject.toml
uv.lock
.gitignore
.gitattributes
src/loader_detection_workbench/
tests/
docs/ 또는 README의 로컬 개발 안내
```

기존 요구사항, MVP, 아키텍처 문서는 구현 사실과 불일치가 생기는 경우에만
최소 수정한다.

## 9. 구현 전 계획 제출

Codex는 코드 변경 전에 다음을 사용자에게 제시하고 승인받는다.

- 목표
- 포함/제외 범위
- 변경 예정 파일
- 내부 package 구조
- config와 logging 동작 요약
- 테스트 전략
- 실행할 검증 명령
- 새 dependency가 없는지 확인
- 미결 결정이나 문서 충돌

`AGENTS.md`의 승인 경계를 변경하지 않는다.

## 10. 검증 명령

```powershell
uv sync
uv lock --check
uv run workbench --help
uv run workbench --version
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src
```

실행하지 못한 검증은 통과했다고 보고하지 않는다. 필수 검증이 차단되면
`verification_blocked`로 보고한다.

## 11. 완료 보고 형식

최종 보고에는 최소 다음을 포함한다.

- 변경 파일
- 구현한 사용자 관찰 가능 동작
- 실행한 검증과 결과
- 실행하지 못한 검증과 이유
- 안전/민감정보 자체 검토 결과
- 범위 이탈 여부
- 남은 위험 또는 M1로 넘길 항목

## 12. M0-local 완료 후

M0-local 완료가 검증되면 `PLANS.md` 상태와 관련 백로그를 갱신한다.
M1 구현 전에는 Project/Case/Artifact, ID/status 규칙, SQLite v1,
`project.json`, Case Bundle 및 CLI contract에 필요한 결정을 별도로 확정한다.
