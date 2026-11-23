# ADR-017-m0-python-toolchain: M0 Python 도구 체인

## 상태
승인

## 배경
M0-local에서 재현 가능한 Python 프로젝트, 최소 CLI, 설정·로깅 골격과
품질 검사 기반을 만들기 위해 언어 버전, 명칭, 패키징 및 개발 도구를
고정해야 한다. M0는 제품 기능을 구현하지 않으며 외부 런타임 패키지 없이
시작한다.

## 결정

- 최소 지원 버전은 Python 3.12 이상이고 로컬 개발 기준은 CPython 3.12이다.
- distribution 이름은 `loader-detection-workbench`이다.
- import package 이름은 `loader_detection_workbench`이다.
- CLI 명령 이름은 `workbench`이다.
- 초기 버전은 `0.1.0`이며 `pyproject.toml`을 버전의 단일 원천으로 사용한다.
- 프로젝트와 dependency 관리는 uv를 사용하고 `uv.lock`을 유지한다.
- build backend는 `uv_build`를 사용한다.
- M0 runtime dependency는 추가하지 않는다.
- CLI parser는 표준 라이브러리 `argparse`를 사용한다.
- TOML 설정 로딩은 표준 라이브러리 `tomllib`을 사용한다.
- 콘솔 로깅은 표준 라이브러리 `logging`을 사용한다.
- 테스트는 pytest, lint와 format은 Ruff, type check는 strict mode mypy를
  사용한다.
- coverage threshold와 pytest-cov 도입은 M1 이후 재검토한다.
- 공개 라이선스 결정은 저장소 공개 전까지 연기한다.

## 결과

M0는 외부 runtime dependency 없이 표준 라이브러리 중심으로 시작하며,
uv와 lockfile을 통해 개발·빌드 도구를 재현할 수 있다. Python 3.11 이하를
지원하지 않고 도구 체인 변경에는 프로젝트 메타데이터와 lockfile 갱신이
필요하다. 라이선스가 확정되기 전에는 공개 배포와 재사용 조건을 확정할 수
없다.

## 개정 (2026-11-24)

사용자 승인으로 GitHub 저장소를 Public으로 전환했고, 라이선스는 부여하지 않기로 했다. 코드는
열람용으로 공개하며, 별도의 재사용 권리를 허락하지 않는다. 재사용을 허용하려면 새 결정으로
라이선스를 추가한다. 위의 "공개 라이선스 결정은 저장소 공개 전까지 연기한다"는 이 결정으로
끝났다. 저장소 공개는 Publication Bundle 공개와 별개이며, 실제 샘플과 원본 로그는 계속
저장소에 포함하지 않는다(ADR-012).

