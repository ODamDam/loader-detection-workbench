# ADR-016-exe-first: MVP 자동 실행 형식은 Windows PE EXE

## 상태
승인

## 배경
다양한 문서·스크립트·DLL 실행 형식을 동시에 지원하면 자동화 복잡도가 급증한다.

## 결정
MVP 자동 실행은 Windows PE `.exe`로 제한하고 다른 형식은 ExecutionProfile 확장 후보로 둔다.

## 결과
6개 케이스 완주 가능성을 높이고 향후 확장 경계를 유지한다.
