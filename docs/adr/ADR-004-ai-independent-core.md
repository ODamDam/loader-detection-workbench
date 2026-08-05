# ADR-004-ai-independent-core: AI 비의존 핵심 파이프라인

## 상태
승인

## 배경
API Key, 네트워크, 모델 품질에 따라 핵심 기능이 중단되어서는 안 된다.

## 결정
ManualProvider와 MockProvider를 먼저 제공하고 외부 API·로컬 LLM은 교체 가능한 Provider로 추가한다.

## 결과
시연과 재현성이 향상되며 AI는 선택적 보조 기능이 된다.
