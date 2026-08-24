# Amazon Bedrock API Lab

이 디렉터리는 기존 GPU EC2 실습과 독립된 Amazon Bedrock 후반부 API 실습 자료입니다. 기존 `infrastructure/`와 `examples/`를 수정하거나 재사용하지 않습니다.

- `knowledge-base/`: 수강생이 읽고 직접 실행하는 정책 원문과 S3 문서
- `runtime/tool_demo.py`: Nova Lite Converse Tool Use 호출 예제

Nova Lite와 Titan Text Embeddings V2는 On-Demand API이므로 Terraform으로 모델 서버를 생성하지 않습니다. Nova Lite는 답변을 생성하고, Titan은 텍스트를 1024차원 의미 벡터로 변환합니다. AWS 자격 증명 준비는 과정 운영자가 별도로 안내하며 자격 증명을 저장소나 이미지에 넣지 않습니다.

Knowledge Base 실습 리소스도 Terraform이나 래퍼 스크립트에 포함하지 않습니다. 수강생은 07장에서 정책 원문을 읽고 AWS CLI 명령을 단계별로 직접 실행합니다.

07장의 Knowledge Base는 튜토리얼 종료 때 삭제하며 08장으로 넘기지 않습니다. 08장은
`llm-security-control-plane/deploy/restore-module08-aws.sh`가 별도 접두사의 실습 상태를
복구합니다. NeMo Guardrails가 흐름을 조정하고 Amazon Nova Lite Content Safety와
애플리케이션 Self-check가 서로 다른 정책 prompt를 실행하며 Microsoft Presidio가
개인정보를 탐지·비식별화합니다. 실제 Llama Guard나 로컬 Ollama는 사용하지 않습니다.
