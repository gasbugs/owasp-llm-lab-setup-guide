# Amazon Bedrock API Lab

이 디렉터리는 기존 GPU EC2 실습과 독립된 Amazon Bedrock 후반부 API 실습 자료입니다. 기존 `infrastructure/`와 `examples/`를 수정하거나 재사용하지 않습니다.

- `knowledge-base/`: 수강생이 읽고 직접 실행하는 정책 원문과 S3 문서
- `runtime/tool_demo.py`: Nova Lite Converse Tool Use 호출 예제

Nova Lite와 Titan Text Embeddings V2는 On-Demand API이므로 Terraform으로 모델 서버를 생성하지 않습니다. Nova Lite는 답변을 생성하고, Titan은 텍스트를 1024차원 의미 벡터로 변환합니다. AWS 자격 증명 준비는 과정 운영자가 별도로 안내하며 자격 증명을 저장소나 이미지에 넣지 않습니다.

Knowledge Base 실습 리소스도 Terraform이나 래퍼 스크립트에 포함하지 않습니다. 수강생은 07장에서 정책 원문을 읽고 AWS CLI 명령을 단계별로 직접 실행합니다.

08장의 보호 계층은 AWS 관리형 정책 리소스를 만들거나 호출하지 않습니다. NeMo Guardrails가 흐름을 조정하고 로컬 Llama Guard가 위해 콘텐츠를 분류하며 Microsoft Presidio가 개인정보를 탐지·비식별화합니다. 07~09장에서 Bedrock은 생성 모델, 임베딩과 Knowledge Base API 호출에만 사용합니다.
