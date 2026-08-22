# Bedrock Guardrails Lab

이 디렉터리는 기존 GPU EC2 실습과 독립된 Amazon Bedrock 후반부 실습 환경입니다. 기존 `infrastructure/`와 `examples/`를 수정하거나 재사용하지 않습니다.

- `terraform/`: Bedrock Guardrail과 고정 버전만 생성
- `scripts/`: Knowledge Base와 S3 Vectors를 AWS CLI로 생성·삭제
- `runtime/`: Nova Lite 직접 호출과 Guardrail 적용을 비교하는 loopback API
- `tests/`: CLI·HTTP E2E 검증

Nova Lite와 Titan Text Embeddings V2는 On-Demand API이므로 Terraform으로 모델 서버를 생성하지 않습니다. Nova Lite는 답변을 생성하고, Titan은 텍스트를 1024차원 의미 벡터로 변환합니다. AWS 자격 증명 준비는 과정 운영자가 별도로 안내하며 자격 증명을 저장소나 이미지에 넣지 않습니다.

Knowledge Base 실습 리소스는 Terraform에 포함하지 않습니다. 07장에서
`./scripts/setup-knowledge-base.sh`로 만들고, 08장 검증 후
`./scripts/delete-knowledge-base.sh`로 제거합니다.

```bash
cd bedrock-guardrails-lab/terraform
terraform init
terraform apply -auto-approve

cd ..
podman build -t localhost/bedrock-guardrail-gateway:1.0.0 runtime
GUARDRAIL_ID=$(terraform -chdir=terraform output -raw guardrail_id)
GUARDRAIL_VERSION=$(terraform -chdir=terraform output -raw guardrail_version)
podman run -d --replace --name bedrock-guardrail-gateway \
  -p 127.0.0.1:18097:8080 \
  -e AWS_REGION=us-east-1 \
  -e AWS_PROFILE="${AWS_PROFILE:-default}" \
  -e BEDROCK_MODEL_ID=us.amazon.nova-lite-v1:0 \
  -e BEDROCK_EMBEDDING_MODEL_ID=amazon.titan-embed-text-v2:0 \
  -e BEDROCK_EMBEDDING_DIMENSIONS=1024 \
  -e BEDROCK_GUARDRAIL_ID="$GUARDRAIL_ID" \
  -e BEDROCK_GUARDRAIL_VERSION="$GUARDRAIL_VERSION" \
  -v "$HOME/.aws:/root/.aws:ro,Z" \
  localhost/bedrock-guardrail-gateway:1.0.0
```

`POST /api/guarded-chat`은 Nova Lite 생성 요청에 Guardrail 적용 여부를 비교하고, `POST /api/embed`은 Titan Text Embeddings V2가 반환한 1024차원 벡터를 확인합니다.

종료 후에는 컨테이너와 Terraform 리소스를 각각 제거합니다.

```bash
podman rm -f bedrock-guardrail-gateway
terraform -chdir=terraform destroy -auto-approve
```
