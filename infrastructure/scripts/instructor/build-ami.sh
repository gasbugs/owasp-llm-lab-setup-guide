#!/bin/bash
# 강사: 강의 D-7에 실행. 골든 AMI 빌드.
set -euo pipefail

cd "$(dirname "$0")/../../packer"

: "${AWS_PROFILE:=owasp-llm}"
: "${AWS_REGION:=us-east-1}"
: "${DOCKERHUB_NAMESPACE:?DOCKERHUB_NAMESPACE 환경변수 필요. 예: gasbugs}"

packer init ami.pkr.hcl
packer build \
  -var "aws_profile=$AWS_PROFILE" \
  -var "region=$AWS_REGION" \
  -var "dockerhub_namespace=$DOCKERHUB_NAMESPACE" \
  ami.pkr.hcl

AMI_ID=$(jq -r '.builds[-1].artifact_id | split(":")[1]' manifest.json)
echo
echo "=========================================="
echo "AMI 빌드 완료: $AMI_ID"
echo
echo "다음 단계:"
echo "  echo 'golden_ami_id = \"$AMI_ID\"' >> ../terraform/terraform.tfvars"
echo "=========================================="
