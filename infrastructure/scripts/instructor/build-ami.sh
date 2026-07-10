#!/bin/bash
# 강사: 골든 AMI 빌드.
# 사용: DOCKERHUB_NAMESPACE=gasbugs IMAGE_TAG=sha-<40자리-main-commit> ./build-ami.sh
set -euo pipefail

cd "$(dirname "$0")/../../packer"

: "${AWS_PROFILE:=owasp-llm}"
: "${AWS_REGION:=us-east-1}"
: "${DOCKERHUB_NAMESPACE:?DOCKERHUB_NAMESPACE 환경변수 필요. 예: gasbugs}"
: "${IMAGE_TAG:?IMAGE_TAG 환경변수 필요. 예: sha-<40자리-main-commit>}"

if [[ ! "$IMAGE_TAG" =~ ^sha-[0-9a-f]{40}$ ]]; then
  echo "ERROR: IMAGE_TAG는 sha-<40자리 lowercase Git commit> 형식이어야 합니다." >&2
  exit 2
fi

packer init ami.pkr.hcl
packer build \
  -var "aws_profile=$AWS_PROFILE" \
  -var "region=$AWS_REGION" \
  -var "dockerhub_namespace=$DOCKERHUB_NAMESPACE" \
  -var "image_tag=$IMAGE_TAG" \
  ami.pkr.hcl

AMI_ID=$(jq -r '.builds[-1].artifact_id | split(":")[1]' manifest.json)
echo
echo "=========================================="
echo "AMI 빌드 완료: $AMI_ID"
echo "사전 적재 이미지 태그: $IMAGE_TAG"
echo
echo "다음 단계:"
echo "  echo 'ami_owner_id = \"self\"' >> ../terraform/terraform.tfvars"
echo "  echo 'ami_name_pattern = \"owasp-llm-lab-*\"' >> ../terraform/terraform.tfvars"
echo
echo "방금 생성된 AMI ID 참고값:"
echo "  $AMI_ID"
echo "=========================================="
