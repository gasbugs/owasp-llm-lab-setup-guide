#!/bin/bash
# Local laptop preflight before Terraform apply and daily lab operations.
#
# Usage:
#   AWS_PROFILE=owasp-llm AWS_REGION=us-east-1 \
#     bash infrastructure/scripts/student/preflight-local.sh
set -euo pipefail

: "${AWS_PROFILE:=owasp-llm}"
: "${AWS_REGION:=us-east-1}"
: "${REQUIRED_G_VCPU:=4}"

missing=0
quota_warning=0

need_cmd() {
  local cmd="$1"
  local hint="$2"
  if command -v "$cmd" >/dev/null 2>&1; then
    printf "OK   %-24s %s\n" "$cmd" "$("$cmd" --version 2>/dev/null | head -1 || true)"
  else
    printf "MISS %-24s %s\n" "$cmd" "$hint"
    missing=1
  fi
}

need_cmd aws "Install AWS CLI v2."
need_cmd terraform "Install Terraform v1.x or later."
need_cmd jq "Install jq for JSON output parsing."
need_cmd unzip "Install unzip to extract the student package."
need_cmd shasum "Install Perl shasum or use sha256sum equivalent."

if command -v session-manager-plugin >/dev/null 2>&1; then
  echo "OK   session-manager-plugin installed"
else
  echo "MISS session-manager-plugin Install AWS Session Manager Plugin for SSM access."
  missing=1
fi

if [ "$missing" -ne 0 ]; then
  echo
  echo "Preflight failed: install the missing local tools, then rerun this script."
  exit 1
fi

echo
echo "Checking AWS credentials: profile=$AWS_PROFILE region=$AWS_REGION"
STS_JSON=$(mktemp "${TMPDIR:-/tmp}/sts-check.XXXXXX")
STS_ERR=$(mktemp "${TMPDIR:-/tmp}/sts-check.err.XXXXXX")
QUOTA_JSON=$(mktemp "${TMPDIR:-/tmp}/quota-check.XXXXXX")
QUOTA_ERR=$(mktemp "${TMPDIR:-/tmp}/quota-check.err.XXXXXX")
cleanup() {
  rm -f "$STS_JSON" "$STS_ERR" "$QUOTA_JSON" "$QUOTA_ERR"
}
trap cleanup EXIT

if ! aws sts get-caller-identity --profile "$AWS_PROFILE" --region "$AWS_REGION" >"$STS_JSON" 2>"$STS_ERR"; then
  echo "ERROR: AWS credentials are not ready."
  echo "Run one of the following, then retry:"
  echo "  aws configure --profile $AWS_PROFILE"
  echo "  aws sso login --profile $AWS_PROFILE"
  echo
  cat "$STS_ERR"
  exit 1
fi

jq -r '"OK   AWS account: \(.Account) / principal: \(.Arn)"' "$STS_JSON"

echo
echo "Checking EC2 G/VT instance quota: required=${REQUIRED_G_VCPU} vCPU"
if aws service-quotas get-service-quota \
  --profile "$AWS_PROFILE" \
  --region "$AWS_REGION" \
  --service-code ec2 \
  --quota-code L-DB2E81BA \
  >"$QUOTA_JSON" 2>"$QUOTA_ERR"; then
  quota_value=$(jq -r '.Quota.Value // 0' "$QUOTA_JSON")
  if jq -e --argjson required "$REQUIRED_G_VCPU" '(.Quota.Value // 0) >= $required' "$QUOTA_JSON" >/dev/null; then
    echo "OK   Running On-Demand G and VT instances quota: ${quota_value} vCPU"
  else
    echo "ERROR: Running On-Demand G and VT instances quota is ${quota_value} vCPU."
    echo "Request at least ${REQUIRED_G_VCPU} vCPU before terraform apply."
    echo "AWS Console: Service Quotas > EC2 > Running On-Demand G and VT instances"
    exit 1
  fi
else
  echo "WARN Could not read EC2 G/VT quota automatically."
  echo "     Manually confirm Service Quotas > EC2 > Running On-Demand G and VT instances >= ${REQUIRED_G_VCPU} vCPU."
  cat "$QUOTA_ERR"
  quota_warning=1
fi

echo
if [ "$quota_warning" -eq 0 ]; then
  echo "Preflight PASS. You can continue with terraform init/plan/apply."
else
  echo "Preflight PASS with quota warning. Resolve the warning before terraform apply."
fi
