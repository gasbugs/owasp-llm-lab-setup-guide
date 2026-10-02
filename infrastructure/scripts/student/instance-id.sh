#!/bin/bash
# Select exactly one tagged EC2, including stopped instances. Refuse legacy ASGs.
set -euo pipefail

: "${AWS_PROFILE:?usage: AWS_PROFILE=<profile> AWS_REGION=<region> bash instance-id.sh}"
: "${AWS_REGION:=us-east-1}"

if ! command -v aws >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
  echo "ERROR: required commands: aws and jq" >&2
  exit 1
fi

if ! aws sts get-caller-identity --profile "$AWS_PROFILE" --region "$AWS_REGION" >/dev/null 2>&1; then
  echo "ERROR: AWS credentials are not ready for profile '$AWS_PROFILE' in region '$AWS_REGION'." >&2
  echo "Run aws configure --profile $AWS_PROFILE or aws sso login --profile $AWS_PROFILE, then retry." >&2
  exit 1
fi

FILTERS=("Name=tag:Project,Values=owasp-top-10-for-llm"
  "Name=instance-state-name,Values=pending,running,stopping,stopped")
if [ -n "${COURSE_ID:-}" ]; then
  [[ "$COURSE_ID" =~ ^[a-z0-9-]{3,40}$ ]] || { echo "ERROR: invalid COURSE_ID" >&2; exit 1; }
  FILTERS+=("Name=tag:Course,Values=$COURSE_ID")
fi
ROWS=$(aws ec2 describe-instances \
  --profile "$AWS_PROFILE" --region "$AWS_REGION" \
  --filters "${FILTERS[@]}" \
  --query "Reservations[].Instances[].{id:InstanceId,asg:Tags[?Key=='aws:autoscaling:groupName'].Value|[0]}" \
  --output json)
COUNT=$(jq -er 'if type == "array" then length else error("invalid EC2 response") end' <<<"$ROWS")
if [ "$COUNT" -ne 1 ]; then
  echo "ERROR: expected exactly one lab EC2 in $AWS_REGION; found $COUNT. Check the account, region and COURSE_ID." >&2
  exit 1
fi
if jq -e '.[0].asg != null' <<<"$ROWS" >/dev/null; then
  echo "ERROR: legacy ASG instance; stop/start is unsafe while managed by Auto Scaling. See docs/TERRAFORM-ADVANCED-OPTIONS.md." >&2
  exit 1
fi
jq -er '.[0].id | select(test("^i-[0-9a-f]+$"))' <<<"$ROWS"
