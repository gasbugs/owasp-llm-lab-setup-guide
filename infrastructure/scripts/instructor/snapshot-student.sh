#!/bin/bash
# DEPRECATED — 현재 1인 1계정 운영 모델에서는 사용하지 않는다.
#
# 강사는 학생 AWS 계정의 EBS에 접근하지 않는다. 스냅샷이 꼭 필요하면
# 학생 본인이 본인 계정에서 직접 생성한다.
#
# 학생 본인이 snapshot 만드는 법 (필요 시):
#   aws ec2 create-snapshot \
#     --volume-id $(aws ec2 describe-instances --instance-ids <my-instance> \
#       --query 'Reservations[0].Instances[0].BlockDeviceMappings[0].Ebs.VolumeId' --output text) \
#     --description "manual snapshot $(date -Iseconds)"
#
# 보통은 불필요 — 작업물은 개인 GitHub 작업 repo에 push로 영구 보존.

echo "이 스크립트는 deprecate됨. 1인 1계정 모델에서 강사는 학생 자원에 접근 불가."
echo "학생 본인이 작업물을 영구 보존하려면 개인 GitHub 작업 repo에 git push."
exit 1
