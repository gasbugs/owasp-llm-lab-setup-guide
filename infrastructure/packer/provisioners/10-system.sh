#!/bin/bash
# 시스템 기본 — apt 업데이트, 필수 패키지, 사용자 권한, SSM 에이전트
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -y
sudo apt-get upgrade -y

sudo apt-get install -y --no-install-recommends \
  curl \
  ca-certificates \
  gnupg \
  lsb-release \
  git \
  jq \
  unzip \
  tmux \
  htop \
  build-essential \
  python3 \
  python3-venv \
  python3-pip

# AWS CLI v2
curl -sSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
unzip -q /tmp/awscliv2.zip -d /tmp/
sudo /tmp/aws/install --update
rm -rf /tmp/aws /tmp/awscliv2.zip

# SSM 에이전트 (Ubuntu 24.04 snap 기본, 확인만)
sudo snap list amazon-ssm-agent || sudo snap install amazon-ssm-agent --classic
sudo snap start amazon-ssm-agent || true

# 디스크 정리
sudo apt-get autoremove -y
sudo apt-get clean
