#!/bin/bash
# Docker Engine + Compose v2 + NVIDIA runtime 설정
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Docker 공식 repo
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin

# ubuntu 사용자에 docker 그룹
sudo usermod -aG docker ubuntu

# NVIDIA runtime — Docker daemon에 등록
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

# 확인 (실패해도 빌드 계속)
sudo docker run --rm --gpus all nvidia/cuda:12.5.0-base-ubuntu24.04 nvidia-smi || \
  echo "WARN: nvidia-smi in container failed, will retry at instance launch"
