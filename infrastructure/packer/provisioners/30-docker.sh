#!/bin/bash
# Docker Engine + Docker Compose v2 + NVIDIA Container Toolkit setup.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
DOCKER_ENGINE_RELEASE="${DOCKER_ENGINE_RELEASE:-29.7.2}"
DOCKER_COMPOSE_RELEASE="${DOCKER_COMPOSE_RELEASE:-5.5.0}"

sudo apt-get update -y
sudo apt-get install -y --no-install-recommends ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
. /etc/os-release
printf 'Types: deb\nURIs: https://download.docker.com/linux/ubuntu\nSuites: %s\nComponents: stable\nArchitectures: %s\nSigned-By: /etc/apt/keyrings/docker.asc\n' \
  "$VERSION_CODENAME" "$(dpkg --print-architecture)" \
  | sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null
sudo apt-get update -y
DOCKER_ENGINE_VERSION="5:${DOCKER_ENGINE_RELEASE}-1~ubuntu.${VERSION_ID}~${VERSION_CODENAME}"
DOCKER_COMPOSE_VERSION="${DOCKER_COMPOSE_RELEASE}-1~ubuntu.${VERSION_ID}~${VERSION_CODENAME}"
sudo apt-get install -y \
  "docker-ce=$DOCKER_ENGINE_VERSION" \
  "docker-ce-cli=$DOCKER_ENGINE_VERSION" \
  containerd.io docker-buildx-plugin \
  "docker-compose-plugin=$DOCKER_COMPOSE_VERSION"

sudo systemctl enable --now docker
sudo usermod -aG docker ubuntu
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker

sudo docker info >/dev/null
sudo docker run --rm --gpus all \
  docker.io/nvidia/cuda:12.8.2-base-ubuntu24.04 nvidia-smi
