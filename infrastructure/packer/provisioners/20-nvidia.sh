#!/bin/bash
# NVIDIA Driver + CUDA Toolkit 12.5
# 설치 후 재부팅 필요 (Packer가 expect_disconnect으로 처리)
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# NVIDIA 공식 repo — Ubuntu 24.04
distribution=$(. /etc/os-release; echo $ID$VERSION_ID | tr -d .)
wget -q https://developer.download.nvidia.com/compute/cuda/repos/${distribution}/x86_64/cuda-keyring_1.1-1_all.deb
sudo dpkg -i cuda-keyring_1.1-1_all.deb
rm cuda-keyring_1.1-1_all.deb

sudo apt-get update -y

# Driver + Toolkit
sudo apt-get install -y --no-install-recommends \
  cuda-toolkit-12-8 \
  cuda-drivers

# nvidia-container-toolkit (CDI 모드 권장)
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
  sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
  sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list

sudo apt-get update -y
sudo apt-get install -y --no-install-recommends nvidia-container-toolkit

# CUDA 환경변수
echo 'export PATH=/usr/local/cuda-12.8/bin:$PATH' | sudo tee -a /etc/profile.d/cuda.sh
echo 'export LD_LIBRARY_PATH=/usr/local/cuda-12.8/lib64:${LD_LIBRARY_PATH:-}' | sudo tee -a /etc/profile.d/cuda.sh
sudo chmod 0644 /etc/profile.d/cuda.sh

# 재부팅 — Packer가 자동 재접속
sudo reboot
