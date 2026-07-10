#!/bin/bash
# Podman rootless + NVIDIA CDI runtime setup.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
  podman \
  crun \
  fuse-overlayfs \
  slirp4netns \
  uidmap

sudo touch /etc/containers/nodocker
grep -q '^ubuntu:' /etc/subuid || echo 'ubuntu:100000:65536' | sudo tee -a /etc/subuid
grep -q '^ubuntu:' /etc/subgid || echo 'ubuntu:100000:65536' | sudo tee -a /etc/subgid
sudo loginctl enable-linger ubuntu

sudo install -d -m 0755 /etc/cdi
sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
test -s /etc/cdi/nvidia.yaml

sudo -u ubuntu -i podman info --format '{{.Host.Security.Rootless}}' | grep -qx true
sudo -u ubuntu -i podman run --rm \
  --device nvidia.com/gpu=all \
  docker.io/nvidia/cuda:12.8.2-base-ubuntu24.04 nvidia-smi
