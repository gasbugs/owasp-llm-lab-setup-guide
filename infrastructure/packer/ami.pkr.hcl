################################################################################
# 골든 AMI — owasp-llm-lab (Podman rootless)
#
# Ubuntu 24.04 + NVIDIA Driver + CUDA 12.8 + Podman + nvidia-container-toolkit(CDI)
# + 강의용 컨테이너 이미지 사전 pull(Docker Hub) + 모델 weights 사전 다운로드
#
# 빌드:
#   packer init ami.pkr.hcl
#   packer build \
#     -var "aws_profile=owasp-llm" \
#     -var "region=ap-northeast-2" \
#     -var "dockerhub_namespace=<your-dockerhub-username-or-org>" \
#     -var "image_tag=sha-<40-character-main-commit>" \
#     ami.pkr.hcl
################################################################################

packer {
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = "~> 1.3"
    }
  }
}

variable "aws_profile" {
  type    = string
  default = "owasp-llm"
}

variable "region" {
  type    = string
  default = "ap-northeast-2"
}

variable "instance_type" {
  description = "AMI 빌드 시 사용할 인스턴스. GPU 인스턴스만 nvidia-container-toolkit 검증 가능."
  type        = string
  default     = "g6.xlarge"
}

variable "ssh_username" {
  type    = string
  default = "ubuntu"
}

variable "ami_name_prefix" {
  type    = string
  default = "owasp-llm-lab"
}

variable "default_model" {
  description = "Ollama가 사전 pull할 모델 ID"
  type        = string
  default     = "llama3.1:8b-instruct-q4_K_M"
}

variable "dockerhub_namespace" {
  description = "강의 이미지가 push되어 있는 Docker Hub 사용자명 또는 organization"
  type        = string
}

variable "image_tag" {
  description = "사전 pull할 불변 런타임 이미지 태그. sha-<40자리 lowercase Git commit> 필수"
  type        = string
  validation {
    condition     = can(regex("^sha-[0-9a-f]{40}$", var.image_tag))
    error_message = "Image tag는 sha-<40자리 lowercase Git commit> 형식이어야 합니다."
  }
}

locals {
  timestamp = formatdate("YYYYMMDDhhmmss", timestamp())
}

data "amazon-ami" "ubuntu" {
  filters = {
    name                = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
    root-device-type    = "ebs"
    virtualization-type = "hvm"
  }
  owners      = ["099720109477"] # Canonical
  most_recent = true
  profile     = var.aws_profile
  region      = var.region
}

source "amazon-ebs" "lab" {
  ami_name        = "${var.ami_name_prefix}-${local.timestamp}"
  ami_description = "OWASP Top 10 for LLM — Lab Golden AMI (Podman rootless + CUDA + models)"
  instance_type   = var.instance_type
  region          = var.region
  profile         = var.aws_profile
  source_ami      = data.amazon-ami.ubuntu.id
  ssh_username    = var.ssh_username

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_size           = 100
    volume_type           = "gp3"
    delete_on_termination = true
  }

  tags = {
    Name      = "${var.ami_name_prefix}-${local.timestamp}"
    Project   = "owasp-top-10-for-llm"
    Runtime   = "podman-rootless"
    BuildTime = local.timestamp
  }
}

build {
  name    = "owasp-llm-lab"
  sources = ["source.amazon-ebs.lab"]

  provisioner "shell" {
    script = "${path.root}/provisioners/10-system.sh"
  }

  provisioner "shell" {
    script            = "${path.root}/provisioners/20-nvidia.sh"
    expect_disconnect = true
  }

  provisioner "shell" {
    pause_before = "30s"
    script       = "${path.root}/provisioners/30-podman.sh"
  }

  provisioner "shell" {
    script = "${path.root}/provisioners/40-pull-images.sh"
    environment_vars = [
      "DEFAULT_MODEL=${var.default_model}",
      "DOCKERHUB_NAMESPACE=${var.dockerhub_namespace}",
      "IMAGE_TAG=${var.image_tag}",
    ]
  }

  post-processor "manifest" {
    output = "manifest.json"
  }
}
