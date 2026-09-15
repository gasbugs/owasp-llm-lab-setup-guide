################################################################################
# 네트워크 — IGW 통한 인터넷 액세스 (검증/빌드용)
#
# 설계 메모:
#   - 검증 단계엔 외부 인터넷 허용 (Ubuntu repo, GHCR, Ollama 등 pull)
#   - 강의 정식 운영 시 골든 AMI(Packer)로 변경하면 인터넷 차단으로 회귀 가능
#   - VPC endpoint는 사용하지 않는다. SSM과 이미지 pull은 public egress 사용.
#   - 수강생별 보안 그룹은 지정한 공인 IPv4 /32 한 곳의 전체 트래픽만 허용
################################################################################

resource "aws_vpc" "main" {
  cidr_block           = "10.42.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  available_gpu_zones = sort(tolist(setintersection(
    toset(data.aws_availability_zones.available.names),
    toset(data.aws_ec2_instance_type_offerings.gpu.locations),
  )))
  selected_availability_zones = local.available_gpu_zones
}

data "aws_ec2_instance_type_offerings" "gpu" {
  filter {
    name   = "instance-type"
    values = [var.instance_type]
  }

  location_type = "availability-zone"
}

resource "aws_subnet" "lab" {
  for_each = { for index, zone in local.selected_availability_zones : zone => index }

  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(aws_vpc.main.cidr_block, 8, each.value + 10)
  availability_zone       = each.key
  map_public_ip_on_launch = true # 검증 단계 — 인스턴스가 직접 인터넷 접근

  tags = {
    Name = "${local.name_prefix}-subnet-${each.key}"
  }

  lifecycle {
    precondition {
      condition     = length(local.selected_availability_zones) > 0
      error_message = "${var.region}에서 ${var.instance_type}을 제공하는 가용 영역을 찾지 못했습니다."
    }

  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-igw"
  }
}

resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${local.name_prefix}-rt"
  }
}

resource "aws_route_table_association" "lab" {
  for_each = aws_subnet.lab

  subnet_id      = each.value.id
  route_table_id = aws_route_table.lab.id
}

################################################################################
# Security Group — 계정당 1개, 지정한 공인 IPv4 /32만 허용
################################################################################

resource "aws_security_group" "student" {
  name        = "${local.name_prefix}-sg"
  description = "Lab ingress restricted to one public IPv4 /32"
  vpc_id      = aws_vpc.main.id

  # 포트별 규칙을 늘리지 않고 실습자의 현재 공인 IPv4 /32 하나만 신뢰한다.
  # 이 주소에서 들어오는 모든 IP 프로토콜과 포트를 하나의 규칙으로 허용한다.
  ingress {
    description = "All traffic from the student's public IPv4 /32"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.allowed_ingress_cidr]
  }

  egress {
    description = "Internet egress (apt/docker/ollama pull, SSM, CloudWatch logs)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-sg"
  }
}

# VPC Endpoint 제거 — IGW + public IP로 외부 통신.
# S3 endpoint도 제거 (S3 자체를 안 씀).
