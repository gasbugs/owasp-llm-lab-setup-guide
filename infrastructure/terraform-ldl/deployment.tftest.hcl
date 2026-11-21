mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111111111111" }
  }

  mock_data "aws_vpc" {
    defaults = { id = "vpc-00000000000000000" }
  }

  mock_data "aws_subnets" {
    defaults = { ids = ["subnet-00000000000000000"] }
  }

  mock_data "aws_ami" {
    defaults = { id = "ami-00000000000000000" }
  }
}

run "isolated_ldl_deployment" {
  command = plan

  variables {
    learner_ipv4_cidr = "198.51.100.10/32"
  }

  assert {
    condition     = aws_instance.ldl.instance_type == "m6a.large" && aws_instance.ldl.iam_instance_profile == "owasp-llm-ldl-ec2"
    error_message = "The dedicated LDL instance must have the requested type and role."
  }

  assert {
    condition     = length(aws_security_group.ldl.ingress) == 1 && one(aws_security_group.ldl.ingress).from_port == 9010 && one(aws_security_group.ldl.ingress).to_port == 9015 && toset(one(aws_security_group.ldl.ingress).cidr_blocks) == toset(["198.51.100.10/32"])
    error_message = "Only the learner's web traffic may reach the LDL security group."
  }

  assert {
    condition     = one(aws_instance.ldl.metadata_options).http_tokens == "required" && one(aws_instance.ldl.metadata_options).http_put_response_hop_limit == 2 && one(aws_instance.ldl.root_block_device).encrypted
    error_message = "IMDSv2 and encrypted storage must be enabled."
  }

  assert {
    condition     = jsondecode(aws_iam_role_policy.model.policy).Statement[0].Action == "bedrock:InvokeModel" && length(jsondecode(aws_iam_role_policy.model.policy).Statement[0].Resource) == 4
    error_message = "The LDL role must only invoke its inference profile and underlying Nova Lite models."
  }
}

run "reject_open_inbound" {
  command = plan

  variables {
    learner_ipv4_cidr = "0.0.0.0/0"
  }

  expect_failures = [var.learner_ipv4_cidr]
}
