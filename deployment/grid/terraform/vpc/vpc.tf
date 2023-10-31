# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/


locals {
  allowed_access_cidr_blocks = ["0.0.0.0/0"] #concat(var.allowed_access_cidr_blocks, ["10.0.0.0/16", "0.0.0.0/0"])
  allowed_access_ports       = [0]           #[0, 80, 443, 6379, 10250]
}


module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"

  name               = "${var.cluster_name}-vpc"
  cidr               = "10.0.0.0/16"
  azs                = data.aws_availability_zones.available.names
  private_subnets    = local.private_subnets
  public_subnets     = local.public_subnets
  enable_nat_gateway = !var.enable_private_subnet
  single_nat_gateway = !var.enable_private_subnet
  # Required for private endpoints
  enable_dns_hostnames = true
  enable_dns_support   = true

  default_security_group_ingress = [
    {
      description = "HTTPS Ingress from within VPC"
      type        = "ingress"
      self        = true
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = "10.0.0.0/16"
    }
  ]

  default_security_group_egress = [
    {
      description      = "Default allow ALL Egress"
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = "0.0.0.0/0" #var.allowed_access_cidr_blocks
      ipv6_cidr_blocks = "::/0"
    }
  ]

  # default_security_group_egress = flatten([
  #   for cidr_block in var.allowed_access_cidr_blocks : [
  #     {
  #       description = "Allow ALL Egress to ${cidr_block}"
  #       protocol    = "-1"
  #       from_port   = 0
  #       to_port     = 0
  #       type        = "egress"
  #       cidr_blocks = cidr_block
  #       # ipv6_cidr_blocks = "::/0"
  #     }
  #   ]
  # ])

  # default_network_acl_ingress = flatten([
  #   for cidr_block in local.allowed_access_cidr_blocks : [for port in local.allowed_access_ports :
  #     {
  #       action     = "allow",
  #       cidr_block = cidr_block,
  #       from_port  = port,
  #       to_port    = port,
  #       protocol   = "tcp",
  #       rule_no    = index(local.allowed_access_cidr_blocks, cidr_block) * length(local.allowed_access_ports) + index(local.allowed_access_ports, port) + 100
  #     }
  #   ]
  # ])

  # Disable dedicated Private Subnet ACL (as using default)
  private_dedicated_network_acl = false
  private_inbound_acl_rules     = []
  private_outbound_acl_rules    = []

  # Disable dedicated Public Subnet ACL (as using default)
  public_dedicated_network_acl = false
  public_inbound_acl_rules     = []
  public_outbound_acl_rules    = []

  # Cloudwatch log group and IAM role will be created
  enable_flow_log                      = true
  create_flow_log_cloudwatch_log_group = true
  create_flow_log_cloudwatch_iam_role  = true

  flow_log_max_aggregation_interval         = 60
  flow_log_cloudwatch_log_group_name_prefix = "/aws/vpc-flow-logs/"
  flow_log_cloudwatch_log_group_name_suffix = var.cluster_name

  tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
  }

  public_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                    = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"           = "1"
  }
}


module "vpc_endpoints" {
  source  = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "~> 5.0"

  vpc_id             = module.vpc.vpc_id
  security_group_ids = [module.vpc.default_security_group_id]
  create             = true

  endpoints = merge({
    s3 = {
      service         = "s3"
      service_type    = "Gateway"
      route_table_ids = flatten([module.vpc.intra_route_table_ids, module.vpc.private_route_table_ids, module.vpc.public_route_table_ids])
    }
    dynamodb = {
      service         = "dynamodb"
      service_type    = "Gateway"
      route_table_ids = flatten([module.vpc.intra_route_table_ids, module.vpc.private_route_table_ids, module.vpc.public_route_table_ids])
    }
    },
    { for service in toset(["autoscaling", "ecr.api", "ecr.dkr", "ec2", "elasticloadbalancing", "eks", "execute-api", "logs", "monitoring", "sqs", "sts", "ssm", "ssmmessages"]) :
      replace(service, ".", "_") =>
      {
        service             = service
        private_dns_enabled = var.enable_private_subnet
        subnet_ids          = var.enable_private_subnet == true ? module.vpc.private_subnets : []
        security_group_ids  = var.enable_private_subnet == true ? [module.vpc.default_security_group_id] : []
      }
  })
}
