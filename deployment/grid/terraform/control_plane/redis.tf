# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/


locals {
  redis_engine_version = "7.0"
}

resource "aws_elasticache_cluster" "stdin_stdout_cache" {
  cluster_id           = "stdin-stdout-cache-${lower(local.suffix)}"
  engine               = "redis"
  node_type            = "cache.r7g.large"
  num_cache_nodes      = 1
  parameter_group_name = aws_elasticache_parameter_group.cache_config.name
  engine_version       = "7.0"
  port                 = 6379
  security_group_ids   = [aws_security_group.allow_incoming_redis.id]
  subnet_group_name    = "stdin-stdout-cache-subnet-${lower(local.suffix)}"

  # snapshot_window          = "06:00-08:00"
  snapshot_retention_limit = 1

  depends_on = [
    aws_elasticache_subnet_group.io_redis_subnet_group,
  ]
}


resource "aws_elasticache_subnet_group" "io_redis_subnet_group" {
  name       = "stdin-stdout-cache-subnet-${lower(local.suffix)}"
  subnet_ids = var.vpc_private_subnet_ids
}


resource "aws_security_group" "allow_incoming_redis" {
  name        = "redis-io-cache-${lower(local.suffix)}"
  description = "Allow inbound Redis access on tcp/6379"
  vpc_id      = var.vpc_id

  ingress {
    description = "Allow inbound Redis access on tcp/6379 from within VPC"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  ingress {
    description = "Allow inbound Redis access on tcp/6379 from allowed_access_cidr_blocks"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = var.allowed_access_cidr_blocks
  }

  egress {
    description = "Allow outbound Redis access to VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Allow outbound Redis access to allowed_access_cidr_blocks"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.allowed_access_cidr_blocks
  }
}


resource "aws_elasticache_parameter_group" "cache_config" {
  name   = "cache-config-${lower(local.suffix)}-${replace(local.redis_engine_version, ".", "-")}"
  family = "redis7"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }
}
