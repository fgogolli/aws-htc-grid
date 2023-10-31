# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/


locals {
  # check if var.suffix is empty then create a random suffix else use var.suffix
  suffix               = var.suffix != "" ? var.suffix : random_string.random.result
  account_id           = data.aws_caller_identity.current.account_id
  dns_suffix           = data.aws_partition.current.dns_suffix
  partition            = data.aws_partition.current.partition
  lambda_build_runtime = "${var.aws_htc_ecr}/ecr-public/sam/build-${var.lambda_runtime}:1"
  sqs_queues_arns      = join(", ", concat([for queue in aws_sqs_queue.htc_task_queue : queue.arn], [aws_sqs_queue.htc_task_queue_dlq.arn]))
}


# Retrieve the account ID
data "aws_caller_identity" "current" {}


# Retrieve AWS Partition
data "aws_partition" "current" {}


resource "random_string" "random" {
  length  = 10
  special = false
  upper   = false
}


# Lambda CloudWatch Config & Permissions
resource "aws_cloudwatch_log_group" "global_error_group" {
  name              = var.error_log_group
  retention_in_days = 14
}


resource "aws_cloudwatch_log_stream" "global_error_stream" {
  name           = var.error_logging_stream
  log_group_name = aws_cloudwatch_log_group.global_error_group.name
}
