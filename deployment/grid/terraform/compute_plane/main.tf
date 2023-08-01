# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/

locals {
  # check if var.suffix is empty then create a random suffix else use var.suffix
  suffix = var.suffix != "" ? var.suffix : random_string.random_resources.result

  eks_worker_group = concat([
    for index in range(0, length(var.eks_worker_groups)) :
    merge(var.eks_worker_groups[index], {
      launch_template_os = "amazonlinux2eks"
      bootstrap_extra_args = "--kubelet-extra-args '--node-labels=grid/type=worker'"
      tags = {
        "aws-node-termination-handler/managed"          = "true"
        "k8s.io/cluster-autoscaler/enabled"             = "true"
        "k8s.io/cluster-autoscaler/${var.cluster_name}" = "true"
    } })
    ], [
    {
      node_group_name = "operator-ondemand",
      instance_types  = ["m6a.2xlarge", "m6i.2xlarge", "m6idn.2xlarge", "m6in.2xlarge", "m5.2xlarge"],
      capacity_type   = "ON_DEMAND",
      iam_role_additional_policies = {
        agent_permissions = aws_iam_policy.agent_permissions.arn
      }
      min_size             = 4,
      max_size             = 6,
      desired_size         = 4,
      launch_template_os   = "amazonlinux2eks"
      bootstrap_extra_args = "--kubelet-extra-args '--node-labels=grid/type=Operator --register-with-taints=grid/type=Operator:NoSchedule'"
    }
  ])
  
  eks_worker_group_name = [
    for index in range(0, length(local.eks_worker_group)) :
    local.eks_worker_group[index].node_group_name
  ]

  eks_worker_group_map = zipmap(local.eks_worker_group_name, local.eks_worker_group)
}

resource "random_string" "random_resources" {
  length  = 10
  special = false
  upper   = false
  # number = false
}

data "aws_caller_identity" "current" {}
