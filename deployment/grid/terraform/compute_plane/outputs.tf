# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/


output "cluster_name" {
  description = "EKS Cluster Name"
  value       = module.eks.cluster_name
}

output "cluster_endpoint" {
  description = "Endpoint for EKS control plane."
  value       = module.eks.cluster_endpoint
}

output "oidc_provider_arn" {
  description = "OIDC Provider ARN for the EKS Cluster"
  value       = module.eks.oidc_provider_arn
}

output "certificate_authority" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = module.eks.cluster_certificate_authority_data
}

# output "token" {
#   description = "authentication token for EKS"
#   value       = data.aws_eks_cluster_auth.cluster.token
#   sensitive   = true
# }


output "eks_managed_node_groups" {
  description = "Map of EKS Managed Node Group outputs"
  value       = try(module.eks.eks_managed_node_groups, {})
}

output "eks_managed_node_groups_autoscaling_group_names" {
  description = "List of EKS Managed Node Groups names"
  value       = try(module.eks.eks_managed_node_groups_autoscaling_group_names, [])
}

output "self_managed_node_groups" {
  description = "Map of self-managed node group outputs"
  value       = try(module.eks.self_managed_node_groups, {})
}

output "self_managed_node_groups_autoscaling_group_names" {
  description = "List of self-managed node groups names"
  value       = try(module.eks.self_managed_node_groups_autoscaling_group_names, [])
}

output "nlb_influxdb" {
  description = "url of the NLB in front of the influx DB"
  value       = try(data.kubernetes_service.influxdb_load_balancer.status.0.load_balancer.0.ingress.0.hostname, "")
}

output "cognito_userpool_arn" {
  description = "url of the NLB in front of the influx DB"
  value       = aws_cognito_user_pool.htc_pool.arn
}

output "cognito_userpool_id" {
  description = "url of the NLB in front of the influx DB"
  value       = aws_cognito_user_pool.htc_pool.id
}

output "cognito_userpool_client_id" {
  description = "url of the NLB in front of the influx DB"
  value       = aws_cognito_user_pool_client.user_data_client.id
}