# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/


locals {
  cognito_domain_name = replace("${lower(var.suffix)}-${random_string.random.result}", "aws", "")
}


resource "aws_cognito_user_pool" "htc_pool" {
  name = "htc_pool"
  account_recovery_setting {
    recovery_mechanism {
      name     = "admin_only"
      priority = 1
    }
  }

  admin_create_user_config {
    allow_admin_create_user_only = true
  }
}


resource "aws_cognito_user_pool_domain" "domain" {
  user_pool_id = aws_cognito_user_pool.htc_pool.id
  domain       = local.cognito_domain_name
}


resource "aws_cognito_user_pool_client" "user_data_client" {
  name         = "user_data_client"
  user_pool_id = aws_cognito_user_pool.htc_pool.id
  explicit_auth_flows = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]
}


resource "aws_cognito_user_pool_client" "grafana" {
  name                                 = "grafana"
  user_pool_id                         = aws_cognito_user_pool.htc_pool.id
  allowed_oauth_flows_user_pool_client = true
  generate_secret                      = true
  allowed_oauth_flows                  = ["code"]
  callback_urls                        = ["https://${data.kubernetes_ingress_v1.grafana_ingress.status.0.load_balancer.0.ingress.0.hostname}/oauth2/idpresponse"]
  allowed_oauth_scopes = [
    "email", "openid"
  ]
  supported_identity_providers = [
    "COGNITO",
  ]
  explicit_auth_flows = [
    "ALLOW_ADMIN_USER_PASSWORD_AUTH",
    "ALLOW_USER_SRP_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH"
  ]
}


resource "aws_cognito_user" "grafana_admin" {
  user_pool_id       = aws_cognito_user_pool.htc_pool.id
  username           = "admin"
  temporary_password = var.grafana_admin_password
}


resource "kubernetes_annotations" "grafana_ingress_auth" {
  api_version = "networking.k8s.io/v1"
  kind        = "Ingress"

  metadata {
    name      = helm_release.this["grafana"].name
    namespace = helm_release.this["grafana"].namespace
  }

  annotations = {
    "alb.ingress.kubernetes.io/auth-idp-cognito"                = "{\"UserPoolArn\": \"${aws_cognito_user_pool.htc_pool.arn}\",\"UserPoolClientId\":\"${aws_cognito_user_pool_client.grafana.id}\",\"UserPoolDomain\":\"${local.cognito_domain_name}\"}"
    "alb.ingress.kubernetes.io/auth-on-unauthenticated-request" = "authenticate"
    "alb.ingress.kubernetes.io/auth-scope"                      = "openid"
    "alb.ingress.kubernetes.io/auth-session-cookie"             = "AWSELBAuthSessionCookie"
    "alb.ingress.kubernetes.io/auth-session-timeout"            = "3600"
    "alb.ingress.kubernetes.io/auth-type"                       = "cognito"
  }
}
