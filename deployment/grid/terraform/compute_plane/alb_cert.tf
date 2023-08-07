# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/


resource "tls_private_key" "alb_certificate" {
  algorithm = "RSA"
  rsa_bits  = 4096
}


resource "tls_self_signed_cert" "alb_certificate" {
  private_key_pem = tls_private_key.alb_certificate.private_key_pem

  # Certificate expires after 1 month.
  validity_period_hours = 730

  # Generate a new certificate if Terraform is run within 24
  # hours of the certificate's expiration time.
  early_renewal_hours = 24

  # Reasonable set of uses for a server SSL certificate.
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  subject {
    common_name         = "*.${var.region}.elb.amazonaws.com"
    organization        = "Amazon.com, Inc."
    country             = "US"
    locality            = "WA"
    organizational_unit = "Amazon Web Services (AWS)"
  }
}


# For example, this can be used to populate an AWS IAM server certificate.
resource "aws_iam_server_certificate" "alb_certificate" {
  name             = "alb_self_signed_cert-${local.suffix}-${tls_self_signed_cert.alb_certificate.id}"
  certificate_body = tls_self_signed_cert.alb_certificate.cert_pem
  private_key      = tls_private_key.alb_certificate.private_key_pem

  lifecycle {
    create_before_destroy = true
  }
}
