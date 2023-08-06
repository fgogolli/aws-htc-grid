# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 19.0"

  cluster_name    = var.cluster_name
  cluster_version = var.kubernetes_version

  cluster_endpoint_public_access  = true
  cluster_endpoint_private_access = var.enable_private_subnet
  cluster_enabled_log_types       = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  vpc_id          = var.vpc_id
  subnet_ids      = var.vpc_private_subnet_ids

  # cluster_addons = {
  #   coredns = {
  #     resolve_conflicts_on_create = "OVERWRITE"
  #     resolve_conflicts_on_update = "PRESERVE"
  #     most_recent                 = true
  #     configuration_values = jsonencode({
  #       tolerations: [
  #         {
  #           key: "htc/node-type",
  #           operator: "Equal",
  #           value: "core",
  #           effect: "NoSchedule"
  #         }
  #       ]
  #     })
  #   }

  #   kube-proxy = {
  #     most_recent = true
  #   }

  #   vpc-cni = {
  #     most_recent = true
  #   }
  # }

  # Node IAM Role  
  create_iam_role = true
  iam_role_additional_policies = {
    AmazonEC2ContainerRegistryReadOnly = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    eks_pull_through_cache_permission  = aws_iam_policy.eks_pull_through_cache_permission.arn
  }

  # EKS Managed Node Group(s)
  eks_managed_node_group_defaults = {
    ami_type       = "AL2_x86_64"
    instance_types = ["m6a.xlarge", "m6i.xlarge", "m6idn.xlarge", "m6in.xlarge", "m5.xlarge"]
    attach_cluster_primary_security_group = false
  }

  eks_managed_node_groups = local.eks_worker_group_map

  //create_cluster_security_group = false
  //create_node_security_group    = true
  node_security_group_additional_rules = {
    # keda_metrics_server_access = {
    #   description                   = "Cluster access to keda metrics"
    #   protocol                      = "tcp"
    #   from_port                     = 6443
    #   to_port                       = 6443
    #   type                          = "ingress"
    #   source_cluster_security_group = true
    # }

    # Extend node-to-node security group rules. Recommended and required for the Add-ons
    ingress_keda_apiservice = {
      description = "apiservice for Keda"
      type        = "ingress"
      self        = true
      from_port   = 9666
      to_port     = 9666
      protocol    = "tcp"
    }
    ingress_dns_tcp = {
      description = "Node to node DNS(TCP)"
      protocol    = "tcp"
      from_port   = 53
      to_port     = 53
      type        = "ingress"
      cidr_blocks = [var.vpc_cidr]
      #self        = true
    }

    ingress_influxdb_tcp = {
      description = "Node to node influxdb"
      protocol    = "tcp"
      from_port   = 8086
      to_port     = 8088
      type        = "ingress"
      cidr_blocks = [var.vpc_cidr]
      #self        = true
    }
    ingress_dns_udp = {
      description = "Node to node DNS(UDP)"
      protocol    = "udp"
      from_port   = 53
      to_port     = 53
      type        = "ingress"
      cidr_blocks = [var.vpc_cidr]
      #self        = true
    }

    egress_dns_tcp = {
      description = "Node to node DNS(TCP)"
      protocol    = "tcp"
      from_port   = 53
      to_port     = 53
      type        = "egress"
      cidr_blocks = [var.vpc_cidr]
      #self        = true
    }
    egress_dns_udp = {
      description = "Node to node DNS(UDP)"
      protocol    = "udp"
      from_port   = 53
      to_port     = 53
      type        = "egress"
      cidr_blocks = [var.vpc_cidr]
      #self        = true
    }

    # Recommended outbound traffic for Node groups
    egress_all = {
      description      = "Node all egress"
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
    # Allows Control Plane Nodes to talk to Worker nodes on all ports. Added this to simplify the example and further avoid issues with Add-ons communication with Control plane.
    # This can be restricted further to specific port based on the requirement for each Add-on e.g., metrics-server 4443, spark-operator 8080, karpenter 8443 etc.
    # Change this according to your security requirements if needed
    ingress_cluster_to_node_all_traffic = {
      description                   = "Cluster API to Nodegroup all traffic"
      protocol                      = "-1"
      from_port                     = 0
      to_port                       = 0
      type                          = "ingress"
      source_cluster_security_group = true
    }
  }

  # aws-auth configmap
  # Self managed node groups will not automatically create the aws-auth configmap so we need to
  # create_aws_auth_configmap = true
  manage_aws_auth_configmap = true
  aws_auth_roles = concat(var.input_role, [
    {
      rolearn  = aws_iam_role.role_lambda_drainer.arn
      username = "lambda"
      groups   = ["system:masters"]
    }
  ])
}

# data "aws_eks_cluster" "cluster" {
#   name = module.eks.cluster_name
# }

# data "aws_eks_cluster_auth" "cluster" {
#   name = module.eks.cluster_name
# }

# module "eks_blueprints_kubernetes_addons" {
#   source = "github.com/aws-ia/terraform-aws-eks-blueprints//modules/kubernetes-addons?ref=v4.32.1"

#   eks_cluster_id       = module.eks.cluster_id
#   eks_cluster_endpoint = data.aws_eks_cluster.cluster.endpoint
#   eks_oidc_provider    = replace(data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer, "https://", "")
#   eks_cluster_version  = data.aws_eks_cluster.cluster.version

#   auto_scaling_group_names = module.eks.self_managed_node_group_autoscaling_groups
#   # EKS Managed Addons
#   # enable_amazon_eks_aws_ebs_csi_driver = true

#   enable_aws_for_fluentbit                 = true
#   aws_for_fluentbit_create_cw_log_group    = true
#   aws_for_fluentbit_cw_log_group_retention = 30
#   aws_for_fluentbit_helm_config = {
#     create_namespace = true
#     version = "0.1.23"
#     values = [templatefile("${path.module}/../../charts/values/aws-for-fluentbit.yaml", {
#       region = var.region
#       account_id       = data.aws_caller_identity.current.account_id
#     })]
#   }

#   enable_prometheus = true
#   prometheus_helm_config = {
#     create_namespace = true
#     values = [templatefile("${path.module}/../../charts/values/prometheus.yaml", {
#       region = var.region
#       account_id       = data.aws_caller_identity.current.account_id
#       kube_state_metrics_tag = var.prometheus_configuration.kube_state_metrics_tag
#       configmap_reload_tag = var.prometheus_configuration.configmap_reload_tag
#     })]
#   }

#   enable_grafana = true
#   grafana_helm_config = {
#     values = [templatefile("${path.module}/../../charts/values/grafana.yaml", {
#       aws_htc_ecr = var.aws_htc_ecr
#       eks_cluster_id =  module.eks.cluster_id
#       grafana_configuration_initChownData_tag = var.grafana_configuration.initChownData_tag
#       grafana_configuration_grafana_tag = var.grafana_configuration.grafana_tag
#       grafana_configuration_downloadDashboardsImage_tag = var.grafana_configuration.downloadDashboardsImage_tag
#       grafana_configuration_sidecar_tag = var.grafana_configuration.sidecar_tag
#     })]
#   }

#   enable_aws_node_termination_handler = true
#   aws_node_termination_handler_helm_config = {
#     values = [templatefile("${path.module}/../../charts/values/aws-node-termination-handler.yaml", {
#       aws_htc_ecr = var.aws_htc_ecr
#       eks_cluster_id =  module.eks.cluster_id
#       region = var.region
#       k8s_ca_version = var.k8s_ca_version
#     })]
#   }

#   enable_cluster_autoscaler = true
#   cluster_autoscaler_helm_config = {
#     values = [templatefile("${path.module}/../../charts/values/cluster-autoscaler.yaml", {
#       aws_htc_ecr = var.aws_htc_ecr
#       eks_cluster_id =  module.eks.cluster_id
#       region = var.region
#       k8s_ca_version = var.k8s_ca_version
#     })]
#   }

#   enable_keda = true
#   keda_helm_config = {
#     chart      = "keda"                                               # (Required) Chart name to be installed.
#     version    = var.k8s_keda_version                                              # (Optional) Specify the exact chart version to install. If this is not specified, it defaults to the version set within default_helm_config: https://github.com/aws-ia/terraform-aws-eks-blueprints/blob/main/modules/kubernetes-addons/keda/locals.tf
#     namespace  = "keda"                                               # (Optional) The namespace to install the release into.
#     values = [templatefile("${path.module}/../../charts/values/keda.yaml", {
#       aws_htc_ecr = var.aws_htc_ecr
#       #eks_cluster_id =  module.eks.cluster_id
#       #region = var.region
#       k8s_keda_version = var.k8s_keda_version
#     })]
#   }

#   enable_aws_load_balancer_control = true
#   aws_load_balancer_control_helm_config = {
#     service_account = "aws-lb-sa"
#     values = [templatefile("${path.module}/../../charts/values/aws-alb-controller.yaml", {
#       region = var.region
#       eks_cluster_id =  module.eks.cluster_id
#     })]
#   }

# #  enable_aws_cloudwatch_metrics = true
# #  aws_cloudwatch_metrics_helm_config = {
# #    values = [
# #      templatefile("${path.module}/../../charts/values/aws-cloudwatch-metrics.yaml", {
# #        aws_htc_ecr    = var.aws_htc_ecr
# #        eks_cluster_id = module.eks.cluster_id
# #      })
# #    ]
# #  }

#   depends_on = [
#     null_resource.patch_coredns
#   ]
# }

module "eks_blueprints_addons" {
  source  = "aws-ia/eks-blueprints-addons/aws"
  version = "~> 1.0"

  cluster_name      = module.eks.cluster_name
  cluster_endpoint  = module.eks.cluster_endpoint //data.aws_eks_cluster.cluster.endpoint
  cluster_version   = module.eks.cluster_version
  oidc_provider_arn = module.eks.oidc_provider_arn
  //oidc_provider    = replace(data.aws_eks_cluster.cluster.identity[0].oidc[0].issuer, "https://", "")

  # EKS Managed Addons
  # enable_amazon_eks_aws_ebs_csi_driver = true

  eks_addons = {
    # aws-ebs-csi-driver = {
    #   resolve_conflicts_on_create = "OVERWRITE"
    #   resolve_conflicts_on_update = "PRESERVE"
    #   most_recent = true
    # }
    
    coredns = {
      resolve_conflicts_on_create = "OVERWRITE"
      resolve_conflicts_on_update = "OVERWRITE"
      preserve                    = false
      most_recent                 = true
      configuration_values = jsonencode(
        {
          replicaCount: 2,
          nodeSelector: {
              "htc/node-type": "core"
          },
          tolerations: [
            {
              key: "htc/node-type",
              operator: "Equal",
              value: "core",
              effect: "NoSchedule"
            }
          ]
        }
      )
      
      timeouts = {
        create = "5m"
        delete = "5m"
      }
    }

    kube-proxy = {
      resolve_conflicts_on_create = "OVERWRITE"
      resolve_conflicts_on_update = "PRESERVE"
      most_recent                 = true
    }

    vpc-cni = {
      resolve_conflicts_on_create = "OVERWRITE"
      resolve_conflicts_on_update = "PRESERVE"
      most_recent                 = true
    }
  }

  enable_aws_for_fluentbit = true
  aws_for_fluentbit_cw_log_group = {
    create    = true
    retention = 30
  }
  aws_for_fluentbit = {
    name             = "aws-for-fluent-bit"
    namespace        = "fluentbit"
    create_namespace = true
    chart_version    = "0.1.23"
    values = [templatefile("${path.module}/../../charts/values/aws-for-fluentbit.yaml", {
      region     = var.region
      account_id = data.aws_caller_identity.current.account_id
    })]
  }

  # enable_kube_prometheus_stack = true
  # kube_prometheus_stack = {
  #   create_namespace = true
  #   name          = "kube-prometheus-stack"
  #   chart_version = "45.10.1"
  #   repository    = "https://prometheus-community.github.io/helm-charts"
  #   namespace     = "kube-prometheus-stack"
  #   values        = [templatefile("${path.module}/../../charts/values/prometheus.yaml", {
  #     region = var.region
  #     account_id       = data.aws_caller_identity.current.account_id
  #     kube_state_metrics_tag = var.prometheus_configuration.kube_state_metrics_tag
  #     configmap_reload_tag = var.prometheus_configuration.configmap_reload_tag,
  #     aws_htc_ecr = var.aws_htc_ecr
  #     cluster_name =  module.eks.cluster_name
  #   })]
  # }

  # enable_aws_node_termination_handler = true
  # aws_node_termination_handler_asg_arns = [ for asg in module.eks.self_managed_node_groups : asg.autoscaling_group_arn ]
  # aws_node_termination_handler = {
  #   name          = "aws-node-termination-handler"
  #   chart_version = "0.21.0"
  #   repository    = "https://aws.github.io/eks-charts"
  #   namespace     = "aws-node-termination-handler"
  #   values = [templatefile("${path.module}/../../charts/values/aws-node-termination-handler.yaml", {
  #     aws_htc_ecr    = var.aws_htc_ecr
  #     cluster_name   = module.eks.cluster_name
  #     region         = var.region
  #     k8s_ca_version = var.k8s_ca_version
  #   })]
  # }

  enable_cluster_autoscaler = true
  cluster_autoscaler = {
    name          = "cluster-autoscaler"
    chart_version = "9.29.0"
    repository    = "https://kubernetes.github.io/autoscaler"
    namespace     = "kube-system"
    values = [templatefile("${path.module}/../../charts/values/cluster-autoscaler.yaml", {
      aws_htc_ecr    = var.aws_htc_ecr
      cluster_name   = module.eks.cluster_name
      region         = var.region
      k8s_ca_version = var.k8s_ca_version
    })]
  }

  enable_aws_load_balancer_controller = true
  aws_load_balancer_controller = {
    values = [templatefile("${path.module}/../../charts/values/aws-alb-controller.yaml", {
      cluster_name = module.eks.cluster_name
      region       = var.region
      vpc_id        = var.vpc_id
    })]
  }

  enable_aws_cloudwatch_metrics = true
  //aws_cloudwatch_metrics_irsa_policies = ["IAM Policies"]
  aws_cloudwatch_metrics = {
    //role_policies = ["IAM Policies"]  # extra policies in addition of CloudWatchAgentServerPolicy
    name          = "aws-cloudwatch-metrics"
    repository    = "https://aws.github.io/eks-charts"
    chart_version = "0.0.9"
    namespace     = "amazon-cloudwatch"
    values = [
      templatefile("${path.module}/../../charts/values/aws-cloudwatch-metrics.yaml", {
        aws_htc_ecr  = var.aws_htc_ecr
        cluster_name = module.eks.cluster_name
      })
    ]
  }

  helm_releases = {
    keda = {
      description      = "A Helm chart for KEDA"
      namespace        = "keda"
      create_namespace = true
      chart            = "keda"
      chart_version    = var.k8s_keda_version
      repository       = "https://kedacore.github.io/charts"
      values = [templatefile("${path.module}/../../charts/values/keda.yaml", {
        aws_htc_ecr      = var.aws_htc_ecr
        k8s_keda_version = var.k8s_keda_version
      })]
    }
    influxdb = {
      description      = "A Helm chart for InfluxDB"
      namespace        = "influxdb"
      create_namespace = true
      chart            = "influxdb"
      chart_version    = "4.10.4"
      repository       = "https://helm.influxdata.com/"
      values = [templatefile("${path.module}/../../charts/values/influxdb.yaml", {
        aws_htc_ecr      = var.aws_htc_ecr
      })]
    }
    prometheus = {
      description      = "A Helm chart for Prometheus"
      namespace        = "prometheus"
      create_namespace = true
      chart            = "prometheus"
      chart_version    = "15.17.0"
      repository       = "https://prometheus-community.github.io/helm-charts"
      values = [templatefile("${path.module}/../../charts/values/prometheus.yaml", {
        region                 = var.region
        account_id             = data.aws_caller_identity.current.account_id
        kube_state_metrics_tag = var.prometheus_configuration.kube_state_metrics_tag
        configmap_reload_tag   = var.prometheus_configuration.configmap_reload_tag
      })]
    }
    grafana = {
      description      = "A Helm chart for Grafana"
      namespace        = "grafana"
      create_namespace = true
      chart            = "grafana"
      chart_version    = "6.43.1"
      repository       = "https://grafana.github.io/helm-charts"
      values = [templatefile("${path.module}/../../charts/values/grafana.yaml", {
        aws_htc_ecr      = var.aws_htc_ecr
        k8s_keda_version = var.k8s_keda_version
        grafana_configuration_initChownData_tag = var.grafana_configuration.initChownData_tag
        grafana_configuration_grafana_tag = var.grafana_configuration.grafana_tag
        grafana_configuration_downloadDashboardsImage_tag = var.grafana_configuration.downloadDashboardsImage_tag
        grafana_configuration_sidecar_tag = var.grafana_configuration.sidecar_tag
        grafana_configuration_admin_password = var.grafana_configuration.admin_password
      })]
    }
  }

  # depends_on = [
  #   null_resource.patch_coredns
  # ]
}

# module "htc_agent_irsa" {
#   source = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
#   version = "~> 5.0"

#   role_name = "role_htc_agent_sa-${local.suffix}"
#   oidc_providers = {
#     compute_plane_eks = {
#       provider_arn               = module.eks.oidc_provider_arn
#       namespace_service_accounts = ["${var.htc_agent_namespace}:htc-agent-sa"]
#     }
#   }

#   role_policy_arns = {
#     agent_permissions = aws_iam_policy.agent_permissions.arn
#   }
# }

# module "htc_agent_irsa" {
#   source = "github.com/aws-ia/terraform-aws-eks-blueprints//modules/irsa?ref=v4.32.1"
#   create_kubernetes_namespace = false
#   create_kubernetes_service_account = true
#   eks_cluster_id = module.eks.cluster_name
#   eks_oidc_provider_arn = module.eks.oidc_provider_arn
#   irsa_iam_policies = [aws_iam_policy.agent_permissions.arn]
#   kubernetes_namespace = "default"
#   kubernetes_service_account = "htc-agent-sa"
# }

# data "local_file" "patch_core_dns" {
#   filename = "${path.module}/patch-toleration-selector.yaml"
# }

resource "null_resource" "update_kubeconfig" {
  triggers = {
    #cluster_arn = "arn:aws:eks:${var.region}:${data.aws_caller_identity.current.account_id}:cluster/${var.cluster_name}"
    cluster_arn = module.eks.cluster_arn
  }
  provisioner "local-exec" {
    command = "aws eks update-kubeconfig --region ${var.region} --name ${var.cluster_name}"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "kubectl config delete-cluster ${self.triggers.cluster_arn}"
  }
  provisioner "local-exec" {
    when    = destroy
    command = "kubectl config delete-context ${self.triggers.cluster_arn}"
  }
  depends_on = [module.eks]

}

# resource "null_resource" "patch_coredns" {
#   provisioner "local-exec" {
#     command = "kubectl -n kube-system patch deployment coredns --patch \"${data.local_file.patch_core_dns.content}\""
#   }
#   depends_on = [
#     module.eks,
#     //module.eks_blueprints_addons,
#     null_resource.update_kubeconfig
#   ]
# }

data "kubernetes_service" "influxdb_load_balancer" {
  metadata {
    name      = "influxdb"
    namespace = "influxdb"
  }
  depends_on = [
    module.eks_blueprints_addons
  ]
}
