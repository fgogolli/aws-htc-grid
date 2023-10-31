# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/

locals {
  agent_permissions = [
    {
      description = "${title(local.suffix)} SQS and DynamoDB Agent Permissions"
      effect      = "Allow"

      actions = [
        "sqs:DeleteMessage",
        "sqs:StartMessageMoveTask",
        "sqs:GetQueueUrl",
        "sqs:ListQueues",
        "sqs:CancelMessageMoveTask",
        "sqs:ChangeMessageVisibility",
        "sqs:ListMessageMoveTasks",
        "sqs:UntagQueue",
        "sqs:ReceiveMessage",
        "sqs:SendMessage",
        "sqs:GetQueueAttributes",
        "sqs:ListQueueTags",
        "sqs:TagQueue",
        "sqs:RemovePermission",
        "sqs:ListDeadLetterSourceQueues",
        "sqs:AddPermission",
        "sqs:PurgeQueue",
        "sqs:DeleteQueue",
        "sqs:CreateQueue",
        "sqs:SetQueueAttributes",
        "dynamodb:DescribeContributorInsights",
        "dynamodb:RestoreTableToPointInTime",
        "dynamodb:UpdateGlobalTable",
        "dynamodb:DeleteTable",
        "dynamodb:UpdateTableReplicaAutoScaling",
        "dynamodb:DescribeTable",
        "dynamodb:PartiQLInsert",
        "dynamodb:GetItem",
        "dynamodb:DescribeContinuousBackups",
        "dynamodb:DescribeExport",
        "dynamodb:ListImports",
        "dynamodb:EnableKinesisStreamingDestination",
        "dynamodb:BatchGetItem",
        "dynamodb:DisableKinesisStreamingDestination",
        "dynamodb:UpdateTimeToLive",
        "dynamodb:BatchWriteItem",
        "dynamodb:PutItem",
        "dynamodb:PartiQLUpdate",
        "dynamodb:Scan",
        "dynamodb:StartAwsBackupJob",
        "dynamodb:UpdateItem",
        "dynamodb:UpdateGlobalTableSettings",
        "dynamodb:CreateTable",
        "dynamodb:RestoreTableFromAwsBackup",
        "dynamodb:GetShardIterator",
        "dynamodb:DescribeReservedCapacity",
        "dynamodb:ExportTableToPointInTime",
        "dynamodb:DescribeEndpoints",
        "dynamodb:DescribeBackup",
        "dynamodb:UpdateTable",
        "dynamodb:GetRecords",
        "dynamodb:DescribeTableReplicaAutoScaling",
        "dynamodb:DescribeImport",
        "dynamodb:ListTables",
        "dynamodb:DeleteItem",
        "dynamodb:PurchaseReservedCapacityOfferings",
        "dynamodb:CreateTableReplica",
        "dynamodb:ListTagsOfResource",
        "dynamodb:UpdateContributorInsights",
        "dynamodb:CreateBackup",
        "dynamodb:UpdateContinuousBackups",
        "dynamodb:DescribeReservedCapacityOfferings",
        "dynamodb:TagResource",
        "dynamodb:PartiQLSelect",
        "dynamodb:UpdateGlobalTableVersion",
        "dynamodb:CreateGlobalTable",
        "dynamodb:DescribeKinesisStreamingDestination",
        "dynamodb:DescribeLimits",
        "dynamodb:ImportTable",
        "dynamodb:ListExports",
        "dynamodb:UntagResource",
        "dynamodb:ConditionCheckItem",
        "dynamodb:ListBackups",
        "dynamodb:Query",
        "dynamodb:DescribeStream",
        "dynamodb:DeleteTableReplica",
        "dynamodb:DescribeTimeToLive",
        "dynamodb:ListStreams",
        "dynamodb:ListContributorInsights",
        "dynamodb:DescribeGlobalTableSettings",
        "dynamodb:ListGlobalTables",
        "dynamodb:DescribeGlobalTable",
        "dynamodb:RestoreTableFromBackup",
        "dynamodb:DeleteBackup",
        "dynamodb:PartiQLDelete"
      ]

      resources = [
        "arn:${local.partition}:sqs:${var.region}:${local.account_id}:*",
        "arn:${local.partition}:dynamodb:${var.region}:${local.account_id}:*"
      ]
    },
    # {
    #   description = "DynamoDB Agent Permissions"
    #   effect      = "Allow"

    #   actions = [
    #     "dynamodb:DescribeContributorInsights",
    #     "dynamodb:RestoreTableToPointInTime",
    #     "dynamodb:UpdateGlobalTable",
    #     "dynamodb:DeleteTable",
    #     "dynamodb:UpdateTableReplicaAutoScaling",
    #     "dynamodb:DescribeTable",
    #     "dynamodb:PartiQLInsert",
    #     "dynamodb:GetItem",
    #     "dynamodb:DescribeContinuousBackups",
    #     "dynamodb:DescribeExport",
    #     "dynamodb:ListImports",
    #     "dynamodb:EnableKinesisStreamingDestination",
    #     "dynamodb:BatchGetItem",
    #     "dynamodb:DisableKinesisStreamingDestination",
    #     "dynamodb:UpdateTimeToLive",
    #     "dynamodb:BatchWriteItem",
    #     "dynamodb:PutItem",
    #     "dynamodb:PartiQLUpdate",
    #     "dynamodb:Scan",
    #     "dynamodb:StartAwsBackupJob",
    #     "dynamodb:UpdateItem",
    #     "dynamodb:UpdateGlobalTableSettings",
    #     "dynamodb:CreateTable",
    #     "dynamodb:RestoreTableFromAwsBackup",
    #     "dynamodb:GetShardIterator",
    #     "dynamodb:DescribeReservedCapacity",
    #     "dynamodb:ExportTableToPointInTime",
    #     "dynamodb:DescribeEndpoints",
    #     "dynamodb:DescribeBackup",
    #     "dynamodb:UpdateTable",
    #     "dynamodb:GetRecords",
    #     "dynamodb:DescribeTableReplicaAutoScaling",
    #     "dynamodb:DescribeImport",
    #     "dynamodb:ListTables",
    #     "dynamodb:DeleteItem",
    #     "dynamodb:PurchaseReservedCapacityOfferings",
    #     "dynamodb:CreateTableReplica",
    #     "dynamodb:ListTagsOfResource",
    #     "dynamodb:UpdateContributorInsights",
    #     "dynamodb:CreateBackup",
    #     "dynamodb:UpdateContinuousBackups",
    #     "dynamodb:DescribeReservedCapacityOfferings",
    #     "dynamodb:TagResource",
    #     "dynamodb:PartiQLSelect",
    #     "dynamodb:UpdateGlobalTableVersion",
    #     "dynamodb:CreateGlobalTable",
    #     "dynamodb:DescribeKinesisStreamingDestination",
    #     "dynamodb:DescribeLimits",
    #     "dynamodb:ImportTable",
    #     "dynamodb:ListExports",
    #     "dynamodb:UntagResource",
    #     "dynamodb:ConditionCheckItem",
    #     "dynamodb:ListBackups",
    #     "dynamodb:Query",
    #     "dynamodb:DescribeStream",
    #     "dynamodb:DeleteTableReplica",
    #     "dynamodb:DescribeTimeToLive",
    #     "dynamodb:ListStreams",
    #     "dynamodb:ListContributorInsights",
    #     "dynamodb:DescribeGlobalTableSettings",
    #     "dynamodb:ListGlobalTables",
    #     "dynamodb:DescribeGlobalTable",
    #     "dynamodb:RestoreTableFromBackup",
    #     "dynamodb:DeleteBackup",
    #     "dynamodb:PartiQLDelete"
    #   ]

    #   resources = ["arn:${local.partition}:dynamodb:${var.region}:${local.account_id}:*"]
    # },
    # {
    #   description = "Firehose Agent Permissions"
    #   effect      = "Allow"

    #   actions = [
    #     "firehose:DescribeDeliveryStream",
    #     "firehose:DeleteDeliveryStream",
    #     "firehose:PutRecord",
    #     "firehose:StartDeliveryStreamEncryption",
    #     "firehose:CreateDeliveryStream",
    #     "firehose:PutRecordBatch",
    #     "firehose:ListDeliveryStreams",
    #     "firehose:StopDeliveryStreamEncryption",
    #     "firehose:ListTagsForDeliveryStream",
    #     "firehose:TagDeliveryStream",
    #     "firehose:UpdateDestination",
    #     "firehose:UntagDeliveryStream"
    #   ]

    #   resources = ["arn:${local.partition}:firehose:${var.region}:${local.account_id}:*"]
    # },
    {
      description = "${title(local.suffix)} S3 and KMS Agent Permissions"
      effect      = "Allow"

      actions = [
        "s3:ListAccessPointsForObjectLambda",
        "s3:DeleteAccessPoint",
        "s3:DeleteAccessPointForObjectLambda",
        "s3:DeleteJobTagging",
        "s3:PutLifecycleConfiguration",
        "s3:PutObjectTagging",
        "s3:DeleteObject",
        "s3:CreateMultiRegionAccessPoint",
        "s3:PutAccessPointPolicyForObjectLambda",
        "s3:PutAccountPublicAccessBlock",
        "s3:GetBucketWebsite",
        "s3:PutMultiRegionAccessPointPolicy",
        "s3:DeleteStorageLensConfigurationTagging",
        "s3:GetMultiRegionAccessPoint",
        "s3:PutReplicationConfiguration",
        "s3:GetObjectAttributes",
        "s3:DeleteObjectVersionTagging",
        "s3:InitiateReplication",
        "s3:GetObjectLegalHold",
        "s3:GetBucketNotification",
        "s3:DeleteBucketPolicy",
        "s3:GetReplicationConfiguration",
        "s3:DescribeMultiRegionAccessPointOperation",
        "s3:PutObject",
        "s3:PutBucketNotification",
        "s3:PutObjectVersionAcl",
        "s3:PutAccessPointPublicAccessBlock",
        "s3:CreateJob",
        "s3:PutBucketObjectLockConfiguration",
        "s3:PutAccessPointPolicy",
        "s3:GetStorageLensDashboard",
        "s3:GetLifecycleConfiguration",
        "s3:GetBucketTagging",
        "s3:GetInventoryConfiguration",
        "s3:GetAccessPointPolicyForObjectLambda",
        "s3:ReplicateTags",
        "s3:ListBucket",
        "s3:AbortMultipartUpload",
        "s3:PutBucketTagging",
        "s3:UpdateJobPriority",
        "s3:DeleteBucket",
        "s3:PutBucketVersioning",
        "s3:GetMultiRegionAccessPointPolicyStatus",
        "s3:ListBucketMultipartUploads",
        "s3:PutIntelligentTieringConfiguration",
        "s3:PutMetricsConfiguration",
        "s3:PutStorageLensConfigurationTagging",
        "s3:PutObjectVersionTagging",
        "s3:GetBucketVersioning",
        "s3:GetAccessPointConfigurationForObjectLambda",
        "s3:PutInventoryConfiguration",
        "s3:GetMultiRegionAccessPointRoutes",
        "s3:ObjectOwnerOverrideToBucketOwner",
        "s3:GetStorageLensConfiguration",
        "s3:DeleteStorageLensConfiguration",
        "s3:GetAccountPublicAccessBlock",
        "s3:PutBucketWebsite",
        "s3:ListAllMyBuckets",
        "s3:PutBucketRequestPayment",
        "s3:PutObjectRetention",
        "s3:CreateAccessPointForObjectLambda",
        "s3:GetBucketCORS",
        "s3:DeleteAccessPointPolicy",
        "s3:GetObjectVersion",
        "s3:PutAnalyticsConfiguration",
        "s3:PutAccessPointConfigurationForObjectLambda",
        "s3:GetObjectVersionTagging",
        "s3:PutStorageLensConfiguration",
        "s3:CreateBucket",
        "s3:GetStorageLensConfigurationTagging",
        "s3:ReplicateObject",
        "s3:GetObjectAcl",
        "s3:GetBucketObjectLockConfiguration",
        "s3:DeleteBucketWebsite",
        "s3:GetIntelligentTieringConfiguration",
        "s3:DeleteAccessPointPolicyForObjectLambda",
        "s3:GetObjectVersionAcl",
        "s3:PutBucketAcl",
        "s3:DeleteObjectTagging",
        "s3:GetBucketPolicyStatus",
        "s3:GetObjectRetention",
        "s3:GetJobTagging",
        "s3:ListJobs",
        "s3:PutObjectLegalHold",
        "s3:PutBucketCORS",
        "s3:ListMultipartUploadParts",
        "s3:GetObject",
        "s3:DescribeJob",
        "s3:PutBucketLogging",
        "s3:GetAnalyticsConfiguration",
        "s3:GetObjectVersionForReplication",
        "s3:GetAccessPointForObjectLambda",
        "s3:CreateAccessPoint",
        "s3:GetAccessPoint",
        "s3:PutAccelerateConfiguration",
        "s3:SubmitMultiRegionAccessPointRoutes",
        "s3:DeleteObjectVersion",
        "s3:GetBucketLogging",
        "s3:ListBucketVersions",
        "s3:RestoreObject",
        "s3:GetAccelerateConfiguration",
        "s3:GetObjectVersionAttributes",
        "s3:GetBucketPolicy",
        "s3:PutEncryptionConfiguration",
        "s3:GetEncryptionConfiguration",
        "s3:GetObjectVersionTorrent",
        "s3:GetBucketRequestPayment",
        "s3:GetAccessPointPolicyStatus",
        "s3:GetObjectTagging",
        "s3:GetBucketOwnershipControls",
        "s3:GetMetricsConfiguration",
        "s3:PutObjectAcl",
        "s3:GetBucketPublicAccessBlock",
        "s3:PutBucketPublicAccessBlock",
        "s3:GetMultiRegionAccessPointPolicy",
        "s3:GetAccessPointPolicyStatusForObjectLambda",
        "s3:ListAccessPoints",
        "s3:PutBucketOwnershipControls",
        "s3:DeleteMultiRegionAccessPoint",
        "s3:PutJobTagging",
        "s3:ListMultiRegionAccessPoints",
        "s3:UpdateJobStatus",
        "s3:GetBucketAcl",
        "s3:BypassGovernanceRetention",
        "s3:ListStorageLensConfigurations",
        "s3:GetObjectTorrent",
        "s3:PutBucketPolicy",
        "s3:GetBucketLocation",
        "s3:GetAccessPointPolicy",
        "s3:ReplicateDelete",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ]

      resources = [
        "arn:${local.partition}:s3:::*",
        "arn:${local.partition}:kms:${var.region}:${local.account_id}:*"
      ]
    },
    {
      description = "${title(local.suffix)} Lambda Agent Permissions"
      effect      = "Allow"

      actions = [
        "lambda:CreateFunction",
        "lambda:TagResource",
        "lambda:DeleteProvisionedConcurrencyConfig",
        "lambda:GetFunctionConfiguration",
        "lambda:EnableReplication",
        "lambda:ListProvisionedConcurrencyConfigs",
        "lambda:DisableReplication",
        "lambda:GetProvisionedConcurrencyConfig",
        "lambda:DeleteFunction",
        "lambda:GetAlias",
        "lambda:UpdateFunctionUrlConfig",
        "lambda:CreateFunctionUrlConfig",
        "lambda:UpdateFunctionEventInvokeConfig",
        "lambda:DeleteFunctionCodeSigningConfig",
        "lambda:InvokeFunctionUrl",
        "lambda:GetEventSourceMapping",
        "lambda:InvokeFunction",
        "lambda:ListAliases",
        "lambda:GetFunctionUrlConfig",
        "lambda:AddLayerVersionPermission",
        "lambda:GetFunctionCodeSigningConfig",
        "lambda:UpdateAlias",
        "lambda:UpdateFunctionCode",
        "lambda:ListFunctionEventInvokeConfigs",
        "lambda:PutRuntimeManagementConfig",
        "lambda:ListFunctionsByCodeSigningConfig",
        "lambda:GetFunctionConcurrency",
        "lambda:PutProvisionedConcurrencyConfig",
        "lambda:PublishVersion",
        "lambda:DeleteEventSourceMapping",
        "lambda:CreateAlias",
        "lambda:ListVersionsByFunction",
        "lambda:GetLayerVersion",
        "lambda:PublishLayerVersion",
        "lambda:InvokeAsync",
        "lambda:GetLayerVersionPolicy",
        "lambda:UntagResource",
        "lambda:RemoveLayerVersionPermission",
        "lambda:PutFunctionConcurrency",
        "lambda:DeleteCodeSigningConfig",
        "lambda:ListTags",
        "lambda:GetRuntimeManagementConfig",
        "lambda:DeleteLayerVersion",
        "lambda:PutFunctionEventInvokeConfig",
        "lambda:DeleteFunctionEventInvokeConfig",
        "lambda:PutFunctionCodeSigningConfig",
        "lambda:UpdateEventSourceMapping",
        "lambda:UpdateFunctionCodeSigningConfig",
        "lambda:GetFunction",
        "lambda:UpdateFunctionConfiguration",
        "lambda:ListFunctionUrlConfigs",
        "lambda:UpdateCodeSigningConfig",
        "lambda:AddPermission",
        "lambda:GetFunctionEventInvokeConfig",
        "lambda:DeleteAlias",
        "lambda:DeleteFunctionConcurrency",
        "lambda:GetCodeSigningConfig",
        "lambda:DeleteFunctionUrlConfig",
        "lambda:RemovePermission",
        "lambda:GetPolicy",
        "lambda:ListFunctions",
        "lambda:ListEventSourceMappings",
        "lambda:ListLayerVersions",
        "lambda:ListLayers",
        "lambda:GetAccountSettings",
        "lambda:CreateEventSourceMapping",
        "lambda:ListCodeSigningConfigs",
        "lambda:CreateCodeSigningConfig"
      ]

      resources = ["arn:${local.partition}:lambda:${var.region}:${local.account_id}:*"]
    },
    {
      description = "${title(local.suffix)} Cloudwatch Route53 Agent Permissions"
      effect      = "Allow"

      actions = [
        "logs:ListTagsLogGroup",
        "logs:GetDataProtectionPolicy",
        "logs:GetLogRecord",
        "logs:DeleteDataProtectionPolicy",
        "logs:DeleteSubscriptionFilter",
        "logs:DescribeLogStreams",
        "logs:DescribeSubscriptionFilters",
        "logs:StartQuery",
        "logs:DescribeMetricFilters",
        "logs:DeleteLogStream",
        "logs:CreateExportTask",
        "logs:CreateLogStream",
        "logs:DeleteMetricFilter",
        "logs:TagLogGroup",
        "logs:DeleteRetentionPolicy",
        "logs:GetLogEvents",
        "logs:AssociateKmsKey",
        "logs:FilterLogEvents",
        "logs:PutDestination",
        "logs:DisassociateKmsKey",
        "logs:PutDataProtectionPolicy",
        "logs:UntagLogGroup",
        "logs:DeleteLogGroup",
        "logs:PutDestinationPolicy",
        "logs:Unmask",
        "logs:UntagResource",
        "logs:DeleteDestination",
        "logs:TagResource",
        "logs:PutLogEvents",
        "logs:CreateLogGroup",
        "logs:ListTagsForResource",
        "logs:PutMetricFilter",
        "logs:GetQueryResults",
        "logs:PutSubscriptionFilter",
        "logs:PutRetentionPolicy",
        "logs:GetLogGroupFields",
        "logs:DescribeQueries",
        "logs:DescribeLogGroups",
        "logs:DescribeAccountPolicies",
        "logs:StopQuery",
        "logs:TestMetricFilter",
        "logs:DeleteQueryDefinition",
        "logs:PutQueryDefinition",
        "logs:PutAccountPolicy",
        "logs:GetLogDelivery",
        "logs:ListLogDeliveries",
        "logs:DeleteAccountPolicy",
        "logs:Link",
        "logs:CreateLogDelivery",
        "logs:DeleteResourcePolicy",
        "logs:PutResourcePolicy",
        "logs:DescribeExportTasks",
        "logs:StartLiveTail",
        "logs:UpdateLogDelivery",
        "logs:StopLiveTail",
        "logs:CancelExportTask",
        "logs:DeleteLogDelivery",
        "logs:DescribeQueryDefinitions",
        "logs:DescribeResourcePolicies",
        "logs:DescribeDestinations",
        "cloudwatch:PutMetricData",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "route53:AssociateVPCWithHostedZone"
      ]

      resources = [
        "arn:${local.partition}:logs:${var.region}:${local.account_id}:*",
        "arn:${local.partition}:cloudwatch:${var.region}:${local.account_id}:*",
        "arn:${local.partition}:route53:::*"
      ]
    }
  ]
}


#Agent Permissions
data "aws_iam_policy_document" "agent_permissions" {
  for_each = { for k, v in local.agent_permissions : replace(v.description, " ", "") => v }

  statement {
    sid       = each.key
    effect    = each.value["effect"]
    actions   = each.value["actions"]
    resources = each.value["resources"]
  }
}


resource "aws_iam_policy" "agent_permissions" {
  for_each = { for k, v in local.agent_permissions : replace(v.description, " ", "") => v }

  name        = each.key
  description = each.value["description"]
  policy      = data.aws_iam_policy_document.agent_permissions[each.key].json
}


#EKS Pull Through Cache Permissions
data "aws_iam_policy_document" "eks_pull_through_cache_permission" {
  statement {
    sid    = "PullThroughCacheFromReadOnlyRole"
    effect = "Allow"

    actions = [
      "ecr:CreateRepository",
      "ecr:BatchImportUpstreamImage"
    ]

    resources = [
      "arn:${local.partition}:ecr:${var.region}:${local.account_id}:repository/ecr-public/*",
      "arn:${local.partition}:ecr:${var.region}:${local.account_id}:repository/quay/*",
      "arn:${local.partition}:ecr:${var.region}:${local.account_id}:repository/registry-k8s-io/*"
    ]
  }
}


resource "aws_iam_policy" "eks_pull_through_cache_permission" {
  name        = "ECRPullThroughCachePermissions"
  description = "ECR PullThroughCache permissions for the nodes/kubelet"
  policy      = data.aws_iam_policy_document.eks_pull_through_cache_permission.json
}
