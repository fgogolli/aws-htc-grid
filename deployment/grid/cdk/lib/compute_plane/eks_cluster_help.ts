// Copyright 2022 Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/


import { Construct } from "constructs";
import * as cdk from "aws-cdk-lib";
import * as eks from "aws-cdk-lib/aws-eks";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import { IWorkerGroup, IWorkerInfo } from "../shared/cluster-interfaces";
import { EksIamStack } from "./eks_iam_conf";
import { LambdaDrainerScalingStack } from "./lambda_drainer_scaling";
import * as iam from "aws-cdk-lib/aws-iam";

interface EksClusterHelperStackProps extends cdk.NestedStackProps {
  readonly cluster: eks.Cluster;
  readonly vpc: ec2.IVpc;
  readonly vpcDefaultSg: ec2.ISecurityGroup;
  readonly eksWorkerGroups: IWorkerGroup[];
  readonly privateSubnetSelector: ec2.SubnetSelection;
  readonly projectName: string;
  readonly ddbTableName : string;
  readonly taskService :string ;
  readonly taskConfig : string;
  readonly sqsQueue: string;
  readonly gracefulTerminationDelay: number;
  readonly errorLogGroup: string;
  readonly errorLoggingStream: string;
  readonly lambdaNameScalingMetrics: string;
  readonly namespaceMetrics: string;
  readonly dimensionNameMetrics: string;
  readonly periodMetrics: string;
  readonly metricsName: string;
  readonly metricsEventRuleTime: string;
  readonly tasksQueueName: string;
  readonly lambdaDrainerRole: iam.IRole

}

export class EksClusterHelperStack extends cdk.NestedStack {
  public readonly workerInfo: IWorkerInfo[] = [];
  constructor(
    scope: Construct,
    id: string,
    props: EksClusterHelperStackProps
  ) {
    super(scope, id, props);
    const cluster = props.cluster;

    this.addWorkerGroup(cluster,props.privateSubnetSelector,props.eksWorkerGroups);
    const workerInfo = this.workerInfo;
    const worker_roles = [
      ...(function* () {
        for (const info of workerInfo) yield info.role;
      })(),
    ];

    new EksIamStack(this, "eks-iam", {
      worker_roles: worker_roles,
      cluster_id: cluster.clusterName,
    });


    new LambdaDrainerScalingStack(this, "eks-drainer-scaling", {
      vpc: props.vpc,
      vpcDefaultSg: props.vpcDefaultSg,
      cluster: cluster,
      drainerLambdaRole: props.lambdaDrainerRole,
      workerInfo: this.workerInfo,
      privateSubnetSelector: props.privateSubnetSelector,
      projectName:props.projectName,
      gracefulTerminationDelay:props.gracefulTerminationDelay,
      ddbTableName: props.ddbTableName,
      dimensionNameMetrics: props.dimensionNameMetrics,
      errorLogGroup: props.errorLogGroup,
      errorLoggingStream: props.errorLoggingStream,
      lambdaNameScalingMetrics: props.lambdaNameScalingMetrics,
      metricsEventRuleTime: props.metricsEventRuleTime,
      metricsName: props.metricsName,
      namespaceMetrics: props.namespaceMetrics,
      periodMetrics: props.periodMetrics,
      sqsQueue: props.sqsQueue,
      taskConfig: props.taskConfig,
      taskService: props.taskService,
      tasksQueueName: props.tasksQueueName

    });
  }

  private addClusterRoleMapping(cluster: eks.Cluster, worker_node_role: any) {
    cluster.awsAuth.addRoleMapping(worker_node_role, {
      groups: ["system:bootstrappers", "system:nodes"],
      username: "system:node:{{EC2PrivateDNSName}}", // Need to figure out what this should be referencing
    });
  }
  private addWorkerGroup(cluster: eks.Cluster, privateSubnetSelector: ec2.SubnetSelection, workerGroups: IWorkerGroup[]) {
    // Get worker groups from context
    const finalWorkerGroup: eks.Nodegroup[] = [];
    workerGroups.forEach((worker: IWorkerGroup) => {
      // Map each override instance type to the correct ec2.InstanceType class
      const override_instance_types = Array.from(
        worker.override_instance_types,
        (t) => new ec2.InstanceType(t)
      );
      const temp_worker_group = cluster.addNodegroupCapacity(worker.name, {
        instanceTypes: override_instance_types,
        capacityType: eks.CapacityType.SPOT, // Can only be spot or on-demand via cdk
        minSize: worker.asg_min_size,
        maxSize: worker.asg_max_size,
        desiredSize: worker.asg_desired_capacity,
        nodegroupName: worker.name,
        subnets: privateSubnetSelector

        // nodeRole: worker_role,
      });
      this.addClusterRoleMapping(cluster, temp_worker_group.role);
      this.workerInfo.push({
        configs: worker,
        role: temp_worker_group.role,
        nodegroup: temp_worker_group,
      });
      finalWorkerGroup.push(temp_worker_group);
    });
    const opsWorker: IWorkerGroup = {
      asg_desired_capacity: 2,
      asg_max_size: 5,
      asg_min_size: 2,
      on_demand_base_capacity: 2,
      spot_instance_pools: 0,
      override_instance_types: [""],
      name: "operational-worker-ondemand",
    };
    const opsWorkerGroup = cluster.addNodegroupCapacity(opsWorker.name, {
      desiredSize: opsWorker.asg_desired_capacity,
      maxSize: opsWorker.asg_max_size,
      minSize: opsWorker.asg_min_size,
      nodegroupName: opsWorker.name,
      subnets: privateSubnetSelector,
      instanceTypes: [
        new ec2.InstanceType("m5.xlarge"),
        new ec2.InstanceType("m5d.xlarge"),
      ],
      labels: {
        "htc/node-type": "core",
      },
      taints: [
        {
          effect: eks.TaintEffect.NO_SCHEDULE,
          key: "htc/node-type",
          value: "core",
        },
      ],
    });
    this.addClusterRoleMapping(cluster, opsWorkerGroup.role);
    this.workerInfo.push({
      configs: opsWorker,
      role: opsWorkerGroup.role,
      nodegroup: opsWorkerGroup,
    });
    finalWorkerGroup.push(opsWorkerGroup);
  }
}
