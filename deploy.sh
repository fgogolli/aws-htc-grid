#!/usr/bin/bash

# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/

# aws cloud9 update-environment --environment-id ${C9_PID} --managed-credentials-action DISABLE
# rm -vf ${HOME}/.aws/credentials

# aws sts get-caller-identity

# cd aws-htc-grid
# virtualenv venv

# source ./venv/bin/activate
# echo "source ~/environment/aws-htc-grid/venv/bin/activate" >> ~/.bashrc

# which python

# export TAG=main
# export HTCGRID_REGION=$(curl -s 169.254.169.254/latest/dynamic/instance-identity/document | jq -r '.region')

# for var in TAG HTCGRID_REGION  ; do echo "export $var=$(eval "echo \"\$$var\"")" >> load_variables.sh ; done
# echo -e "===\nYour variables and configuration have been setup as follows\n===\n$(cat load_variables.sh)"
# echo "source ~/environment/aws-htc-grid/load_variables.sh" >> ~/.bashrc

make init-grid-state TAG=$TAG REGION=$HTCGRID_REGION
aws cloudformation describe-stacks --stack-name $TAG --region $HTCGRID_REGION --query 'Stacks[0]'

make init-images TAG=$TAG REGION=$HTCGRID_REGION
make auto-transfer-images TAG=$TAG REGION=$HTCGRID_REGION
aws ecr describe-repositories --region $HTCGRID_REGION --query "repositories[*].repositoryUri"

make happy-path TAG=$TAG REGION=$HTCGRID_REGION

make init-grid-deployment TAG=$TAG REGION=$HTCGRID_REGION
make auto-apply-custom-runtime TAG=$TAG REGION=$HTCGRID_REGION

cd ~/environment/aws-htc-grid
kubectl delete job --all
kubectl apply -f ~/environment/aws-htc-grid/generated/single-task-test.yaml
sleep 10
kubectl logs -f jobs/single-task


kubectl delete job --all
kubectl apply -f ~/environment/aws-htc-grid/generated/batch-task-test.yaml
sleep 10
kubectl logs -f jobs/batch-task
