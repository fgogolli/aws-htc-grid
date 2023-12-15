#!/usr/bin/bash

# Copyright 2023 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0 https://aws.amazon.com/apache-2-0/

make auto-destroy-python-runtime TAG=$TAG REGION=$HTCGRID_REGION
make auto-destroy-custom-runtime TAG=$TAG REGION=$HTCGRID_REGION
make reset-grid-deployment TAG=$TAG REGION=$HTCGRID_REGION

make auto-destroy-images TAG=$TAG REGION=$HTCGRID_REGION
make reset-images-deployment TAG=$TAG REGION=$HTCGRID_REGION

# make delete-grid-state TAG=$TAG REGION=$HTCGRID_REGION
