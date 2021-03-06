#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#


# Release Parameters
BASE_VERSION=0.1.7
IS_RELEASE=false

# Project Parameters
BASE_PKG_NAME=driver-did-trustbloc
CLI_PKG_NAME=did-method-cli
RELEASE_REPO=ghcr.io/trustbloc
SNAPSHOT_REPO=ghcr.io/trustbloc-cicd

if [ ${IS_RELEASE} = false ]
then
  EXTRA_VERSION=snapshot-$(git rev-parse --short=7 HEAD)
  PROJECT_VERSION=${BASE_VERSION}-${EXTRA_VERSION}
  PROJECT_PKG_REPO=${SNAPSHOT_REPO}
else
  PROJECT_VERSION=${BASE_VERSION}
  PROJECT_PKG_REPO=${RELEASE_REPO}
fi


export TRUSTBLOC_DID_METHOD_TAG=${PROJECT_VERSION}
export TRUSTBLOC_DID_METHOD_PKG=${PROJECT_PKG_REPO}/${BASE_PKG_NAME}
export TRUSTBLOC_DID_METHOD_CLI_PKG=${PROJECT_PKG_REPO}/${CLI_PKG_NAME}
