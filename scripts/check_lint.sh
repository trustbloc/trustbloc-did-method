#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e

echo "Running $0"

DOCKER_CMD=${DOCKER_CMD:-docker}
GOLANGCI_LINT_IMAGE="golangci/golangci-lint:v1.39.0"

if [ ! $(command -v ${DOCKER_CMD}) ]; then
    exit 0
fi
echo "linting root directory.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace ${GOLANGCI_LINT_IMAGE} golangci-lint run
echo "done linting root directory"
echo "linting cmd/did-method-rest.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/did-method-rest ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting cmd/did-method-rest"
echo "linting cmd/did-method-cli.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/cmd/did-method-cli ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting cmd/did-method-cli"
echo "linting test/bdd.."
${DOCKER_CMD} run --rm -e GOPROXY=${GOPROXY} -v $(pwd):/opt/workspace -w /opt/workspace/test/bdd ${GOLANGCI_LINT_IMAGE} golangci-lint run -c ../../.golangci.yml
echo "done linting test/bdd"