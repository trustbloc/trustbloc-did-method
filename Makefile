# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0


DOCKER_OUTPUT_NS                 ?= docker.pkg.github.com
# Namespace for the did method image
DID_METHOD_REST_IMAGE_NAME       ?= trustbloc/bloc-did-method/did-method-rest

# Tool commands (overridable)
ALPINE_VER ?= 3.10
GO_VER     ?= 1.13.1

.PHONY: all
all: checks unit-test

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: did-method-rest
did-method-rest:
	@echo "Building did-method-rest"
	@mkdir -p ./.build/bin
	@cd cmd/did-method-rest && go build -o ../../.build/bin/did-method main.go


.PHONY: did-method-rest-docker
did-method-rest-docker:
	@echo "Building did method docker image"
	@docker build -f ./images/did-method-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(DID_METHOD_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .


.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./coverage.txt
