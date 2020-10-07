# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0


DOCKER_OUTPUT_NS                 ?= docker.pkg.github.com
# Namespace for the did method image
DID_METHOD_REST_IMAGE_NAME       ?= trustbloc/trustbloc-did-method/did-method-rest

# Tool commands (overridable)
ALPINE_VER ?= 3.10
GO_VER     ?= 1.13.1

.PHONY: all
all: checks unit-test bdd-test

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

.PHONY: bdd-test
bdd-test: clean did-method-cli did-method-rest-docker generate-test-keys
	@mkdir -p ./test/bdd/fixtures/wellknown/jws
	@scripts/check_integration.sh

.PHONY: did-method-rest
did-method-rest:
	@echo "Building did-method-rest"
	@mkdir -p ./.build/bin
	@cd cmd/did-method-rest && go build -o ../../.build/bin/did-method main.go

.PHONY: did-method-cli
did-method-cli:
	@echo "Building did-method-cli"
	@mkdir -p ./.build/bin
	@cd cmd/did-method-cli && go build -o ../../.build/bin/cli main.go


.PHONY: generate-config-hash
generate-config-hash: did-method-cli
	@echo "Generate config hash"
	@scripts/generate_config_hash.sh

.PHONY: did-method-rest-docker
did-method-rest-docker:
	@echo "Building did method docker image"
	@docker build -f ./images/did-method-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(DID_METHOD_REST_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) .

.PHONY: generate-test-keys
generate-test-keys:
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/workspace/trustbloc-did-method \
		--entrypoint "/opt/workspace/trustbloc-did-method/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: clean
clean: clean-build

.PHONY: clean-build
clean-build:
	@rm -Rf ./.build
	@rm -Rf ./coverage.txt
	@rm -Rf ./test/bdd/fixtures/keys/tls
	@rm -Rf ./test/bdd/docker-compose.log
