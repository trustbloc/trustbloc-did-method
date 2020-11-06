#!/bin/bash
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
set -e

echo "Running $0"

go generate ./...
pwd=`pwd`
touch "$pwd"/coverage.out

amend_coverage_file () {
if [ -f profile.out ]; then
     cat profile.out >> "$pwd"/coverage.out
     rm profile.out
fi
}

# Running trustbloc-did-method unit tests
PKGS=`go list github.com/trustbloc/trustbloc-did-method/... 2> /dev/null | \
                                                  grep -v /mock`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file

# Running did-method-rest unit tests
cd cmd/did-method-rest
PKGS=`go list github.com/trustbloc/trustbloc-did-method/cmd/did-method-rest/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd" || exit

# Running did-method-cli unit tests
cd cmd/did-method-cli
PKGS=`go list github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli/... 2> /dev/null | \
                                                 grep -v /mocks`
go test $PKGS -count=1 -race -coverprofile=profile.out -covermode=atomic -timeout=10m
amend_coverage_file
cd "$pwd" || exit
