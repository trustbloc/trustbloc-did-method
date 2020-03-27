// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/test/bdd

replace github.com/trustbloc/trustbloc-did-method => ../..

go 1.13

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200325175154-d18ad2581ed9
	github.com/trustbloc/edge-core v0.1.3-0.20200327203235-d7f232b27a56
	github.com/trustbloc/trustbloc-did-method v0.0.0
)
