// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/bloc-did-method/test/bdd

replace github.com/trustbloc/bloc-did-method => ../..

go 1.13

require (
	github.com/cucumber/godog v0.8.1
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/hyperledger/aries-framework-go v0.1.3-0.20200306180503-5ec22171d15f
	github.com/sirupsen/logrus v1.4.2
	github.com/trustbloc/bloc-did-method v0.0.0
)
