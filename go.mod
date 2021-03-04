// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210304152953-16ffd16ca955
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210303194824-a55a12f8d063
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210303194824-a55a12f8d063
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.7.0
)
