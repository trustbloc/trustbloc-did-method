// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210127113808-f60b9683e266
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210121210840-ee9984a4579c
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210129185922-c6a8732ff634
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.4-0.20200709143857-e104bb29f6c6
)
