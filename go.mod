// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

go 1.15

require (
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/btcsuite/btcutil v1.0.1
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210120000618-bdf82385e9df
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210120122509-18c6f2a030bd
	github.com/sirupsen/logrus v1.4.2
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/sidetree-core-go v0.1.6-0.20201217192009-0d2b4436912f
)
