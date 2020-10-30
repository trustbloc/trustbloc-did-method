// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

replace github.com/phoreproject/bls => github.com/trustbloc/bls v0.0.0-20201023141329-a1e218beb89e

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201008080608-ba2e87ef05ef

go 1.13

require (
	github.com/bluele/gcache v0.0.0-20190518031135-bc40bd653833
	github.com/btcsuite/btcutil v1.0.1
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201029183113-1e234a0af6c6
	github.com/sirupsen/logrus v1.4.2
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/sidetree-core-go v0.1.5-0.20201006193409-11b061380f5b
)
