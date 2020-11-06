// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli

replace github.com/trustbloc/trustbloc-did-method => ../..

replace github.com/phoreproject/bls => github.com/trustbloc/bls v0.0.0-20201023141329-a1e218beb89e

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201008080608-ba2e87ef05ef

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/hyperledger/aries-framework-go v0.1.5-0.20201030222504-2f5e96e162b3
	github.com/spf13/cobra v1.0.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.5-0.20201106164919-76ecfeca954f
	github.com/trustbloc/sidetree-core-go v0.1.5-0.20201029224912-2c4c336bf323
	github.com/trustbloc/trustbloc-did-method v0.0.0
)

go 1.15
