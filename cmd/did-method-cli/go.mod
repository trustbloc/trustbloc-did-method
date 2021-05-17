// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli

go 1.16

require (
	github.com/btcsuite/btcutil v1.0.2
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210517160459-a72f856f36b8
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210517171415-871dc45ae58d
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210517171415-871dc45ae58d
	github.com/spf13/cobra v1.0.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210517172158-aa11a4f18737
	github.com/trustbloc/sidetree-core-go v0.6.0
	github.com/trustbloc/trustbloc-did-method v0.0.0
)

replace github.com/trustbloc/trustbloc-did-method => ../..
