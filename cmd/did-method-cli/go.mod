// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.2
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210310014234-cfa8c6d6e2f4
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210306170115-156a24580a5c
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210306170115-156a24580a5c
	github.com/spf13/cobra v1.0.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210310142750-7eb11997c4a9
	github.com/trustbloc/sidetree-core-go v0.6.0
	github.com/trustbloc/trustbloc-did-method v0.0.0
)

replace github.com/trustbloc/trustbloc-did-method => ../..
