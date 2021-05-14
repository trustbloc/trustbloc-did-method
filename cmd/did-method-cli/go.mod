// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli

go 1.16

require (
	github.com/btcsuite/btcutil v1.0.2
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210512223230-d4aa62b079bc
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210514172744-92d9a7ecd44d
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210514172744-92d9a7ecd44d
	github.com/spf13/cobra v1.0.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210514182200-47eb0f3a6b95
	github.com/trustbloc/sidetree-core-go v0.6.0
	github.com/trustbloc/trustbloc-did-method v0.0.0
)

replace github.com/trustbloc/trustbloc-did-method => ../..
