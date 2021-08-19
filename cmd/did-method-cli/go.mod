// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli

go 1.16

require (
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210818152228-f9e43f21be95
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210816132213-a0d886dde049
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210816155124-45ab1ecd4762
	github.com/spf13/cobra v1.0.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210816120552-ed93662ac716
	github.com/trustbloc/sidetree-core-go v0.6.1-0.20210816121828-682fcf6e8012
	github.com/trustbloc/trustbloc-did-method v0.0.0
)

replace github.com/trustbloc/trustbloc-did-method => ../..
