// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli

replace github.com/trustbloc/trustbloc-did-method => ../..

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210304152953-16ffd16ca955
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210303194824-a55a12f8d063
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210303194824-a55a12f8d063
	github.com/spf13/cobra v1.0.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.6-0.20210304151911-954ad69796fc
	github.com/trustbloc/sidetree-core-go v0.1.6-0.20210301232849-50c4792e1ca1
	github.com/trustbloc/trustbloc-did-method v0.0.0
)

go 1.15
