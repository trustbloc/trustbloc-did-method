// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli

replace github.com/trustbloc/trustbloc-did-method => ../..

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210127113808-f60b9683e266
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210125133828-10c25f5d6d37
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210125133828-10c25f5d6d37
	github.com/spf13/cobra v1.0.0
	github.com/square/go-jose/v3 v3.0.0-20200630053402-0a67ce9b0693
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.6-0.20210127161542-9e174750f523
	github.com/trustbloc/sidetree-core-go v0.1.6-0.20210114211953-cf95801cfe3e
	github.com/trustbloc/trustbloc-did-method v0.0.0
)

go 1.15
