// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-rest

go 1.16

require (
	github.com/gorilla/mux v1.7.4
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210514172744-92d9a7ecd44d
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.7.0
	github.com/trustbloc/edge-core v0.1.7-0.20210514182200-47eb0f3a6b95
	github.com/trustbloc/trustbloc-did-method v0.0.0
)

replace github.com/trustbloc/trustbloc-did-method => ../..
