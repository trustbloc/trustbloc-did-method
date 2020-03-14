// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-rest

replace github.com/trustbloc/trustbloc-did-method => ../..

require (
	github.com/gorilla/mux v1.7.4
	github.com/spf13/cobra v0.0.6
	github.com/stretchr/testify v1.4.0
	github.com/trustbloc/trustbloc-did-method v0.0.0-00010101000000-000000000000
)

go 1.13
