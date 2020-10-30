// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/cmd/did-method-rest

replace github.com/trustbloc/trustbloc-did-method => ../..

replace github.com/piprate/json-gold => github.com/trustbloc/json-gold v0.3.1-0.20200414173446-30d742ee949e

replace github.com/phoreproject/bls => github.com/trustbloc/bls v0.0.0-20201023141329-a1e218beb89e

replace github.com/kilic/bls12-381 => github.com/trustbloc/bls12-381 v0.0.0-20201008080608-ba2e87ef05ef

require (
	github.com/gorilla/mux v1.7.4
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/edge-core v0.1.4
	github.com/trustbloc/trustbloc-did-method v0.0.0
)

go 1.15
