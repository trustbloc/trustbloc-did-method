// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/test/bdd

replace github.com/trustbloc/trustbloc-did-method => ../..

go 1.15

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.6-0.20210304152953-16ffd16ca955
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210303194824-a55a12f8d063
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210303194824-a55a12f8d063
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210303180208-4bb3ae8b32c9
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210303180208-4bb3ae8b32c9
	github.com/sirupsen/logrus v1.6.0
	github.com/tidwall/gjson v1.6.7
	github.com/trustbloc/edge-core v0.1.6-0.20210304151911-954ad69796fc
	github.com/trustbloc/trustbloc-did-method v0.0.0
	gotest.tools/v3 v3.0.3 // indirect
)

// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
