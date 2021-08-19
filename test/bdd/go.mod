// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/trustbloc/trustbloc-did-method/test/bdd

go 1.16

require (
	github.com/cucumber/godog v0.9.0
	github.com/fsouza/go-dockerclient v1.6.0
	github.com/google/uuid v1.2.0
	github.com/hyperledger/aries-framework-go v0.1.7-0.20210818152228-f9e43f21be95
	github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree v0.0.0-20210816132213-a0d886dde049
	github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc v0.0.0-20210816155124-45ab1ecd4762
	github.com/hyperledger/aries-framework-go/component/storageutil v0.0.0-20210807121559-b41545a4f1e8
	github.com/hyperledger/aries-framework-go/spi v0.0.0-20210807121559-b41545a4f1e8
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-varint v0.0.6 // indirect
	github.com/pquerna/cachecontrol v0.0.0-20201205024021-ac21108117ac // indirect
	github.com/sirupsen/logrus v1.6.0
	github.com/tidwall/gjson v1.6.7
	github.com/trustbloc/edge-core v0.1.7-0.20210816120552-ed93662ac716
	github.com/trustbloc/trustbloc-did-method v0.0.0
	gotest.tools/v3 v3.0.3 // indirect
)

replace github.com/trustbloc/trustbloc-did-method => ../..

// https://github.com/ory/dockertest/issues/208#issuecomment-686820414
replace golang.org/x/sys => golang.org/x/sys v0.0.0-20200826173525-f9321e4c35a6
