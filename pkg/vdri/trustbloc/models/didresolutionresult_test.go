/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"bytes"
	"encoding/json"
	"testing"

	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	"github.com/stretchr/testify/require"
)

func TestMakeDIDResolutionResult(t *testing.T) {
	mockdoc := mockdiddoc.GetMockDIDDoc()

	resultBytes, err := MakeDIDResolutionResult(mockdoc)
	require.NoError(t, err)

	var result DIDResolutionResult
	err = json.Unmarshal(resultBytes, &result)
	require.NoError(t, err)

	docBytes, err := mockdoc.JSONBytes()
	require.NoError(t, err)

	require.True(t, bytes.Equal(docBytes, result.DIDDocument))
}
