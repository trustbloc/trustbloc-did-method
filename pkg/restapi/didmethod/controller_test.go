/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didmethod

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
)

func TestController_New(t *testing.T) {
	controller, err := New(&operation.Config{Mode: "combined"})
	require.NoError(t, err)
	require.NotNil(t, controller)

	controller, err = New(&operation.Config{Mode: "invalid"})
	require.Error(t, err)
	require.Nil(t, controller)
	require.Contains(t, err.Error(), "invalid operation mode")
}

func TestController_GetOperations(t *testing.T) {
	controller, err := New(&operation.Config{Mode: "combined"})
	require.NoError(t, err)
	require.NotNil(t, controller)

	ops := controller.GetOperations()
	require.Equal(t, 2, len(ops))
}
