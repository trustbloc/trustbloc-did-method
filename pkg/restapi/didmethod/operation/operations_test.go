/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	svc := New()
	require.NotNil(t, svc)
	require.Equal(t, 0, len(svc.GetRESTHandlers()))
}
