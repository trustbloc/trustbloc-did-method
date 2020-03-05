/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package staticdiscovery

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDiscoveryService_GetEndpoints(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s := NewService()
		endpoints, err := s.GetEndpoints("domain")
		require.NoError(t, err)
		require.Len(t, endpoints, 1)
		require.Equal(t, "http://domain/document", endpoints[0].URL)
	})
}
