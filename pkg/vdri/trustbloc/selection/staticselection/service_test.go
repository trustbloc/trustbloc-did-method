/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package staticselection

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/bloc-did-method/pkg/vdri/trustbloc/endpoint"
)

func TestSelectionService_SelectEndpoints(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		s := NewService()
		endpoints, err := s.SelectEndpoints([]*endpoint.Endpoint{{URL: "url"}})
		require.NoError(t, err)
		require.Len(t, endpoints, 1)
		require.Equal(t, "url", endpoints[0].URL)
	})
}
