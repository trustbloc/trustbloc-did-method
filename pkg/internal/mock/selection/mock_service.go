/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package discovery

import "github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/endpoint"

// MockSelectionService implements a mock selection service
type MockSelectionService struct {
	SelectEndpointsFunc func(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error)
}

// SelectEndpoints select endpoints
func (m *MockSelectionService) SelectEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	if m.SelectEndpointsFunc != nil {
		return m.SelectEndpointsFunc(endpoints)
	}

	return nil, nil
}
