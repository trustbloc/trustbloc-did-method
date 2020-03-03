/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package discovery

import "github.com/trustbloc/bloc-did-method/pkg/vdri/bloc/endpoint"

// MockDiscoveryService implements a mock discovery service
type MockDiscoveryService struct {
	GetEndpointsFunc func(domain string) ([]*endpoint.Endpoint, error)
}

// GetEndpoints discover endpoints from domain
func (m *MockDiscoveryService) GetEndpoints(domain string) ([]*endpoint.Endpoint, error) {
	if m.GetEndpointsFunc != nil {
		return m.GetEndpointsFunc(domain)
	}

	return nil, nil
}
