/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package endpoint

import (
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// MockEndpointService implements a mock endpoint service
type MockEndpointService struct {
	GetEndpointsFunc func(domain string) ([]*models.Endpoint, error)
}

// GetEndpoints discover endpoints for a consortium domain
func (m *MockEndpointService) GetEndpoints(domain string) ([]*models.Endpoint, error) {
	if m.GetEndpointsFunc != nil {
		return m.GetEndpointsFunc(domain)
	}

	return nil, nil
}
