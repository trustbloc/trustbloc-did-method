/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package staticdiscovery

import (
	"github.com/trustbloc/bloc-did-method/pkg/vdri/bloc/endpoint"
)

// DiscoveryService implements a static discovery service
type DiscoveryService struct {
}

// NewService return static discovery service
func NewService() *DiscoveryService {
	return &DiscoveryService{}
}

// GetEndpoints discover endpoints from domain
func (ds *DiscoveryService) GetEndpoints(domain string) ([]*endpoint.Endpoint, error) {
	// TODO add logic to discover endpoints
	// For now we just return domain as endpoint !!! need to be removed after adding discovery logic
	return []*endpoint.Endpoint{{URL: domain}}, nil
}
