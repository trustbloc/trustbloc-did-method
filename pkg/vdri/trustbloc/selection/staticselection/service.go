/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package staticselection

import (
	"github.com/trustbloc/bloc-did-method/pkg/vdri/trustbloc/endpoint"
)

// SelectionService implements a static selection service
type SelectionService struct {
}

// NewService return static selection service
func NewService() *SelectionService {
	return &SelectionService{}
}

// SelectEndpoints select endpoints
func (ds *SelectionService) SelectEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
	// TODO add logic to select endpoints
	// For now we just return all endpoints !!! need to be removed after adding selection logic
	return endpoints, nil
}
