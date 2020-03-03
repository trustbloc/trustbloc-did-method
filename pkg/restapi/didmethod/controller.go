/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didmethod

import (
	"github.com/trustbloc/bloc-did-method/pkg/restapi/didmethod/operation"
)

// New returns new controller instance.
func New() (*Controller, error) {
	var allHandlers []operation.Handler

	didMethodService := operation.New()
	allHandlers = append(allHandlers, didMethodService.GetRESTHandlers()...)

	return &Controller{handlers: allHandlers}, nil
}

// Controller contains handlers for controller
type Controller struct {
	handlers []operation.Handler
}

// GetOperations returns all controller endpoints
func (c *Controller) GetOperations() []operation.Handler {
	return c.handlers
}
