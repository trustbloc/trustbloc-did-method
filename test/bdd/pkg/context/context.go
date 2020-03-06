/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package context

// BDDContext is a global context shared between different test suites in bddtests
type BDDContext struct {
}

// NewBDDContext create new BDDContext
func NewBDDContext() *BDDContext {
	return &BDDContext{}
}
