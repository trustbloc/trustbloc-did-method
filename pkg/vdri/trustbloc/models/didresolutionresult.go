/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	didResolutionResultNamespace = "https://www.w3.org/ns/did-resolution/v1"
)

// DIDResolutionResult holds the result of a DID resolution operation
type DIDResolutionResult struct {
	Context        string          `json:"@context"`
	DIDDocument    json.RawMessage `json:"didDocument"`
	MethodMetadata MethodMetaData  `json:"methodMetadata"`
}

// MethodMetaData dummy object
type MethodMetaData struct{}

// MakeDIDResolutionResult constructs, marshals, and returns a DID resolution result containing only a DID document
func MakeDIDResolutionResult(doc *did.Doc) ([]byte, error) {
	docBytes, err := doc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("marshalling did doc: %w", err)
	}

	drr := &DIDResolutionResult{
		Context:     didResolutionResultNamespace,
		DIDDocument: docBytes,
	}

	return json.Marshal(drr)
}
