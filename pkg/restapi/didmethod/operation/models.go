/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

const (
	// RegistrationStateFinished registration state finished
	RegistrationStateFinished = "finished"
	// RegistrationStateFailure registration state failure
	RegistrationStateFailure = "failure"
)

// RegisterDIDRequest input data for register DID
type RegisterDIDRequest struct {
	JobID         string            `json:"jobId,omitempty"`
	Options       map[string]string `json:"options,omitempty"`
	AddPublicKeys []PublicKey       `json:"addPublicKeys,omitempty"`
}

// RegisterResponse register response
type RegisterResponse struct {
	JobID             string                 `json:"jobId,omitempty"`
	DIDState          DIDState               `json:"didState,omitempty"`
	RegistrarMetadata map[string]interface{} `json:"registrarMetadata"`
	MethodMetadata    map[string]interface{} `json:"methodMetadata"`
}

// DIDState did state
type DIDState struct {
	Identifier string `json:"identifier,omitempty"`
	Reason     string `json:"reason,omitempty"`
	State      string `json:"state,omitempty"`
	Secret     Secret `json:"secret,omitempty"`
}

// Secret include keys
type Secret struct {
	Keys []Key `json:"keys,omitempty"`
}

// Key include public key and private key
type Key struct {
	PublicKeyBase58  string `json:"publicKeyBase58,omitempty"`
	PrivateKeyBase58 string `json:"privateKeyBase58,omitempty"`
	PublicKeyDIDURL  string `json:"publicKeyDIDURL,omitempty"`
}

// PublicKey public key
type PublicKey struct {
	ID    string `json:"id,omitempty"`
	Type  string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}
