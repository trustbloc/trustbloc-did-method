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
	JobID       string            `json:"jobId,omitempty"`
	Options     map[string]string `json:"options,omitempty"`
	DIDDocument DIDDocument       `json:"didDocument,omitempty"`
}

// DIDDocument did doc
type DIDDocument struct {
	PublicKey []*PublicKey `json:"publicKey,omitempty"`
	Service   []*Service   `json:"service,omitempty"`
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
	PublicKeyBase58  string   `json:"publicKeyBase58,omitempty"`
	PrivateKeyBase58 string   `json:"privateKeyBase58,omitempty"`
	ID               string   `json:"id,omitempty"`
	Purpose          []string `json:"purpose,omitempty"`
}

// PublicKey public key
type PublicKey struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
	// Value is always Base64
	Value    string   `json:"value,omitempty"`
	Purpose  []string `json:"purpose,omitempty"`
	Encoding string   `json:"encoding,omitempty"`
	Recovery bool     `json:"recovery,omitempty"`
	Update   bool     `json:"update,omitempty"`
	KeyType  string   `json:"keyType,omitempty"`
}

// Service DID doc service
type Service struct {
	ID            string   `json:"id,omitempty"`
	Type          string   `json:"type,omitempty"`
	Priority      uint     `json:"priority,omitempty"`
	RecipientKeys []string `json:"recipientKeys,omitempty"`
	RoutingKeys   []string `json:"routingKeys,omitempty"`
	Endpoint      string   `json:"serviceEndpoint,omitempty"`
}
