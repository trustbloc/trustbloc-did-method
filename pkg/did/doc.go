/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	jsonldID            = "id"
	jsonldType          = "type"
	jsonldUsage         = "usage"
	jsonldServicePoint  = "serviceEndpoint"
	jsonldRecipientKeys = "recipientKeys"
	jsonldRoutingKeys   = "routingKeys"
	jsonldPriority      = "priority"

	jsonldPublicKeyBase58 = "publicKeyBase58"
	jsonldPublicKeyjwk    = "publicKeyJwk"

	// PublicKeyEncodingBase58 define base58 encoding type
	PublicKeyEncodingBase58 = "Base58"
	// PublicKeyEncodingJwk define jwk encoding type
	PublicKeyEncodingJwk = "Jwk"

	// KeyUsageOps defines key usage as operations key
	KeyUsageOps = "ops"
	// KeyUsageAuth defines key usage as authentication key
	KeyUsageAuth = "auth"
	// KeyUsageGeneral defines key usage as general key
	KeyUsageGeneral = "general"

	// JWSVerificationKey2020 defines key type
	JWSVerificationKey2020 = "JwsVerificationKey2020"
)

type rawDoc struct {
	PublicKey []map[string]interface{} `json:"publicKey,omitempty"`
	Service   []map[string]interface{} `json:"service,omitempty"`
}

// Doc DID Document definition
type Doc struct {
	PublicKey []PublicKey
	Service   []docdid.Service
}

// PublicKey DID doc public key.
type PublicKey struct {
	ID       string
	Type     string
	Encoding string
	Usage    []string

	Value []byte
}

// JSONBytes converts document to json bytes
func (doc *Doc) JSONBytes() ([]byte, error) {
	raw := &rawDoc{
		PublicKey: populateRawPublicKeys(doc.PublicKey),
		Service:   populateRawServices(doc.Service),
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of document failed: %w", err)
	}

	return byteDoc, nil
}

func populateRawPublicKeys(pks []PublicKey) []map[string]interface{} {
	var rawPKs []map[string]interface{}

	for i := range pks {
		rawPKs = append(rawPKs, populateRawPublicKey(&pks[i]))
	}

	return rawPKs
}

func populateRawPublicKey(pk *PublicKey) map[string]interface{} {
	rawPK := make(map[string]interface{})
	rawPK[jsonldID] = pk.ID
	rawPK[jsonldType] = pk.Type
	rawPK[jsonldUsage] = pk.Usage

	switch pk.Encoding {
	case PublicKeyEncodingJwk:
		// TODO convert pk.Value to JWK using sidetree-core-go helper
		rawPK[jsonldPublicKeyjwk] = pk.Value
	case PublicKeyEncodingBase58:
		rawPK[jsonldPublicKeyBase58] = base58.Encode(pk.Value)
	}

	return rawPK
}

func populateRawServices(services []docdid.Service) []map[string]interface{} {
	var rawServices []map[string]interface{}

	for _, service := range services {
		rawService := make(map[string]interface{})

		for k, v := range service.Properties {
			rawService[k] = v
		}

		rawService[jsonldID] = service.ID
		rawService[jsonldType] = service.Type
		rawService[jsonldServicePoint] = service.ServiceEndpoint
		rawService[jsonldRecipientKeys] = service.RecipientKeys
		rawService[jsonldRoutingKeys] = service.RoutingKeys
		rawService[jsonldPriority] = service.Priority

		rawServices = append(rawServices, rawService)
	}

	return rawServices
}
