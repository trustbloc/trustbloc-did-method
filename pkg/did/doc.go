/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
)

const (
	jsonldID            = "id"
	jsonldType          = "type"
	jsonldUsage         = "usage"
	jsonldServicePoint  = "serviceEndpoint"
	jsonldRecipientKeys = "recipientKeys"
	jsonldRoutingKeys   = "routingKeys"
	jsonldPriority      = "priority"

	jsonldPublicKeyjwk = "publicKeyJwk"

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
	Recovery bool

	Value []byte
}

// JSONBytes converts document to json bytes
func (doc *Doc) JSONBytes() ([]byte, error) {
	publicKeys, err := populateRawPublicKeys(doc.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Public Key failed: %w", err)
	}

	raw := &rawDoc{
		PublicKey: publicKeys,
		Service:   populateRawServices(doc.Service),
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of document failed: %w", err)
	}

	return byteDoc, nil
}

func populateRawPublicKeys(pks []PublicKey) ([]map[string]interface{}, error) {
	var rawPKs []map[string]interface{}

	for i := range pks {
		if !pks[i].Recovery {
			publicKey, err := populateRawPublicKey(&pks[i])
			if err != nil {
				return nil, err
			}

			rawPKs = append(rawPKs, publicKey)
		}
	}

	return rawPKs, nil
}

func populateRawPublicKey(pk *PublicKey) (map[string]interface{}, error) {
	rawPK := make(map[string]interface{})
	rawPK[jsonldID] = pk.ID
	rawPK[jsonldType] = pk.Type
	rawPK[jsonldUsage] = pk.Usage

	switch pk.Encoding {
	case PublicKeyEncodingJwk:
		jwk, err := pubkey.GetPublicKeyJWK(ed25519.PublicKey(pk.Value))
		if err != nil {
			return nil, err
		}

		rawPK[jsonldPublicKeyjwk] = jwk
	default:
		return nil, fmt.Errorf("public key encoding not supported: %s", pk.Encoding)
	}

	return rawPK, nil
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
