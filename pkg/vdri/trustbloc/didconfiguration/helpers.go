/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didconfiguration

import (
	"encoding/json"
	"fmt"

	"github.com/square/go-jose/v3"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// CreateDIDConfiguration creates a DID Configuration asserting a given DID's ownership over a given domain
//   using the given signing keys (which are assumed to belong to the DID)
// Implements https://identity.foundation/specs/did-configuration/
func CreateDIDConfiguration(domain, didValue string, expiryTime int64,
	signingKeys ...*jose.SigningKey) (*models.DIDConfiguration, error) {
	config := models.DIDConfiguration{Entries: []models.DomainLinkageAssertion{}}

	for _, key := range signingKeys {
		dla, err := createDomainLinkageAssertion(domain, didValue, expiryTime, key)
		if err != nil {
			return nil, fmt.Errorf("can't create DomainLinkageAssertion: %w", err)
		}

		config.Entries = append(config.Entries, *dla)
	}

	return &config, nil
}

// createDomainLinkageAssertion creates a Domain Linkage Assertion for a DID Configuration
func createDomainLinkageAssertion(
	domain, didValue string, expiryTime int64, signingKey *jose.SigningKey) (*models.DomainLinkageAssertion, error) {
	claims := models.DomainLinkageAssertionClaims{
		ISS:    didValue,
		Domain: domain,
		Exp:    expiryTime,
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("can't marshal claims: %w", err)
	}

	signer, err := jose.NewSigner(*signingKey, nil)
	if err != nil {
		return nil, fmt.Errorf("can't construct signer: %w", err)
	}

	jws, err := signer.Sign(claimsBytes)
	if err != nil {
		return nil, fmt.Errorf("can't sign claims: %w", err)
	}

	jwsCompact, err := jws.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("can't serialize signature: %w", err)
	}

	return &models.DomainLinkageAssertion{
		DID: didValue,
		JWT: jwsCompact,
	}, nil
}
