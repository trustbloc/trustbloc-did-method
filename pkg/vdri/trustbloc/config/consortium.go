/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"encoding/json"
	"errors"

	"github.com/square/go-jose"
)

/*
A consortium config file is a JWS, signed by the stakeholders,
with the payload being a JSON object containing:
  - The domain name of the consortium
  - Consortium policy configuration settings
  - A list of stakeholders - containing, for each stakeholder:
    - The web domain where its configuration can be found
    - The did:trustbloc DID of the stakeholder
  - The hash of the previous version of this config file
*/

// Consortium holds the configuration for a consortium, which is signed by stakeholders
type Consortium struct {
	// Domain is the domain name of the consortium
	Domain string `json:"domain,omitempty"`
	// Policy contains the consortium policy configuration
	Policy ConsortiumPolicy `json:"policy"`
	// Stakeholders is a list containing references to the stakeholders on this consortium
	Stakeholders []StakeholderListElement `json:"stakeholders"`
	// Previous contains a hashlink to the previous version of this file. Optional.
	Previous string `json:"previous,omitempty"`
}

// ConsortiumPolicy holds consortium policy configuration
type ConsortiumPolicy struct {
	Cache CacheControl `json:"cache"`
}

// CacheControl holds cache settings for this file,
//  indicating to the recipient how long until they should check for a new version of the file.
type CacheControl struct {
	MaxAge uint32 `json:"max-age"`
}

// StakeholderListElement holds the domain and DID of a stakeholder within the consortium
type StakeholderListElement struct {
	// Domain is the domain name of the stakeholder
	Domain string `json:"domain,omitempty"`
	// DID is the DID of the stakeholder
	DID string `json:"did,omitempty"`
}

// ConsortiumFileData holds the data within a consortium config file
type ConsortiumFileData struct {
	Config *Consortium
	JWS    *jose.JSONWebSignature
}

// ParseConsortium parses the contents of a consortium file into a ConsortiumFileData object
func ParseConsortium(data []byte) (*ConsortiumFileData, error) {
	jws, err := jose.ParseSigned(string(data))
	if err != nil {
		return nil, errors.New("consortium config data should be a JWS")
	}

	configBytes := jws.UnsafePayloadWithoutVerification()

	var config Consortium

	err = json.Unmarshal(configBytes, &config)
	if err != nil {
		return nil, err
	}

	return &ConsortiumFileData{
		Config: &config,
		JWS:    jws,
	}, nil
}
