/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package models

import (
	"encoding/base64"
	"encoding/json"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// DummyJWSWrap wraps a config JSON in a dummy JWS
func DummyJWSWrap(data string) string {
	dataB64 := base64.RawURLEncoding.EncodeToString([]byte(data))
	return `{"payload":"` + dataB64 + `","signatures":[{"header":{"kid":""}, "signature":""}]}`
}

// DummyConsortium creates a default consortium object
func DummyConsortium(consortiumDomain string, stakeholders []models.StakeholderListElement) *models.Consortium {
	cc := &models.Consortium{
		Domain:   consortiumDomain,
		Policy:   models.ConsortiumPolicy{Cache: models.CacheControl{MaxAge: 0}},
		Members:  stakeholders,
		Previous: "",
	}

	return cc
}

// DummyConsortiumJSON creates a dummy consortium JSON config
func DummyConsortiumJSON(consortiumDomain string, stakeholders []models.StakeholderListElement) (string, error) {
	out, err := json.Marshal(DummyConsortium(consortiumDomain, stakeholders))
	if err != nil {
		return "", err
	}

	return string(out), nil
}

// DummyStakeholderJSON creates a dummy stakeholder JSON config
func DummyStakeholderJSON(stakeholderDomain string, endpoints []string) (string, error) {
	sc := models.Stakeholder{
		Domain:    stakeholderDomain,
		DID:       "",
		Policy:    models.StakeholderSettings{Cache: models.CacheControl{MaxAge: 0}},
		Endpoints: endpoints,
		Previous:  "",
	}

	out, err := json.Marshal(sc)
	if err != nil {
		return "", err
	}

	return string(out), nil
}
