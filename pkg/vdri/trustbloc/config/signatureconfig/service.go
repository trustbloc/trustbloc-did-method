/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package signatureconfig

import (
	"fmt"
	"math/rand"

	log "github.com/sirupsen/logrus"
	"github.com/square/go-jose/v3"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

type config interface {
	GetConsortium(string, string) (*models.ConsortiumFileData, error)
	GetStakeholder(string, string) (*models.StakeholderFileData, error)
}

// ConfigService fetches consortium and stakeholder configs over http
type ConfigService struct {
	config config
}

// NewService create new ConfigService
func NewService(config config) *ConfigService {
	configService := &ConfigService{config: config}

	return configService
}

// GetConsortium fetches and parses the consortium file at the given domain
func (cs *ConfigService) GetConsortium(url, domain string) (*models.ConsortiumFileData, error) {
	consortiumData, err := cs.config.GetConsortium(url, domain)
	if err != nil {
		return nil, fmt.Errorf("wrapped config service: %w", err)
	}

	consortium := consortiumData.Config
	if consortium == nil {
		return nil, fmt.Errorf("consortium is nil")
	}

	n := consortium.Policy.NumQueries

	// if ds.numStakeholders is 0, then we use all stakeholders
	if n == 0 {
		n = len(consortium.Members)
	}

	perm := rand.Perm(len(consortium.Members))

	sig := consortiumData.JWS

	// number of stakeholders that have verified
	verifiedCount := 0

	for i := 0; i < len(consortium.Members); i++ {
		keyData := consortium.Members[perm[i]].PublicKey.JWK
		key := jose.JSONWebKey{}

		err := key.UnmarshalJSON(keyData)
		if err != nil {
			log.Warnf("bad key for stakeholder: %s", consortium.Members[perm[i]].Domain)
			continue
		}

		_, _, _, err = sig.VerifyMulti(key)
		if err != nil {
			log.Warnf("key fails to verify for stakeholder: %s", consortium.Members[perm[i]].Domain)
			continue
		}

		verifiedCount++

		if verifiedCount == n {
			break
		}
	}

	if verifiedCount < n {
		return nil, fmt.Errorf("insufficient stakeholder endorsement of consortium config file")
	}

	return consortiumData, nil
}

// GetStakeholder returns the stakeholder config file fetched by the wrapped config service
func (cs *ConfigService) GetStakeholder(url, domain string) (*models.StakeholderFileData, error) {
	return cs.config.GetStakeholder(url, domain)
}
