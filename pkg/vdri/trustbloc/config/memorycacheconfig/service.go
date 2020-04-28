/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package memorycacheconfig

import (
	"fmt"
	"time"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

type consortiumCacheEntry struct {
	data   *models.ConsortiumFileData
	expiry time.Time
}

type stakeholderCacheEntry struct {
	data   *models.StakeholderFileData
	expiry time.Time
}

type config interface {
	GetConsortium(string, string) (*models.ConsortiumFileData, error)
	GetStakeholder(string, string) (*models.StakeholderFileData, error)
}

// ConfigService fetches consortium and stakeholder configs using a wrapped config service, caching results in-memory
type ConfigService struct {
	config config

	//	TODO: temp-cache consortium configs
	consortiumCache map[string]*consortiumCacheEntry
	//	TODO: temp-cache stakeholder configs
	stakeholderCache map[string]*stakeholderCacheEntry
}

// NewService create new ConfigService
func NewService(config config) *ConfigService {
	configService := &ConfigService{
		config:           config,
		consortiumCache:  map[string]*consortiumCacheEntry{},
		stakeholderCache: map[string]*stakeholderCacheEntry{},
	}

	return configService
}

// GetConsortium fetches and parses the consortium file at the given domain, caching the value
func (cs *ConfigService) GetConsortium(url, domain string) (*models.ConsortiumFileData, error) { // nolint: dupl
	if val, ok := cs.consortiumCache[domain]; ok {
		if time.Now().Before(val.expiry) {
			return val.data, nil
		}
	}

	consortiumData, err := cs.config.GetConsortium(url, domain)
	if err != nil {
		return nil, fmt.Errorf("wrapped config service: %w", err)
	}

	fetchTime := time.Now()

	consortium := consortiumData.Config
	if consortium == nil {
		return nil, fmt.Errorf("nil consortium")
	}

	if consortium.Policy.Cache.MaxAge > 0 {
		expiryTime := fetchTime.Add(time.Duration(consortium.Policy.Cache.MaxAge) * time.Second)

		newEntry := consortiumCacheEntry{
			data:   consortiumData,
			expiry: expiryTime,
		}

		cs.consortiumCache[domain] = &newEntry
	}

	return consortiumData, nil
}

// GetStakeholder returns the stakeholder config file fetched by the wrapped config service, caching the value
func (cs *ConfigService) GetStakeholder(url, domain string) (*models.StakeholderFileData, error) { // nolint: dupl
	if val, ok := cs.stakeholderCache[domain]; ok {
		if time.Now().Before(val.expiry) {
			return val.data, nil
		}
	}

	stakeholderData, err := cs.config.GetStakeholder(url, domain)
	if err != nil {
		return nil, fmt.Errorf("wrapped config service: %w", err)
	}

	fetchTime := time.Now()

	stakeholder := stakeholderData.Config
	if stakeholder == nil {
		return nil, fmt.Errorf("nil stakeholder")
	}

	if stakeholder.Policy.Cache.MaxAge > 0 {
		expiryTime := fetchTime.Add(time.Duration(stakeholder.Policy.Cache.MaxAge) * time.Second)

		newEntry := stakeholderCacheEntry{
			data:   stakeholderData,
			expiry: expiryTime,
		}

		cs.stakeholderCache[domain] = &newEntry
	}

	return stakeholderData, nil
}
