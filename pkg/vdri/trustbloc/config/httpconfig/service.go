/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package httpconfig

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// ConfigService fetches consortium and stakeholder configs over http
type ConfigService struct {
	httpClient *http.Client
	tlsConfig  *tls.Config
}

// NewService create new ConfigService
func NewService(opts ...Option) *ConfigService {
	configService := &ConfigService{httpClient: &http.Client{}}

	for _, opt := range opts {
		opt(configService)
	}

	configService.httpClient.Transport = &http.Transport{TLSClientConfig: configService.tlsConfig}

	return configService
}

const consortiumURLInfix = "/.well-known/did-trustbloc/"
const consortiumURLSuffix = ".json"

func configURL(urlDomain, consortiumDomain string) string {
	prefix := ""
	if !strings.HasPrefix(urlDomain, "http://") && !strings.HasPrefix(urlDomain, "https://") {
		prefix = "https://"
	}

	return prefix + urlDomain + consortiumURLInfix + consortiumDomain + consortiumURLSuffix
}

// GetConsortium fetches and parses the consortium file at the given domain
func (cs *ConfigService) GetConsortium(url, domain string) (*models.ConsortiumFileData, error) {
	res, err := cs.httpClient.Get(configURL(url, domain))
	if err != nil {
		return nil, err
	}

	// nolint: errcheck
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		// TODO retry
		return nil, fmt.Errorf("consortium config request failed: error %d, `%s`", res.StatusCode, string(body))
	}

	return models.ParseConsortium(body)
}

// GetStakeholder fetches and parses a stakeholder file under the given url with the given domain
func (cs *ConfigService) GetStakeholder(url, domain string) (*models.StakeholderFileData, error) {
	res, err := cs.httpClient.Get(configURL(url, domain))
	if err != nil {
		return nil, err
	}

	// nolint: errcheck
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != 200 {
		// TODO retry
		return nil, fmt.Errorf("stakeholder config request failed: error %d, `%s`", res.StatusCode, string(body))
	}

	return models.ParseStakeholder(body)
}

// Option is a config service instance option
type Option func(opts *ConfigService)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *ConfigService) {
		opts.tlsConfig = tlsConfig
	}
}
