/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/square/go-jose/v3"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/edsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/client"

	"github.com/trustbloc/trustbloc-did-method/pkg/did/doc"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/deactivate"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/httpconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/memorycacheconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/discovery/staticdiscovery"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/endpoint"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/selection/staticselection"
)

type endpointService interface {
	GetEndpoints(domain string) ([]*models.Endpoint, error)
}

type configService interface {
	GetSidetreeConfig(url string) (*models.SidetreeConfig, error)
}

// Client for did bloc
type Client struct {
	endpointService endpointService
	client          *http.Client
	tlsConfig       *tls.Config
	authToken       string
	configService   configService
}

// New return did bloc client
func New(opts ...Option) *Client {
	c := &Client{client: &http.Client{}}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	c.client.Transport = &http.Transport{TLSClientConfig: c.tlsConfig}
	configService := memorycacheconfig.NewService(httpconfig.NewService(httpconfig.WithTLSConfig(c.tlsConfig)))
	c.configService = configService
	c.endpointService = endpoint.NewService(
		staticdiscovery.NewService(configService),
		staticselection.NewService(configService))

	return c
}

// DeactivateDID deactivate did doc
func (c *Client) DeactivateDID(did, domain string, opts ...deactivate.Option) error {
	deactivateDIDOpts := &deactivate.Opts{}
	// Apply options
	for _, opt := range opts {
		opt(deactivateDIDOpts)
	}

	if deactivateDIDOpts.SigningKey == nil {
		return fmt.Errorf("signing key is required")
	}

	sidetreeEndpoint, err := c.getEndpoint(domain, deactivateDIDOpts.SidetreeEndpoints)
	if err != nil {
		return err
	}

	sidetreeConfig, err := c.configService.GetSidetreeConfig(sidetreeEndpoint)
	if err != nil {
		return err
	}

	req, err := buildDeactivateRequest(did, sidetreeConfig, deactivateDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build sidetree request: %w", err)
	}

	_, err = c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return fmt.Errorf("failed to send deactivate sidetree request: %w", err)
	}

	return err
}

func (c *Client) getEndpoint(domain string, sidetreeEndpoints []*models.Endpoint) (string, error) {
	if domain == "" && len(sidetreeEndpoints) == 0 {
		return "", errors.New("domain is empty and sidetree endpoints is empty")
	}

	endpoints := sidetreeEndpoints

	if domain != "" {
		var err error
		endpoints, err = c.endpointService.GetEndpoints(domain)

		if err != nil {
			return "", fmt.Errorf("failed to get endpoints: %w", err)
		}

		if len(endpoints) == 0 {
			return "", errors.New("list of endpoints is empty")
		}
	}

	// TODO change the logic of choosing first endpoints
	return endpoints[0].URL, nil
}

// unwrapPubKeyJWK takes a key which may contain a JSON JWK as a public key value
// and returns a PublicKey which contains the JWK's key value as the public key value
func unwrapPubKeyJWK(key doc.PublicKey) (*doc.PublicKey, error) { // nolint: gocritic
	out := key

	var jwk jose.JSONWebKey

	// skip those that don't parse - expect them to be binary keys instead of JWKs
	err := jwk.UnmarshalJSON(out.Value)
	if err == nil {
		pub := jwk.Public()

		err = out.GetValueFromJWK(&pub)
		if err != nil {
			return nil, err
		}
	}

	return &out, nil
}

// buildDeactivateRequest request builder for sidetree public DID deactivate
func buildDeactivateRequest(did string, sidetreeConfig *models.SidetreeConfig,
	deactivateDIDOpts *deactivate.Opts) ([]byte, error) {
	signer, publicKey, err := getSigner(deactivateDIDOpts.SigningKey, deactivateDIDOpts.SigningKeyID)
	if err != nil {
		return nil, err
	}

	didSuffix, err := getUniqueSuffix(did)
	if err != nil {
		return nil, err
	}

	revealValue := deactivateDIDOpts.RevealValue

	// TODO: client should be managing reveal value, this defaulting here is just temporary convenience (issue-246)
	if revealValue == "" {
		revealValue = defaultRevealValue(publicKey, sidetreeConfig.MultiHashAlgorithm)
	}

	return client.NewDeactivateRequest(&client.DeactivateRequestInfo{
		DidSuffix:   didSuffix,
		RevealValue: revealValue,
		RecoveryKey: publicKey,
		Signer:      signer,
	})
}

func getSigner(signingkey crypto.PrivateKey, keyID string) (client.Signer, *jws.JWK, error) {
	switch key := signingkey.(type) {
	case *ecdsa.PrivateKey:
		updateKey, err := pubkey.GetPublicKeyJWK(key.Public())
		if err != nil {
			return nil, nil, err
		}

		return ecsigner.New(key, "ES256", keyID), updateKey, nil
	case ed25519.PrivateKey:
		updateKey, err := pubkey.GetPublicKeyJWK(key.Public())
		if err != nil {
			return nil, nil, err
		}

		return edsigner.New(key, "EdDSA", keyID), updateKey, nil
	default:
		return nil, nil, fmt.Errorf("key not supported")
	}
}

func getUniqueSuffix(id string) (string, error) {
	p := strings.LastIndex(id, ":")
	if p == -1 {
		return "", fmt.Errorf("unique suffix not provided in id [%s]", id)
	}

	return id[p+1:], nil
}

func (c *Client) sendRequest(req []byte, endpointURL string) ([]byte, error) { //nolint:unparam
	httpReq, err := http.NewRequest(http.MethodPost, endpointURL+"/operations", bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	if c.authToken != "" {
		httpReq.Header.Add("Authorization", c.authToken)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	defer closeResponseBody(resp.Body)

	responseBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response : %s", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got unexpected response from %s status '%d' body %s",
			endpointURL, resp.StatusCode, responseBytes)
	}

	return responseBytes, nil
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		log.Errorf("Failed to close response body: %v", e)
	}
}

func defaultRevealValue(jwk *jws.JWK, multihashCode uint) string {
	revealValue, err := commitment.GetRevealValue(jwk, multihashCode)
	if err != nil {
		log.Errorf("Failed to default reveal value: %v", err)
		return ""
	}

	return revealValue
}
