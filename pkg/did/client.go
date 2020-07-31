/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	log "github.com/sirupsen/logrus"
	"github.com/square/go-jose/v3"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/httpconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/discovery/staticdiscovery"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/endpoint"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/selection/staticselection"
)

const (
	sha2_256 = 18
)

type endpointService interface {
	GetEndpoints(domain string) ([]*models.Endpoint, error)
}

// Client for did bloc
type Client struct {
	endpointService endpointService
	client          *http.Client
	tlsConfig       *tls.Config
	authToken       string
}

type didResolution struct {
	Context          interface{}     `json:"@context"`
	DIDDocument      json.RawMessage `json:"didDocument"`
	ResolverMetadata json.RawMessage `json:"resolverMetadata"`
	MethodMetadata   json.RawMessage `json:"methodMetadata"`
}

// New return did bloc client
func New(opts ...Option) *Client {
	c := &Client{client: &http.Client{}}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	c.client.Transport = &http.Transport{TLSClientConfig: c.tlsConfig}
	configService := httpconfig.NewService(httpconfig.WithTLSConfig(c.tlsConfig))
	c.endpointService = endpoint.NewService(
		staticdiscovery.NewService(configService),
		staticselection.NewService(configService))

	return c
}

// CreateDID create did doc
func (c *Client) CreateDID(domain string, opts ...CreateDIDOption) (*docdid.Doc, error) {
	createDIDOpts := &CreateDIDOpts{}
	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	if domain == "" && createDIDOpts.sidetreeEndpoint == "" {
		return nil, errors.New("domain is empty and sidetree endpoint is empty")
	}

	sidetreeEndpoint := createDIDOpts.sidetreeEndpoint

	if domain != "" {
		endpoints, err := c.endpointService.GetEndpoints(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to get endpoints: %w", err)
		}

		if len(endpoints) == 0 {
			return nil, errors.New("list of endpoints is empty")
		}

		sidetreeEndpoint = endpoints[0].URL
	}

	req, err := c.buildSideTreeRequest(createDIDOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to build sidetree request: %w", err)
	}

	resDoc, err := c.sendCreateRequest(req, sidetreeEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to send create sidetree request: %w", err)
	}

	return resDoc, nil
}

// unwrapPubKeyJWK takes a key which may contain a JSON JWK as a public key value
// and returns a PublicKey which contains the JWK's key value as the public key value
func unwrapPubKeyJWK(key PublicKey) (*PublicKey, error) { // nolint: gocritic
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

// buildSideTreeRequest request builder for sidetree public DID creation
func (c *Client) buildSideTreeRequest(createDIDOpts *CreateDIDOpts) ([]byte, error) {
	publicKeys := createDIDOpts.publicKeys

	var parsedKeys []PublicKey

	for _, key := range publicKeys {
		parsedKey, err := unwrapPubKeyJWK(key)
		if err != nil {
			return nil, err
		}

		parsedKeys = append(parsedKeys, *parsedKey)
	}

	doc := &Doc{
		PublicKey: parsedKeys,
		Service:   createDIDOpts.services,
	}

	docBytes, err := doc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %s", err)
	}

	recoveryKey, err := c.getRecoveryKey(publicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to get recovery key : %s", err)
	}

	updateKey, err := c.getUpdateKey(publicKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to get update key : %s", err)
	}

	recoveryCommitment, err := commitment.Calculate(recoveryKey, sha2_256)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.Calculate(updateKey, sha2_256)
	if err != nil {
		return nil, err
	}

	req, err := helper.NewCreateRequest(&helper.CreateRequestInfo{
		OpaqueDocument:     string(docBytes),
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sha2_256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sidetree request: %w", err)
	}

	return req, nil
}

func (c *Client) getRecoveryKey(publicKeys []PublicKey) (*jws.JWK, error) {
	for _, v := range publicKeys {
		if v.Recovery {
			if v.Encoding != PublicKeyEncodingJwk {
				return nil, fmt.Errorf("recovery public key encoding not supported: %s", v.Encoding)
			}

			return pubkey.GetPublicKeyJWK(ed25519.PublicKey(v.Value))
		}
	}

	return nil, fmt.Errorf("recovery key not found")
}

func (c *Client) getUpdateKey(publicKeys []PublicKey) (*jws.JWK, error) {
	for _, v := range publicKeys {
		if v.Update {
			if v.Encoding != PublicKeyEncodingJwk {
				return nil, fmt.Errorf("update public key encoding not supported: %s", v.Encoding)
			}

			return pubkey.GetPublicKeyJWK(ed25519.PublicKey(v.Value))
		}
	}

	return nil, fmt.Errorf("update key not found")
}

func (c *Client) sendCreateRequest(req []byte, endpointURL string) (*docdid.Doc, error) {
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

	var r didResolution
	if errUnmarshal := json.Unmarshal(responseBytes, &r); errUnmarshal != nil {
		return nil, fmt.Errorf("unmarshal data return from sidtree %w", errUnmarshal)
	}

	didDocBytes := responseBytes
	// check if data is did resolution
	if len(r.DIDDocument) != 0 {
		didDocBytes = r.DIDDocument
	}

	didDoc, err := docdid.ParseDocument(didDocBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public DID document: %s", err)
	}

	return didDoc, nil
}

func closeResponseBody(respBody io.Closer) {
	e := respBody.Close()
	if e != nil {
		log.Errorf("Failed to close response body: %v", e)
	}
}

// Option is a DID client instance option
type Option func(opts *Client)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Client) {
		opts.tlsConfig = tlsConfig
	}
}

// WithAuthToken add auth token
func WithAuthToken(authToken string) Option {
	return func(opts *Client) {
		opts.authToken = "Bearer " + authToken
	}
}

// CreateDIDOpts create did opts
type CreateDIDOpts struct {
	publicKeys       []PublicKey
	services         []docdid.Service
	sidetreeEndpoint string
}

// CreateDIDOption is a create DID option
type CreateDIDOption func(opts *CreateDIDOpts)

// WithPublicKey add DID public key
func WithPublicKey(publicKey *PublicKey) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.publicKeys = append(opts.publicKeys, *publicKey)
	}
}

// WithService add service
func WithService(service *docdid.Service) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.services = append(opts.services, *service)
	}
}

// WithSidetreeEndpoint go directly to sidetree
func WithSidetreeEndpoint(sidetreeEndpoint string) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.sidetreeEndpoint = sidetreeEndpoint
	}
}
