/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/btcsuite/btcutil/base58"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	log "github.com/sirupsen/logrus"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/discovery/staticdiscovery"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/endpoint"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/selection/staticselection"
)

const (
	sha2_256       = 18
	recoveryOTP    = "recoveryOTP"
	pubKeyIndex1   = "#key-1"
	defaultKeyType = "Ed25519VerificationKey2018"
	updateOTP      = "updateOTP"
)

type discovery interface {
	GetEndpoints(domain string) ([]*endpoint.Endpoint, error)
}

type selection interface {
	SelectEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error)
}

// Client for did bloc
type Client struct {
	discovery discovery
	selection selection
	kms       legacykms.KeyManager
	client    *http.Client
	tlsConfig *tls.Config
}

// New return did bloc client
func New(opts ...Option) *Client {
	c := &Client{client: &http.Client{}, selection: staticselection.NewService()}

	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	c.client.Transport = &http.Transport{TLSClientConfig: c.tlsConfig}
	c.discovery = staticdiscovery.NewService(staticdiscovery.WithTLSConfig(c.tlsConfig))

	return c
}

// CreateDID create did doc
func (c *Client) CreateDID(domain string, opts ...CreateDIDOption) (*docdid.Doc, error) {
	if domain == "" {
		return nil, errors.New("domain is empty")
	}

	createDIDOpts := &CreateDIDOpts{}
	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	endpoints, err := c.getEndpoints(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints: %w", err)
	}

	req, err := c.buildSideTreeRequest(createDIDOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to build sidetree request: %w", err)
	}

	resDoc, err := c.sendCreateRequest(req, endpoints[0].URL)
	if err != nil {
		return nil, fmt.Errorf("failed to send create sidetree request: %w", err)
	}

	return resDoc, nil
}

func (c *Client) getEndpoints(domain string) ([]*endpoint.Endpoint, error) {
	endpoints, err := c.discovery.GetEndpoints(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to discover endpoints: %w", err)
	}

	selectedEndpoints, err := c.selection.SelectEndpoints(endpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to select endpoints: %w", err)
	}

	if len(selectedEndpoints) == 0 {
		return nil, errors.New("list of endpoints is empty")
	}

	return selectedEndpoints, nil
}

// buildSideTreeRequest request builder for sidetree public DID creation
func (c *Client) buildSideTreeRequest(createDIDOpts *CreateDIDOpts) ([]byte, error) {
	didDoc := createDIDOpts.didDoc

	// create default did doc if user didn't provide their DID
	if didDoc == nil {
		publicKeys := createDIDOpts.publicKeys

		// create default public key if user didn't provide their public key
		if len(publicKeys) == 0 {
			_, base58PubKey, err := c.kms.CreateKeySet()
			if err != nil {
				return nil, fmt.Errorf("failed to create key set: %w", err)
			}

			publicKeys = append(publicKeys, docdid.PublicKey{
				ID:    pubKeyIndex1,
				Type:  defaultKeyType,
				Value: base58.Decode(base58PubKey),
			})
		}

		didDoc = &docdid.Doc{
			Context:   []string{},
			PublicKey: publicKeys,
		}
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %s", err)
	}

	req, err := helper.NewCreateRequest(&helper.CreateRequestInfo{
		OpaqueDocument:  string(docBytes),
		RecoveryKey:     "recoveryKey",
		NextRecoveryOTP: docutil.EncodeToString([]byte(recoveryOTP)),
		NextUpdateOTP:   docutil.EncodeToString([]byte(updateOTP)),
		MultihashCode:   sha2_256,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sidetree request: %w", err)
	}

	return req, nil
}

func (c *Client) sendCreateRequest(req []byte, endpointURL string) (*docdid.Doc, error) {
	httpReq, err := http.NewRequest(http.MethodPost, endpointURL, bytes.NewReader(req))
	if err != nil {
		return nil, fmt.Errorf("failed to create http request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

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

	didDoc, err := docdid.ParseDocument(responseBytes)
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

// WithKMS add kms
func WithKMS(kms legacykms.KeyManager) Option {
	return func(opts *Client) {
		opts.kms = kms
	}
}

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Client) {
		opts.tlsConfig = tlsConfig
	}
}

// CreateDIDOpts create did opts
type CreateDIDOpts struct {
	publicKeys []docdid.PublicKey
	didDoc     *docdid.Doc
}

// CreateDIDOption is a create DID option
type CreateDIDOption func(opts *CreateDIDOpts)

// WithPublicKey add DID public key
func WithPublicKey(publicKey docdid.PublicKey) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.publicKeys = append(opts.publicKeys, publicKey)
	}
}

// WithDID add DID doc
func WithDID(didDoc *docdid.Doc) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.didDoc = didDoc
	}
}
