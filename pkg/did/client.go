/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/btcsuite/btcutil/base58"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	log "github.com/sirupsen/logrus"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/helper"

	"github.com/trustbloc/bloc-did-method/pkg/vdri/trustbloc/discovery/staticdiscovery"
	"github.com/trustbloc/bloc-did-method/pkg/vdri/trustbloc/endpoint"
	"github.com/trustbloc/bloc-did-method/pkg/vdri/trustbloc/selection/staticselection"
)

const (
	sha2_256       = 18
	recoveryOTP    = "recoveryOTP"
	pubKeyIndex1   = "#key-1"
	defaultKeyType = "Ed25519VerificationKey2018"
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
}

// New return did bloc client
func New(kms legacykms.KeyManager) *Client {
	return &Client{client: &http.Client{}, kms: kms, discovery: staticdiscovery.NewService(),
		selection: staticselection.NewService()}
}

// CreateDID create did doc
func (c *Client) CreateDID(domain string) (*docdid.Doc, error) {
	if domain == "" {
		return nil, errors.New("domain is empty")
	}

	endpoints, err := c.getEndpoints(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints: %w", err)
	}

	req, err := c.buildSideTreeRequest()
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
func (c *Client) buildSideTreeRequest() ([]byte, error) {
	_, base58PubKey, err := c.kms.CreateKeySet()
	if err != nil {
		return nil, fmt.Errorf("failed to create key set: %w", err)
	}

	publicKey := docdid.PublicKey{
		ID:    pubKeyIndex1,
		Type:  defaultKeyType,
		Value: base58.Decode(base58PubKey),
	}

	t := time.Now()

	didDoc := &docdid.Doc{
		Context:   []string{},
		PublicKey: []docdid.PublicKey{publicKey},
		Created:   &t,
		Updated:   &t,
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %s", err)
	}

	req, err := helper.NewCreateRequest(&helper.CreateRequestInfo{
		OpaqueDocument:  string(docBytes),
		RecoveryKey:     "recoveryKey",
		NextRecoveryOTP: recoveryOTP,
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
