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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	log "github.com/sirupsen/logrus"
	"github.com/square/go-jose/v3"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/patch"
	"github.com/trustbloc/sidetree-core-go/pkg/util/ecsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/edsigner"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"
	"github.com/trustbloc/sidetree-core-go/pkg/versions/0_1/client"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/httpconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/discovery/staticdiscovery"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/endpoint"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/selection/staticselection"
)

const (
	// default hashes for sidetree
	sha2_256 = 18 // multihash
	sha256   = 5  // hash
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

	if createDIDOpts.recoveryPublicKey == nil {
		return nil, fmt.Errorf("recovery public key is required")
	}

	if createDIDOpts.updatePublicKey == nil {
		return nil, fmt.Errorf("update public key is required")
	}

	sidetreeEndpoint, err := c.getEndpoint(domain, createDIDOpts.sidetreeEndpoints)
	if err != nil {
		return nil, err
	}

	req, err := buildCreateRequest(createDIDOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to build sidetree request: %w", err)
	}

	responseBytes, err := c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to send create sidetree request: %w", err)
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

// UpdateDID update did doc
func (c *Client) UpdateDID(did, domain string, opts ...UpdateDIDOption) error {
	updateDIDOpts := &UpdateDIDOpts{}
	// Apply options
	for _, opt := range opts {
		opt(updateDIDOpts)
	}

	if updateDIDOpts.signingKey == nil {
		return fmt.Errorf("signing public key is required")
	}

	if updateDIDOpts.nextUpdatePublicKey == nil {
		return fmt.Errorf("next update public key is required")
	}

	sidetreeEndpoint, err := c.getEndpoint(domain, updateDIDOpts.sidetreeEndpoints)
	if err != nil {
		return err
	}

	req, err := c.buildUpdateRequest(did, updateDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build update request: %w", err)
	}

	_, err = c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return fmt.Errorf("failed to send create sidetree request: %w", err)
	}

	return nil
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

// buildUpdateRequest request builder for sidetree public DID update
func (c *Client) buildUpdateRequest(did string, updateDIDOpts *UpdateDIDOpts) ([]byte, error) {
	nextUpdateKey, err := pubkey.GetPublicKeyJWK(updateDIDOpts.nextUpdatePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get next update key : %s", err)
	}

	nextUpdateCommitment, err := commitment.Calculate(nextUpdateKey, sha2_256, sha256)
	if err != nil {
		return nil, err
	}

	signer, updateKey, err := getSigner(updateDIDOpts.signingKey, updateDIDOpts.signingKeyID)
	if err != nil {
		return nil, err
	}

	patches, err := createUpdatePatches(updateDIDOpts)
	if err != nil {
		return nil, err
	}

	didSuffix, err := getUniqueSuffix(did)
	if err != nil {
		return nil, err
	}

	return client.NewUpdateRequest(&client.UpdateRequestInfo{
		DidSuffix:        didSuffix,
		UpdateCommitment: nextUpdateCommitment,
		UpdateKey:        updateKey,
		Patches:          patches,
		MultihashCode:    sha2_256,
		Signer:           signer,
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

func createUpdatePatches(updateDIDOpts *UpdateDIDOpts) ([]patch.Patch, error) {
	var patches []patch.Patch

	if len(updateDIDOpts.removePublicKeys) != 0 {
		p, err := createRemovePublicKeysPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	if len(updateDIDOpts.removeServices) != 0 {
		p, err := createRemoveServicesPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	if len(updateDIDOpts.addServices) != 0 {
		p, err := createAddServicesPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	if len(updateDIDOpts.addPublicKeys) != 0 {
		p, err := createAddPublicKeysPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	return patches, nil
}

func createRemovePublicKeysPatch(updateDIDOpts *UpdateDIDOpts) (patch.Patch, error) {
	removePubKeys, err := json.Marshal(updateDIDOpts.removePublicKeys)
	if err != nil {
		return nil, err
	}

	return patch.NewRemovePublicKeysPatch(string(removePubKeys))
}

func createRemoveServicesPatch(updateDIDOpts *UpdateDIDOpts) (patch.Patch, error) {
	removeServices, err := json.Marshal(updateDIDOpts.removeServices)
	if err != nil {
		return nil, err
	}

	return patch.NewRemoveServiceEndpointsPatch(string(removeServices))
}

func createAddServicesPatch(updateDIDOpts *UpdateDIDOpts) (patch.Patch, error) {
	addServices, err := json.Marshal(populateRawServices(updateDIDOpts.addServices))
	if err != nil {
		return nil, err
	}

	return patch.NewAddServiceEndpointsPatch(string(addServices))
}

func createAddPublicKeysPatch(updateDIDOpts *UpdateDIDOpts) (patch.Patch, error) {
	rawPublicKeys, err := populateRawPublicKeys(updateDIDOpts.addPublicKeys)
	if err != nil {
		return nil, err
	}

	addPublicKeys, err := json.Marshal(rawPublicKeys)
	if err != nil {
		return nil, err
	}

	return patch.NewAddPublicKeysPatch(string(addPublicKeys))
}

// buildCreateRequest request builder for sidetree public DID creation
func buildCreateRequest(createDIDOpts *CreateDIDOpts) ([]byte, error) {
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

	recoveryKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.recoveryPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get recovery key : %s", err)
	}

	updateKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.updatePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get update key : %s", err)
	}

	recoveryCommitment, err := commitment.Calculate(recoveryKey, sha2_256, sha256)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.Calculate(updateKey, sha2_256, sha256)
	if err != nil {
		return nil, err
	}

	req, err := client.NewCreateRequest(&client.CreateRequestInfo{
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

func (c *Client) sendRequest(req []byte, endpointURL string) ([]byte, error) {
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
