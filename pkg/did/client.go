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

	"github.com/trustbloc/trustbloc-did-method/pkg/did/doc"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/create"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/deactivate"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/recovery"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/update"
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
	configService := memorycacheconfig.NewService(httpconfig.NewService(httpconfig.WithTLSConfig(c.tlsConfig)))
	c.configService = configService
	c.endpointService = endpoint.NewService(
		staticdiscovery.NewService(configService),
		staticselection.NewService(configService))

	return c
}

// CreateDID create did doc
func (c *Client) CreateDID(domain string, opts ...create.Option) (*docdid.Doc, error) { //
	createDIDOpts := &create.Opts{}
	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	err := validateCreateReq(createDIDOpts)
	if err != nil {
		return nil, err
	}

	sidetreeEndpoint, err := c.getEndpoint(domain, createDIDOpts.SidetreeEndpoints)
	if err != nil {
		return nil, err
	}

	sidetreeConfig, err := c.configService.GetSidetreeConfig(sidetreeEndpoint)
	if err != nil {
		return nil, err
	}

	req, err := buildCreateRequest(sidetreeConfig, createDIDOpts)
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

func validateCreateReq(createDIDOpts *create.Opts) error {
	if createDIDOpts.RecoveryPublicKey == nil {
		return fmt.Errorf("recovery public key is required")
	}

	if createDIDOpts.UpdatePublicKey == nil {
		return fmt.Errorf("update public key is required")
	}

	return nil
}

// UpdateDID update did doc
func (c *Client) UpdateDID(did, domain string, opts ...update.Option) error {
	updateDIDOpts := &update.Opts{}
	// Apply options
	for _, opt := range opts {
		opt(updateDIDOpts)
	}

	if updateDIDOpts.SigningKey == nil {
		return fmt.Errorf("signing public key is required")
	}

	if updateDIDOpts.NextUpdatePublicKey == nil {
		return fmt.Errorf("next update public key is required")
	}

	sidetreeEndpoint, err := c.getEndpoint(domain, updateDIDOpts.SidetreeEndpoints)
	if err != nil {
		return err
	}

	sidetreeConfig, err := c.configService.GetSidetreeConfig(sidetreeEndpoint)
	if err != nil {
		return err
	}

	req, err := c.buildUpdateRequest(did, sidetreeConfig, updateDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build update request: %w", err)
	}

	_, err = c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return fmt.Errorf("failed to send create sidetree request: %w", err)
	}

	return nil
}

// RecoverDID recover did doc
func (c *Client) RecoverDID(did, domain string, opts ...recovery.Option) error {
	recoverDIDOpts := &recovery.Opts{}
	// Apply options
	for _, opt := range opts {
		opt(recoverDIDOpts)
	}

	err := validateRecoverReq(recoverDIDOpts)
	if err != nil {
		return err
	}

	sidetreeEndpoint, err := c.getEndpoint(domain, recoverDIDOpts.SidetreeEndpoints)
	if err != nil {
		return err
	}

	sidetreeConfig, err := c.configService.GetSidetreeConfig(sidetreeEndpoint)
	if err != nil {
		return err
	}

	req, err := buildRecoverRequest(did, sidetreeConfig, recoverDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build sidetree request: %w", err)
	}

	_, err = c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return fmt.Errorf("failed to send recover sidetree request: %w", err)
	}

	return err
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

	req, err := buildDeactivateRequest(did, deactivateDIDOpts)
	if err != nil {
		return fmt.Errorf("failed to build sidetree request: %w", err)
	}

	_, err = c.sendRequest(req, sidetreeEndpoint)
	if err != nil {
		return fmt.Errorf("failed to send deactivate sidetree request: %w", err)
	}

	return err
}

func validateRecoverReq(recoverDIDOpts *recovery.Opts) error {
	if recoverDIDOpts.NextRecoveryPublicKey == nil {
		return fmt.Errorf("next recovery public key is required")
	}

	if recoverDIDOpts.NextUpdatePublicKey == nil {
		return fmt.Errorf("next update public key is required")
	}

	if recoverDIDOpts.SigningKey == nil {
		return fmt.Errorf("signing key is required")
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

// buildUpdateRequest request builder for sidetree public DID update
func (c *Client) buildUpdateRequest(did string, sidetreeConfig *models.SidetreeConfig,
	updateDIDOpts *update.Opts) ([]byte, error) {
	nextUpdateKey, err := pubkey.GetPublicKeyJWK(updateDIDOpts.NextUpdatePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get next update key : %s", err)
	}

	nextUpdateCommitment, err := commitment.Calculate(nextUpdateKey, sidetreeConfig.MultiHashAlgorithm)
	if err != nil {
		return nil, err
	}

	signer, updateKey, err := getSigner(updateDIDOpts.SigningKey, updateDIDOpts.SigningKeyID)
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
		MultihashCode:    sidetreeConfig.MultiHashAlgorithm,
		Signer:           signer,
	})
}

// buildDeactivateRequest request builder for sidetree public DID deactivate
func buildDeactivateRequest(did string, deactivateDIDOpts *deactivate.Opts) ([]byte, error) {
	signer, publicKey, err := getSigner(deactivateDIDOpts.SigningKey, deactivateDIDOpts.SigningKeyID)
	if err != nil {
		return nil, err
	}

	didSuffix, err := getUniqueSuffix(did)
	if err != nil {
		return nil, err
	}

	return client.NewDeactivateRequest(&client.DeactivateRequestInfo{
		DidSuffix:   didSuffix,
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

func createUpdatePatches(updateDIDOpts *update.Opts) ([]patch.Patch, error) {
	var patches []patch.Patch

	if len(updateDIDOpts.RemovePublicKeys) != 0 {
		p, err := createRemovePublicKeysPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	if len(updateDIDOpts.RemoveServices) != 0 {
		p, err := createRemoveServicesPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	if len(updateDIDOpts.AddServices) != 0 {
		p, err := createAddServicesPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	if len(updateDIDOpts.AddPublicKeys) != 0 {
		p, err := createAddPublicKeysPatch(updateDIDOpts)
		if err != nil {
			return nil, err
		}

		patches = append(patches, p)
	}

	return patches, nil
}

func createRemovePublicKeysPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	removePubKeys, err := json.Marshal(updateDIDOpts.RemovePublicKeys)
	if err != nil {
		return nil, err
	}

	return patch.NewRemovePublicKeysPatch(string(removePubKeys))
}

func createRemoveServicesPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	removeServices, err := json.Marshal(updateDIDOpts.RemoveServices)
	if err != nil {
		return nil, err
	}

	return patch.NewRemoveServiceEndpointsPatch(string(removeServices))
}

func createAddServicesPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	addServices, err := json.Marshal(doc.PopulateRawServices(updateDIDOpts.AddServices))
	if err != nil {
		return nil, err
	}

	return patch.NewAddServiceEndpointsPatch(string(addServices))
}

func createAddPublicKeysPatch(updateDIDOpts *update.Opts) (patch.Patch, error) {
	rawPublicKeys, err := doc.PopulateRawPublicKeys(updateDIDOpts.AddPublicKeys)
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
func buildCreateRequest(sidetreeConfig *models.SidetreeConfig, createDIDOpts *create.Opts) ([]byte, error) {
	publicKeys := createDIDOpts.PublicKeys

	var parsedKeys []doc.PublicKey

	for _, key := range publicKeys {
		parsedKey, err := unwrapPubKeyJWK(key)
		if err != nil {
			return nil, err
		}

		parsedKeys = append(parsedKeys, *parsedKey)
	}

	didDoc := &doc.Doc{
		PublicKey: parsedKeys,
		Service:   createDIDOpts.Services,
	}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %s", err)
	}

	recoveryKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.RecoveryPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get recovery key : %s", err)
	}

	updateKey, err := pubkey.GetPublicKeyJWK(createDIDOpts.UpdatePublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get update key : %s", err)
	}

	recoveryCommitment, err := commitment.Calculate(recoveryKey, sidetreeConfig.MultiHashAlgorithm)
	if err != nil {
		return nil, err
	}

	updateCommitment, err := commitment.Calculate(updateKey, sidetreeConfig.MultiHashAlgorithm)
	if err != nil {
		return nil, err
	}

	req, err := client.NewCreateRequest(&client.CreateRequestInfo{
		OpaqueDocument:     string(docBytes),
		RecoveryCommitment: recoveryCommitment,
		UpdateCommitment:   updateCommitment,
		MultihashCode:      sidetreeConfig.MultiHashAlgorithm,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create sidetree request: %w", err)
	}

	return req, nil
}

// buildRecoverRequest request builder for sidetree public DID recovery
func buildRecoverRequest(did string, sidetreeConfig *models.SidetreeConfig,
	recoverDIDOpts *recovery.Opts) ([]byte, error) {
	publicKeys := recoverDIDOpts.PublicKeys

	var parsedKeys []doc.PublicKey

	for _, key := range publicKeys {
		parsedKey, err := unwrapPubKeyJWK(key)
		if err != nil {
			return nil, err
		}

		parsedKeys = append(parsedKeys, *parsedKey)
	}

	didDoc := &doc.Doc{PublicKey: parsedKeys, Service: recoverDIDOpts.Services}

	docBytes, err := didDoc.JSONBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to get document bytes : %s", err)
	}

	nextRecoveryCommitment, nextUpdateCommitment, err := getCommitment(sidetreeConfig, recoverDIDOpts)
	if err != nil {
		return nil, err
	}

	signer, recoveryKey, err := getSigner(recoverDIDOpts.SigningKey, recoverDIDOpts.SigningKeyID)
	if err != nil {
		return nil, err
	}

	didSuffix, err := getUniqueSuffix(did)
	if err != nil {
		return nil, err
	}

	req, err := client.NewRecoverRequest(&client.RecoverRequestInfo{
		DidSuffix: didSuffix, OpaqueDocument: string(docBytes),
		RecoveryCommitment: nextRecoveryCommitment, UpdateCommitment: nextUpdateCommitment,
		MultihashCode: sidetreeConfig.MultiHashAlgorithm, Signer: signer, RecoveryKey: recoveryKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create sidetree request: %w", err)
	}

	return req, nil
}

func getCommitment(sidetreeConfig *models.SidetreeConfig, recoverDIDOpts *recovery.Opts) (string, string, error) {
	nextRecoveryKey, err := pubkey.GetPublicKeyJWK(recoverDIDOpts.NextRecoveryPublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to get next recovery key : %s", err)
	}

	nextUpdateKey, err := pubkey.GetPublicKeyJWK(recoverDIDOpts.NextUpdatePublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to get next update key : %s", err)
	}

	nextRecoveryCommitment, err := commitment.Calculate(nextRecoveryKey, sidetreeConfig.MultiHashAlgorithm)
	if err != nil {
		return "", "", err
	}

	nextUpdateCommitment, err := commitment.Calculate(nextUpdateKey, sidetreeConfig.MultiHashAlgorithm)
	if err != nil {
		return "", "", err
	}

	return nextRecoveryCommitment, nextUpdateCommitment, nil
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
