/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cucumber/godog"
	"github.com/google/uuid"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	ariescontext "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"

	"github.com/trustbloc/trustbloc-did-method/pkg/did"
	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/context"
)

const (
	maxRetry     = 10
	pubKeyIndex1 = "key-1"
	pubKeyIndex2 = "key-2"
	serviceID    = "service"
	// P256KeyType EC P-256 key type
	P256KeyType = "P256"
)

// Steps is steps for VC BDD tests
type Steps struct {
	bddContext *context.BDDContext
	createdDID string
	httpClient *http.Client
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx, httpClient: &http.Client{}}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^TrustBloc DID is created through registrar "([^"]*)" with key type "([^"]*)" with signature suite "([^"]*)"$`, e.createDIDBloc) //nolint: lll
	s.Step(`^Resolve created DID through resolver URL "([^"]*)" and validate key type "([^"]*)", signature suite "([^"]*)"$`,                //nolint: lll
		e.resolveCreatedDID)
}

func (e *Steps) createDIDBloc(url, keyType, signatureSuite string) error { //nolint: gocyclo,funlen
	pubKey, err := getPublicKey(keyType)
	if err != nil {
		return err
	}

	jobID := uuid.New().String()

	reqBytes, err := json.Marshal(operation.RegisterDIDRequest{JobID: jobID, DIDDocument: operation.DIDDocument{
		PublicKey: []*operation.PublicKey{{ID: pubKeyIndex1, Type: signatureSuite,
			Value: base64.StdEncoding.EncodeToString(pubKey), Encoding: did.PublicKeyEncodingJwk, KeyType: keyType,
			Usage: []string{did.KeyUsageGeneral}}, {ID: pubKeyIndex2, Type: did.JWSVerificationKey2020,
			Value: base64.StdEncoding.EncodeToString(pubKey), KeyType: keyType,
			Encoding: did.PublicKeyEncodingJwk, Recovery: true}},
		Service: []*operation.Service{{ID: serviceID, Type: "type", ServiceEndpoint: "http://www.example.com/"}}}})
	if err != nil {
		return err
	}

	resp, err := e.httpClient.Post(url, "application/json", bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			fmt.Println(errClose.Error())
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status code is not ok: %s", body)
	}

	var registerResponse operation.RegisterResponse
	if err := json.Unmarshal(body, &registerResponse); err != nil {
		return err
	}

	if jobID != registerResponse.JobID {
		return fmt.Errorf("register response jobID %s not equal %s", registerResponse.JobID, jobID)
	}

	if registerResponse.DIDState.State == operation.RegistrationStateFailure {
		return fmt.Errorf("register response state %s reason %s",
			registerResponse.DIDState.State, registerResponse.DIDState.Reason)
	}

	e.createdDID = registerResponse.DIDState.Identifier

	return nil
}

func (e *Steps) resolveCreatedDID(url, keyType, signatureSuite string) error {
	blocVDRI := trustbloc.New(trustbloc.WithResolverURL(url), trustbloc.WithTLSConfig(e.bddContext.TLSConfig),
		trustbloc.WithAuthToken("rw_token"))

	var doc *ariesdid.Doc

	for i := 1; i <= maxRetry; i++ {
		var err error
		doc, err = blocVDRI.Read(e.createdDID)

		if err != nil && (!strings.Contains(err.Error(), "DID does not exist") || i == maxRetry) {
			return err
		}

		time.Sleep(1 * time.Second)
	}

	if doc.ID != e.createdDID {
		return fmt.Errorf("resolved did %s not equal to created did %s", doc.ID, e.createdDID)
	}

	if doc.Service[0].ID != doc.ID+"#"+serviceID {
		return fmt.Errorf("resolved did service ID %s not equal to %s", doc.Service[0].ID, doc.ID+"#"+serviceID)
	}

	if err := validatePublicKey(doc, keyType, signatureSuite); err != nil {
		return err
	}

	return nil
}

func createKMS(s storage.Provider) (ariesapi.CloseableKMS, error) {
	kmsProvider, err := ariescontext.New(ariescontext.WithStorageProvider(s))
	if err != nil {
		return nil, fmt.Errorf("failed to create new kms provider: %w", err)
	}

	kms, err := legacykms.New(kmsProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create new kms: %w", err)
	}

	return kms, nil
}

func getPublicKey(keyType string) ([]byte, error) {
	var pubKey []byte

	switch keyType {
	case did.Ed25519KeyType:
		kms, err := createKMS(mem.NewProvider())
		if err != nil {
			return nil, err
		}

		_, base58PubKey, err := kms.CreateKeySet()
		if err != nil {
			return nil, err
		}

		pubKey = base58.Decode(base58PubKey)
	case P256KeyType:
		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		ecPubKeyBytes := elliptic.Marshal(ecPrivKey.PublicKey.Curve, ecPrivKey.PublicKey.X, ecPrivKey.PublicKey.Y)

		pubKey = ecPubKeyBytes
	}

	return pubKey, nil
}

func validatePublicKey(doc *ariesdid.Doc, keyType, signatureSuite string) error {
	if len(doc.PublicKey) != 1 {
		return fmt.Errorf("public key size not equal one")
	}

	expectedJwkKeyType := ""

	switch keyType {
	case did.Ed25519KeyType:
		expectedJwkKeyType = "OKP"
	case P256KeyType:
		expectedJwkKeyType = "EC"
	}

	if signatureSuite == did.JWSVerificationKey2020 &&
		expectedJwkKeyType != doc.PublicKey[0].JSONWebKey().Kty {
		return fmt.Errorf("jwk key type : expected=%s actual=%s", expectedJwkKeyType,
			doc.PublicKey[0].JSONWebKey().Kty)
	}

	if signatureSuite == did.Ed25519VerificationKey2018 &&
		doc.PublicKey[0].JSONWebKey() != nil {
		return fmt.Errorf("jwk is not nil for %s", signatureSuite)
	}

	if doc.PublicKey[0].ID != doc.ID+"#"+pubKeyIndex1 {
		return fmt.Errorf("resolved did public key ID %s not equal to %s",
			doc.PublicKey[0].ID, doc.ID+"#"+pubKeyIndex1)
	}

	if doc.PublicKey[0].Type != signatureSuite {
		return fmt.Errorf("resolved did public key type %s not equal to %s",
			doc.PublicKey[0].Type, signatureSuite)
	}

	return nil
}
