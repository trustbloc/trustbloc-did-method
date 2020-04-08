/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	ariescontext "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"

	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/context"
)

const (
	maxRetry     = 10
	pubKeyIndex1 = "#key-1"
	keyType      = "Ed25519VerificationKey2018"
	serviceID    = "#service"
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
	s.Step(`^TrustBloc DID is created through registrar "([^"]*)"$`, e.createDIDBloc)
	s.Step(`^Resolving created DID through resolver URL "([^"]*)"$`, e.resolveCreatedDID)
}

func (e *Steps) createDIDBloc(url string) error {
	kms, err := createKMS(mem.NewProvider())
	if err != nil {
		return err
	}

	_, base58PubKey, err := kms.CreateKeySet()
	if err != nil {
		return err
	}

	jobID := uuid.New().String()

	reqBytes, err := json.Marshal(operation.RegisterDIDRequest{JobID: jobID,
		AddPublicKeys: []*operation.PublicKey{{ID: pubKeyIndex1, Type: keyType, Value: base58PubKey}},
		AddServices:   []*did.Service{{ID: serviceID, ServiceEndpoint: "http://www.example.com/"}}})
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
		return fmt.Errorf("register response jobID=%s not equal %s", registerResponse.JobID, jobID)
	}

	e.createdDID = registerResponse.DIDState.Identifier

	return nil
}

func (e *Steps) resolveCreatedDID(url string) error {
	blocVDRI := trustbloc.New(trustbloc.WithResolverURL(url), trustbloc.WithTLSConfig(e.bddContext.TLSConfig))

	var doc *did.Doc

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

	if doc.Service[0].ID != serviceID {
		return fmt.Errorf("resolved did service ID %s not equal to %s", doc.Service[0].ID, serviceID)
	}

	if doc.PublicKey[0].ID != doc.ID+pubKeyIndex1 {
		return fmt.Errorf("resolved did public key ID %s not equal to %s",
			doc.PublicKey[0].ID, doc.ID+pubKeyIndex1)
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
