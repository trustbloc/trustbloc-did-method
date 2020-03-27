/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"fmt"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	ariescontext "github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/hyperledger/aries-framework-go/pkg/storage/mem"

	didclient "github.com/trustbloc/trustbloc-did-method/pkg/did"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/context"
)

const (
	maxRetry = 10
)

// Steps is steps for VC BDD tests
type Steps struct {
	bddContext *context.BDDContext
	createdDID string
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^TrustBloc DID is created from domain "([^"]*)"$`, e.createDIDBloc)
	s.Step(`^Resolving created DID through resolver URL "([^"]*)"$`, e.resolveCreatedDID)
}

func (e *Steps) createDIDBloc(domain string) error {
	kms, err := createKMS(mem.NewProvider())
	if err != nil {
		return err
	}

	c := didclient.New(didclient.WithKMS(kms), didclient.WithTLSConfig(e.bddContext.TLSConfig))

	doc, err := c.CreateDID(domain)
	if err != nil {
		return err
	}

	e.createdDID = doc.ID

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
