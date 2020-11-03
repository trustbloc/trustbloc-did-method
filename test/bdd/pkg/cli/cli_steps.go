/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cli

import (
	"bytes"
	"fmt"
	"os/exec"

	"github.com/cucumber/godog"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/context"
)

// Steps is steps for cli BDD tests.
type Steps struct {
	bddContext *context.BDDContext
	cliValue   string
}

// NewSteps returns new agent from client SDK.
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

// RegisterSteps registers agent steps.
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^TrustBloc DID is created through cli using domain "([^"]*)"$`, e.createDID)
	s.Step(`^TrustBloc DID is created through cli using direct url "([^"]*)"$`, e.createDIDDirect)
	s.Step(`^check cli created valid DID$`, e.checkCreatedDID)
}

func (e *Steps) checkCreatedDID() error {
	const numberOfPublicKeys = 2

	const numberOfServices = 2

	doc, err := ariesdid.ParseDocument([]byte(e.cliValue))
	if err != nil {
		return err
	}

	if len(doc.PublicKey) != numberOfPublicKeys {
		return fmt.Errorf("did doc public key is not equal to 2")
	}

	if len(doc.Service) != numberOfServices {
		return fmt.Errorf("did doc services is not equal to 2")
	}

	return nil
}

func (e *Steps) createDID(domain string) error {
	return e.executeCreateDIDCMD(domain, "")
}

func (e *Steps) createDIDDirect(sidetreeURL string) error {
	return e.executeCreateDIDCMD("", sidetreeURL)
}

func (e *Steps) executeCreateDIDCMD(domain, sidetreeURL string) error {
	var args []string

	if domain != "" {
		args = append(args, "--domain", domain)
	}

	if sidetreeURL != "" {
		args = append(args, "--sidetree-url", sidetreeURL)
	}

	args = append(args, "create-did",
		"--tls-cacerts", "fixtures/keys/tls/ec-cacert.pem", "--publickey-file", "fixtures/did-keys/publickeys.json",
		"--sidetree-write-token", "rw_token", "--service-file", "fixtures/did-services/services.json",
		"--recoverykey-file", "./fixtures/keys/recover/public.pem", "--updatekey-file", "./fixtures/keys/update/public.pem")

	value, err := execCMD("../../.build/bin/cli", args...)

	if err != nil {
		return err
	}

	e.cliValue = value

	return nil
}

func execCMD(command string, args ...string) (string, error) {
	cmd := exec.Command(command, args...) // nolint: gosec

	var out bytes.Buffer

	var stderr bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf(fmt.Sprint(err) + ": " + stderr.String())
	}

	return out.String(), nil
}
