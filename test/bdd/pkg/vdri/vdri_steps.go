/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package vdri

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/google/uuid"
	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"

	"github.com/trustbloc/trustbloc-did-method/pkg/did/doc"
	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
	"github.com/trustbloc/trustbloc-did-method/test/bdd/pkg/context"
)

const (
	maxRetry  = 10
	serviceID = "service"
	// P256KeyType EC P-256 key type
	P256KeyType = "P256"
)

// Steps is steps for VC BDD tests
type Steps struct {
	bddContext *context.BDDContext
	createdDID string
	httpClient *http.Client
	blocVDRI   *trustbloc.VDRI
}

// NewSteps returns new agent from client SDK
func NewSteps(ctx *context.BDDContext) *Steps {
	return &Steps{bddContext: ctx, httpClient: &http.Client{}}
}

// RegisterSteps registers agent steps
func (e *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^TrustBloc DID is created through registrar "([^"]*)" with key type "([^"]*)" with signature suite "([^"]*)"$`, e.createDIDBloc) //nolint: lll
	s.Step(`^Resolve created DID and validate key type "([^"]*)", signature suite "([^"]*)"$`,                                               //nolint: lll
		e.resolveCreatedDID)
	s.Step(`^DID resolution fails, containing error "([^"]*)"$`, e.didResolutionError)
	s.Step(`^Consortium config is updated with config file "([^"]*)"$`, e.updateConfig)
	s.Step(`^Consortium config is generated with config file "([^"]*)"$`, e.generateConfig)
	s.Step(`^Consortium config is deleted$`, e.deleteConfig)
	s.Step(`^Bloc VDRI is initialized with genesis file "([^"]*)"$`, e.initBlocVDRIWithGenesisFile)
	s.Step(`^Bloc VDRI is initialized with resolver URL "([^"]*)"$`, e.initBlocVDRIWithResolverURL)
}

func (e *Steps) createDIDBloc(url, keyType, signatureSuite string) error { //nolint: funlen,gocyclo
	kid, pubKey, err := e.getPublicKey(keyType)
	if err != nil {
		return err
	}

	_, updateKey, err := e.getPublicKey(keyType)
	if err != nil {
		return err
	}

	_, recoveryKey, err := e.getPublicKey(keyType)
	if err != nil {
		return err
	}

	jobID := uuid.New().String()

	reqBytes, err := json.Marshal(operation.RegisterDIDRequest{JobID: jobID, DIDDocument: operation.DIDDocument{
		PublicKey: []*operation.PublicKey{
			{ID: kid, Type: signatureSuite, Value: base64.StdEncoding.EncodeToString(pubKey),
				Encoding: doc.PublicKeyEncodingJwk, KeyType: keyType, Purposes: []string{doc.KeyPurposeAuthentication}},
			{Type: doc.JWSVerificationKey2020, Value: base64.StdEncoding.EncodeToString(recoveryKey),
				KeyType: keyType, Encoding: doc.PublicKeyEncodingJwk, Recovery: true},
			{Type: doc.JWSVerificationKey2020, Value: base64.StdEncoding.EncodeToString(updateKey),
				KeyType: keyType, Encoding: doc.PublicKeyEncodingJwk, Update: true},
		},
		Service: []*operation.Service{{ID: serviceID, Type: "type", Endpoint: "http://www.example.com/"}}}})
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

func (e *Steps) initBlocVDRIWithResolverURL(url string) error {
	e.blocVDRI = trustbloc.New(trustbloc.WithResolverURL(url), trustbloc.WithTLSConfig(e.bddContext.TLSConfig),
		trustbloc.WithAuthToken("rw_token"), trustbloc.WithDomain("testnet.trustbloc.local"))

	return nil
}

func (e *Steps) initBlocVDRIWithGenesisFile(genesisFileName string) error {
	genesisFile, err := ioutil.ReadFile(filepath.Clean(genesisFileName))
	if err != nil {
		return err
	}

	e.blocVDRI = trustbloc.New(trustbloc.WithTLSConfig(e.bddContext.TLSConfig),
		trustbloc.WithAuthToken("rw_token"), trustbloc.WithDomain("testnet.trustbloc.local"),
		trustbloc.UseGenesisFile("testnet.trustbloc.local", "testnet.trustbloc.local", genesisFile))

	return nil
}

func (e *Steps) didResolutionError(errorMessageContains string) error {
	if e.blocVDRI == nil {
		return fmt.Errorf("bloc VDRI must be initialized before this step")
	}

	var err error

	for i := 1; i <= maxRetry; i++ {
		_, err = e.blocVDRI.Read(e.createdDID)

		if err != nil && (!strings.Contains(err.Error(), "DID does not exist") || i == maxRetry) {
			break
		}

		time.Sleep(1 * time.Second)
	}

	if err == nil {
		return fmt.Errorf("error required but error was nil")
	}

	if !strings.Contains(err.Error(), errorMessageContains) {
		return fmt.Errorf("error should contain %s, error is instead: %w", errorMessageContains, err)
	}

	return nil
}

func (e *Steps) resolveCreatedDID(keyType, signatureSuite string) error {
	if e.blocVDRI == nil {
		return fmt.Errorf("bloc VDRI must be initialized before this step")
	}

	var didDoc *ariesdid.Doc

	for i := 1; i <= maxRetry; i++ {
		var err error
		didDoc, err = e.blocVDRI.Read(e.createdDID)

		if err != nil && (!strings.Contains(err.Error(), "DID does not exist") || i == maxRetry) {
			return err
		}

		time.Sleep(1 * time.Second)
	}

	if didDoc.ID != e.createdDID {
		return fmt.Errorf("resolved did %s not equal to created did %s", didDoc.ID, e.createdDID)
	}

	if didDoc.Service[0].ID != didDoc.ID+"#"+serviceID {
		return fmt.Errorf("resolved did service ID %s not equal to %s",
			didDoc.Service[0].ID, didDoc.ID+"#"+serviceID)
	}

	if err := validatePublicKey(didDoc, keyType, signatureSuite); err != nil {
		return err
	}

	return nil
}

func (e *Steps) generateConfig(config string) error {
	return execCMD("./generate_config.sh", config)
}

func (e *Steps) updateConfig(config string) error {
	return execCMD("./update_config.sh", config)
}

func (e *Steps) deleteConfig() error {
	return os.RemoveAll("./fixtures/wellknown/jws")
}

func (e *Steps) getPublicKey(keyType string) (string, []byte, error) {
	var kt kms.KeyType

	switch keyType {
	case doc.Ed25519KeyType:
		kt = kms.ED25519Type
	case P256KeyType:
		kt = kms.ECDSAP256TypeIEEEP1363
	}

	return e.bddContext.LocalKMS.CreateAndExportPubKeyBytes(kt)
}

func validatePublicKey(didDoc *ariesdid.Doc, keyType, signatureSuite string) error {
	if len(didDoc.VerificationMethod) != 1 {
		return fmt.Errorf("veification method size not equal one")
	}

	expectedJwkKeyType := ""

	var kt kms.KeyType

	switch keyType {
	case doc.Ed25519KeyType:
		expectedJwkKeyType = "OKP"
		kt = kms.ED25519Type
	case P256KeyType:
		expectedJwkKeyType = "EC"
		kt = kms.ECDSAP256TypeIEEEP1363
	}

	if signatureSuite == doc.JWSVerificationKey2020 &&
		expectedJwkKeyType != didDoc.VerificationMethod[0].JSONWebKey().Kty {
		return fmt.Errorf("jwk key type : expected=%s actual=%s", expectedJwkKeyType,
			didDoc.VerificationMethod[0].JSONWebKey().Kty)
	}

	if signatureSuite == doc.Ed25519VerificationKey2018 &&
		didDoc.VerificationMethod[0].JSONWebKey() != nil {
		return fmt.Errorf("jwk is not nil for %s", signatureSuite)
	}

	return verifyPublicKeyAndType(didDoc, kt, signatureSuite)
}

func verifyPublicKeyAndType(didDoc *ariesdid.Doc, kt kms.KeyType, signatureSuite string) error {
	pubKeyID, err := localkms.CreateKID(didDoc.VerificationMethod[0].Value, kt)
	if err != nil {
		return err
	}

	if didDoc.VerificationMethod[0].ID != didDoc.ID+"#"+pubKeyID {
		return fmt.Errorf("resolved did public key ID %s not equal to %s",
			didDoc.VerificationMethod[0].ID, didDoc.ID+"#"+pubKeyID)
	}

	if didDoc.VerificationMethod[0].Type != signatureSuite {
		return fmt.Errorf("resolved did public key type %s not equal to %s",
			didDoc.VerificationMethod[0].Type, signatureSuite)
	}

	return nil
}

func execCMD(command string, args ...string) error {
	cmd := exec.Command(command, args...) // nolint: gosec

	var out bytes.Buffer

	var er bytes.Buffer

	cmd.Stdout = &out
	cmd.Stderr = &er

	err := cmd.Start()
	if err != nil {
		return fmt.Errorf(er.String())
	}

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf(er.String())
	}

	return nil
}
