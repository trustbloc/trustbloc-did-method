/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	log "github.com/sirupsen/logrus"

	didclient "github.com/trustbloc/trustbloc-did-method/pkg/did"
	"github.com/trustbloc/trustbloc-did-method/pkg/internal/common/support"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
)

const (
	registerBasePath     = "/1.0"
	registerPath         = registerBasePath + "/register"
	resolveDIDEndpoint   = "/resolveDID"
	didLDJson            = "application/did+ld+json"
	invalidRequestErrMsg = "invalid request"

	// DID public key
	pubKeyIndex1 = "#key-1"
	keyType      = "Ed25519VerificationKey2018"

	// modes
	registrarMode = "registrar"
	resolverMode  = "resolver"
	combinedMode  = "combined"
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers
type Operation struct {
	blocVDRI      vdri.VDRI
	didBlocClient didBlocClient
	blocDomain    string
	kms           ariesapi.CloseableKMS
}

// Config defines configuration for trustbloc did method operations
type Config struct {
	TLSConfig  *tls.Config
	BlocDomain string
	KMS        ariesapi.CloseableKMS
	Mode       string
}

type didBlocClient interface {
	CreateDID(domain string, opts ...didclient.CreateDIDOption) (*did.Doc, error)
}

// New returns did method operation instance
func New(config *Config) *Operation {
	svc := &Operation{blocVDRI: trustbloc.New(trustbloc.WithTLSConfig(config.TLSConfig)),
		didBlocClient: didclient.New(didclient.WithTLSConfig(config.TLSConfig)),
		blocDomain:    config.BlocDomain, kms: config.KMS}

	return svc
}

func (o *Operation) registerDIDHandler(rw http.ResponseWriter, req *http.Request) { //nolint: funlen
	data := RegisterDIDRequest{}

	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	var opts []didclient.CreateDIDOption

	registerResponse := RegisterResponse{JobID: data.JobID}
	keysID := make(map[string]string)

	if len(data.AddPublicKeys) == 0 {
		// TODO change kms to return private key
		_, base58PubKey, err := o.kms.CreateKeySet()
		if err != nil {
			log.Errorf("failed to create key set : %s", err.Error())

			registerResponse.DIDState = DIDState{Reason: fmt.Sprintf("failed to create key set : %s",
				err.Error()), State: RegistrationStateFailure}

			o.writeResponse(rw, registerResponse)

			return
		}

		keysID[pubKeyIndex1] = base58PubKey

		opts = append(opts, didclient.WithPublicKey(did.PublicKey{ID: pubKeyIndex1, Type: keyType,
			Value: base58.Decode(base58PubKey)}))
	} else {
		for _, v := range data.AddPublicKeys {
			keysID[v.ID] = v.Value

			opts = append(opts, didclient.WithPublicKey(did.PublicKey{ID: v.ID, Type: v.Type,
				Value: base58.Decode(v.Value)}))
		}
	}

	// Add services
	for _, service := range data.AddServices {
		opts = append(opts, didclient.WithService(service))
	}

	didDoc, err := o.didBlocClient.CreateDID(o.blocDomain, opts...)
	if err != nil {
		log.Errorf("failed to create did doc : %s", err.Error())

		registerResponse.DIDState = DIDState{Reason: fmt.Sprintf("failed to create did doc : %s", err.Error()),
			State: RegistrationStateFailure}

		o.writeResponse(rw, registerResponse)

		return
	}

	registerResponse.DIDState = DIDState{Identifier: didDoc.ID, State: RegistrationStateFinished,
		Secret: Secret{Keys: createKeys(keysID, didDoc.ID)}}

	o.writeResponse(rw, registerResponse)
}

func createKeys(keysID map[string]string, didID string) []Key {
	keys := make([]Key, 0)

	for k, v := range keysID {
		// TODO add PrivateKeyBase58
		keys = append(keys, Key{PublicKeyDIDURL: didID + k, PublicKeyBase58: v})
	}

	return keys
}

func (o *Operation) resolveDIDHandler(rw http.ResponseWriter, req *http.Request) {
	didParam, ok := req.URL.Query()["did"]

	if !ok || didParam[0] == "" {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("url param 'did' is missing"))

		return
	}

	didDoc, err := o.blocVDRI.Read(didParam[0])
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to resolve did: %s", err.Error()))

		return
	}

	bytes, err := didDoc.JSONBytes()
	if err != nil {
		o.writeErrorResponse(rw, http.StatusInternalServerError,
			fmt.Sprintf("failed to marshal did doc: %s", err.Error()))

		return
	}

	rw.Header().Set("Content-type", didLDJson)
	rw.WriteHeader(http.StatusOK)

	if _, err := rw.Write(bytes); err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
}

// writeErrorResponse writes interface value to response
func (o *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
}

// writeResponse writes interface value to response
func (o *Operation) writeResponse(rw io.Writer, v interface{}) {
	err := json.NewEncoder(rw).Encode(v)
	if err != nil {
		log.Errorf("Unable to send error response, %s", err)
	}
}

func (o *Operation) registrarHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(registerPath, http.MethodPost, o.registerDIDHandler)}
}

func (o *Operation) resolverHandlers() []Handler {
	return []Handler{
		support.NewHTTPHandler(resolveDIDEndpoint, http.MethodGet, o.resolveDIDHandler)}
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers(mode string) ([]Handler, error) {
	switch mode {
	case registrarMode:
		return o.registrarHandlers(), nil
	case resolverMode:
		return o.resolverHandlers(), nil
	case combinedMode:
		vh := o.registrarHandlers()
		ih := o.resolverHandlers()

		return append(vh, ih...), nil
	default:
		return nil, fmt.Errorf("invalid operation mode: %s", mode)
	}
}
