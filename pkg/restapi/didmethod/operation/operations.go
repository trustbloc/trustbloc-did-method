/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	log "github.com/sirupsen/logrus"

	didclient "github.com/trustbloc/trustbloc-did-method/pkg/did"
	"github.com/trustbloc/trustbloc-did-method/pkg/internal/common/support"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

const (
	registerBasePath     = "/1.0"
	registerPath         = registerBasePath + "/register"
	resolveDIDEndpoint   = "/resolveDID"
	didLDJson            = "application/did+ld+json"
	invalidRequestErrMsg = "invalid request"

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
	blocVDRI      vdr.VDR
	didBlocClient didBlocClient
	blocDomain    string
}

// Config defines configuration for trustbloc did method operations
type Config struct {
	TLSConfig          *tls.Config
	BlocDomain         string
	Mode               string
	SidetreeReadToken  string
	SidetreeWriteToken string
	EnableSignatures   bool
}

type didBlocClient interface {
	CreateDID(domain string, opts ...didclient.CreateDIDOption) (*did.Doc, error)
}

// New returns did method operation instance
func New(config *Config) *Operation {
	svc := &Operation{blocVDRI: trustbloc.New(trustbloc.WithTLSConfig(config.TLSConfig),
		trustbloc.WithAuthToken(config.SidetreeReadToken), trustbloc.EnableSignatureVerification(config.EnableSignatures),
		trustbloc.WithDomain(config.BlocDomain)),
		didBlocClient: didclient.New(didclient.WithTLSConfig(config.TLSConfig),
			didclient.WithAuthToken(config.SidetreeWriteToken)),
		blocDomain: config.BlocDomain}

	return svc
}

func (o *Operation) registerDIDHandler(rw http.ResponseWriter, req *http.Request) { //nolint: funlen,gocyclo
	data := RegisterDIDRequest{}

	if err := json.NewDecoder(req.Body).Decode(&data); err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest, fmt.Sprintf(invalidRequestErrMsg+": %s", err.Error()))

		return
	}

	var opts []didclient.CreateDIDOption

	registerResponse := RegisterResponse{JobID: data.JobID}
	keysID := make(map[string][]byte)

	if len(data.DIDDocument.PublicKey) == 0 {
		registerResponse.DIDState = DIDState{Reason: "AddPublicKeys is empty",
			State: RegistrationStateFailure}

		o.writeResponse(rw, registerResponse)

		return
	}

	// Add public keys
	for _, v := range data.DIDDocument.PublicKey {
		keyValue, err := base64.StdEncoding.DecodeString(v.Value)
		if err != nil {
			log.Errorf("failed to decode public key value : %s", err.Error())

			registerResponse.DIDState = DIDState{Reason: fmt.Sprintf("failed to decode public key value : %s",
				err.Error()), State: RegistrationStateFailure}

			o.writeResponse(rw, registerResponse)

			return
		}

		if v.Recovery {
			k, err := getKey(v.KeyType, keyValue)
			if err != nil {
				registerResponse.DIDState = DIDState{Reason: err.Error(), State: RegistrationStateFailure}

				o.writeResponse(rw, registerResponse)

				return
			}

			opts = append(opts, didclient.WithRecoveryPublicKey(k))

			continue
		}

		if v.Update {
			k, err := getKey(v.KeyType, keyValue)
			if err != nil {
				registerResponse.DIDState = DIDState{Reason: err.Error(), State: RegistrationStateFailure}

				o.writeResponse(rw, registerResponse)

				return
			}

			opts = append(opts, didclient.WithUpdatePublicKey(k))

			continue
		}

		opts = append(opts, didclient.WithPublicKey(&didclient.PublicKey{ID: v.ID, Type: v.Type, Value: keyValue,
			Encoding: v.Encoding, Purposes: v.Purposes, KeyType: v.KeyType}))

		keysID[v.ID] = keyValue
	}

	// Add services
	for _, service := range data.DIDDocument.Service {
		opts = append(opts, didclient.WithService(&did.Service{ID: service.ID, Type: service.Type,
			Priority: service.Priority, RecipientKeys: service.RecipientKeys, RoutingKeys: service.RoutingKeys,
			ServiceEndpoint: service.Endpoint}))
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

func getKey(keyType string, value []byte) (interface{}, error) {
	switch keyType {
	case didclient.Ed25519KeyType:
		return ed25519.PublicKey(value), nil
	case didclient.P256KeyType:
		x, y := elliptic.Unmarshal(elliptic.P256(), value)

		return &ecdsa.PublicKey{X: x, Y: y, Curve: elliptic.P256()}, nil
	default:
		return nil, fmt.Errorf("invalid key type: %s", keyType)
	}
}

func createKeys(keysID map[string][]byte, didID string) []Key {
	keys := make([]Key, 0)

	for k, v := range keysID {
		keys = append(keys, Key{ID: didID + "#" + k, PublicKeyBase58: base58.Encode(v)})
	}

	return keys
}

func (o *Operation) resolveDIDHandler(rw http.ResponseWriter, req *http.Request) {
	didParam, ok := req.URL.Query()["did"]

	if !ok || didParam[0] == "" {
		o.writeErrorResponse(rw, http.StatusBadRequest, "url param 'did' is missing")

		return
	}

	didDoc, err := o.blocVDRI.Read(didParam[0])
	if err != nil {
		o.writeErrorResponse(rw, http.StatusBadRequest,
			fmt.Sprintf("failed to resolve did: %s", err.Error()))

		return
	}

	bytes, err := models.MakeDIDResolutionResult(didDoc)
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
