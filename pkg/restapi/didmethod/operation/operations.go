/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"fmt"
	"net/http"

	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/bloc-did-method/pkg/internal/common/support"
	"github.com/trustbloc/bloc-did-method/pkg/vdri/bloc"
)

const (
	resolveDIDEndpoint = "/resolveDID"

	didLDJson = "application/did+ld+json"
)

// Handler http handler for each controller API endpoint
type Handler interface {
	Path() string
	Method() string
	Handle() http.HandlerFunc
}

// Operation defines handlers
type Operation struct {
	handlers []Handler
	blocVDRI vdri.VDRI
}

// New returns rp operation instance
func New() *Operation {
	svc := &Operation{blocVDRI: bloc.New()}
	svc.registerHandler()

	return svc
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

// writeResponse writes interface value to response
func (o *Operation) writeErrorResponse(rw http.ResponseWriter, status int, msg string) {
	rw.WriteHeader(status)

	if _, err := rw.Write([]byte(msg)); err != nil {
		log.Errorf("Unable to send error message, %s", err)
	}
}

// registerHandler register handlers to be exposed from this service as REST API endpoints
func (o *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	o.handlers = []Handler{support.NewHTTPHandler(resolveDIDEndpoint, http.MethodGet, o.resolveDIDHandler)}
}

// GetRESTHandlers get all controller API handler available for this service
func (o *Operation) GetRESTHandlers() []Handler {
	return o.handlers
}
