/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	ariesapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mocklegacykms "github.com/hyperledger/aries-framework-go/pkg/mock/kms/legacykms"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/stretchr/testify/require"

	didbloc "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/didbloc"
)

func TestNew(t *testing.T) {
	t.Run("test combined mode", func(t *testing.T) {
		svc := New(&Config{})
		require.NotNil(t, svc)
		handlers, err := svc.GetRESTHandlers(combinedMode)
		require.NoError(t, err)
		require.NotEmpty(t, handlers)
		require.Equal(t, 2, len(handlers))
		require.Equal(t, registerPath, handlers[0].Path())
		require.Equal(t, resolveDIDEndpoint, handlers[1].Path())
	})

	t.Run("test registrar mode", func(t *testing.T) {
		svc := New(&Config{})
		require.NotNil(t, svc)
		handlers, err := svc.GetRESTHandlers(registrarMode)
		require.NoError(t, err)
		require.NotEmpty(t, handlers)
		require.Equal(t, 1, len(handlers))
		require.Equal(t, registerPath, handlers[0].Path())
	})

	t.Run("test resolver mode", func(t *testing.T) {
		svc := New(&Config{})
		require.NotNil(t, svc)
		handlers, err := svc.GetRESTHandlers(resolverMode)
		require.NoError(t, err)
		require.NotEmpty(t, handlers)
		require.Equal(t, 1, len(handlers))
		require.Equal(t, resolveDIDEndpoint, handlers[0].Path())
	})

	t.Run("test invalid mode", func(t *testing.T) {
		svc := New(&Config{})
		require.NotNil(t, svc)
		_, err := svc.GetRESTHandlers("invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid operation mode")
	})
}

func TestRegisterDIDHandler(t *testing.T) {
	t.Run("test error bad request", func(t *testing.T) {
		handler := getHandler(t, nil, nil, nil, registerPath)

		body, status, err := handleRequest(handler, registerPath, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, body.String(), "invalid request")
	})

	t.Run("test error from kms", func(t *testing.T) {
		handler := getHandler(t, nil,
			&mocklegacykms.CloseableKMS{CreateKeyErr: fmt.Errorf("create key error")}, nil, registerPath)

		req, err := json.Marshal(RegisterDIDRequest{JobID: "1"})
		require.NoError(t, err)

		body, status, err := handleRequest(handler, registerPath, req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)

		var registerResponse RegisterResponse
		require.NoError(t, json.Unmarshal(body.Bytes(), &registerResponse))

		require.Equal(t, "1", registerResponse.JobID)
		require.Equal(t, RegistrationStateFailure, registerResponse.DIDState.State)
		require.Contains(t, registerResponse.DIDState.Reason, "failed to create key set")
	})

	t.Run("test error from create did", func(t *testing.T) {
		handler := getHandler(t, nil,
			&mocklegacykms.CloseableKMS{CreateSigningKeyValue: "key"},
			&didbloc.Client{CreateDIDErr: fmt.Errorf("error create did")}, registerPath)

		req, err := json.Marshal(RegisterDIDRequest{JobID: "1"})
		require.NoError(t, err)

		body, status, err := handleRequest(handler, registerPath, req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)

		var registerResponse RegisterResponse
		require.NoError(t, json.Unmarshal(body.Bytes(), &registerResponse))

		require.Equal(t, "1", registerResponse.JobID)
		require.Equal(t, RegistrationStateFailure, registerResponse.DIDState.State)
		require.Contains(t, registerResponse.DIDState.Reason, "error create did")
	})

	t.Run("test success", func(t *testing.T) {
		handler := getHandler(t, nil,
			&mocklegacykms.CloseableKMS{CreateSigningKeyValue: "key"},
			&didbloc.Client{CreateDIDValue: &did.Doc{ID: "did1"}}, registerPath)

		req, err := json.Marshal(RegisterDIDRequest{JobID: "1"})
		require.NoError(t, err)

		body, status, err := handleRequest(handler, registerPath, req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)

		var registerResponse RegisterResponse
		require.NoError(t, json.Unmarshal(body.Bytes(), &registerResponse))

		require.Equal(t, "1", registerResponse.JobID)
		require.Equal(t, RegistrationStateFinished, registerResponse.DIDState.State)
		require.Empty(t, registerResponse.DIDState.Reason)
		require.Equal(t, "did1", registerResponse.DIDState.Identifier)
		require.Equal(t, 1, len(registerResponse.DIDState.Secret.Keys))
		require.Equal(t, "did1"+pubKeyIndex1, registerResponse.DIDState.Secret.Keys[0].PublicKeyDIDURL)
	})

	t.Run("test success with provided public key", func(t *testing.T) {
		handler := getHandler(t, nil,
			&mocklegacykms.CloseableKMS{CreateSigningKeyValue: "key"},
			&didbloc.Client{CreateDIDValue: &did.Doc{ID: "did1"}}, registerPath)

		req, err := json.Marshal(RegisterDIDRequest{JobID: "1", AddPublicKeys: []*PublicKey{{ID: "#key2",
			Type: "type", Value: "value"}}, AddServices: []*Service{{ID: "serviceID"}}})
		require.NoError(t, err)

		body, status, err := handleRequest(handler, registerPath, req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)

		var registerResponse RegisterResponse
		require.NoError(t, json.Unmarshal(body.Bytes(), &registerResponse))

		require.Equal(t, "1", registerResponse.JobID)
		require.Equal(t, RegistrationStateFinished, registerResponse.DIDState.State)
		require.Empty(t, registerResponse.DIDState.Reason)
		require.Equal(t, "did1", registerResponse.DIDState.Identifier)
		require.Equal(t, 1, len(registerResponse.DIDState.Secret.Keys))
		require.Equal(t, "did1#key2", registerResponse.DIDState.Secret.Keys[0].PublicKeyDIDURL)
	})
}

func TestResolveDIDHandler(t *testing.T) {
	t.Run("test did param missing", func(t *testing.T) {
		handler := getHandler(t, nil, nil, nil, resolveDIDEndpoint)

		body, status, err := handleRequest(handler, resolveDIDEndpoint, nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, body.String(), "url param 'did' is missing")
	})

	t.Run("test error from bloc vdri read", func(t *testing.T) {
		handler := getHandler(t, &mockvdri.MockVDRI{
			ReadFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, err error) {
				return nil, fmt.Errorf("read error")
			}}, nil, nil, resolveDIDEndpoint)

		body, status, err := handleRequest(handler, resolveDIDEndpoint+"?did=123", nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, body.String(), "read error")
	})

	t.Run("test success", func(t *testing.T) {
		handler := getHandler(t, &mockvdri.MockVDRI{
			ReadFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, err error) {
				return &did.Doc{ID: "didID", Context: []string{"context"}}, nil
			}}, nil, nil, resolveDIDEndpoint)

		body, status, err := handleRequest(handler, resolveDIDEndpoint+"?did=123", nil)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body.String(), "didID")
	})
}

func handleRequest(handler Handler, path string, body []byte) (*bytes.Buffer, int, error) { //nolint:lll
	req, err := http.NewRequest(handler.Method(), path, bytes.NewBuffer(body))
	if err != nil {
		return nil, 0, err
	}

	router := mux.NewRouter()

	router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())

	// create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	return rr.Body, rr.Code, nil
}

func getHandler(t *testing.T, blocVDRI vdri.VDRI, kms ariesapi.CloseableKMS,
	didBlocClient didBlocClient, lookup string) Handler {
	svc := New(&Config{})
	require.NotNil(t, svc)

	if blocVDRI != nil {
		svc.blocVDRI = blocVDRI
	}

	if kms != nil {
		svc.kms = kms
	}

	if didBlocClient != nil {
		svc.didBlocClient = didBlocClient
	}

	return handlerLookup(t, svc, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers, err := op.GetRESTHandlers(combinedMode)
	require.NoError(t, err)
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}
