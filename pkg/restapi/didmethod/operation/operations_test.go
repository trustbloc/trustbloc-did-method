/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package operation

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	svc := New()
	require.NotNil(t, svc)
	require.Equal(t, 1, len(svc.GetRESTHandlers()))
}

func TestResolveDIDHandler(t *testing.T) {
	t.Run("test did param missing", func(t *testing.T) {
		handler := getHandler(t, nil, resolveDIDEndpoint)

		body, status, err := handleRequest(handler, resolveDIDEndpoint)
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, body.String(), "url param 'did' is missing")
	})

	t.Run("test error from bloc vdri read", func(t *testing.T) {
		handler := getHandler(t, &mockvdri.MockVDRI{
			ReadFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, err error) {
				return nil, fmt.Errorf("read error")
			}}, resolveDIDEndpoint)

		body, status, err := handleRequest(handler, resolveDIDEndpoint+"?did=123")
		require.NoError(t, err)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, body.String(), "read error")
	})

	t.Run("test success", func(t *testing.T) {
		handler := getHandler(t, &mockvdri.MockVDRI{
			ReadFunc: func(didID string, opts ...vdri.ResolveOpts) (doc *did.Doc, err error) {
				return &did.Doc{ID: "didID", Context: []string{"context"}}, nil
			}}, resolveDIDEndpoint)

		body, status, err := handleRequest(handler, resolveDIDEndpoint+"?did=123")
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Contains(t, body.String(), "didID")
	})
}

func handleRequest(handler Handler, path string) (*bytes.Buffer, int, error) { //nolint:lll
	req, err := http.NewRequest(handler.Method(), path, bytes.NewBuffer([]byte("")))
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

func getHandler(t *testing.T, blocVDRI vdri.VDRI, lookup string) Handler {
	svc := New()
	require.NotNil(t, svc)

	if blocVDRI != nil {
		svc.blocVDRI = blocVDRI
	}

	return handlerLookup(t, svc, lookup)
}

func handlerLookup(t *testing.T, op *Operation, lookup string) Handler {
	handlers := op.GetRESTHandlers()
	require.NotEmpty(t, handlers)

	for _, h := range handlers {
		if h.Path() == lookup {
			return h
		}
	}

	require.Fail(t, "unable to find handler")

	return nil
}
