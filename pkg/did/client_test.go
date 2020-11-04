/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/stretchr/testify/require"

	mockdiscovery "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/discovery"
	mockendpoint "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/endpoint"
	mockselection "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/selection"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/endpoint"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

func TestClient_CreateDID(t *testing.T) {
	t.Run("test domain is empty", func(t *testing.T) {
		v := New()

		doc, err := v.CreateDID("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "domain is empty")
		require.Nil(t, doc)
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v.endpointService = endpoint.NewService(
			discoveryMock(nil, fmt.Errorf("discover error")),
			selectionMock(nil, nil))

		doc, err := v.CreateDID("testnet", WithUpdatePublicKey(pubKey), WithRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "discover error")
		require.Nil(t, doc)

		v.endpointService = endpoint.NewService(
			discoveryMock(nil, nil),
			selectionMock(nil, fmt.Errorf("select error")))

		doc, err = v.CreateDID("testnet", WithUpdatePublicKey(pubKey), WithRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "select error")
		require.Nil(t, doc)

		v.endpointService = endpoint.NewService(
			discoveryMock(nil, nil),
			selectionMock(nil, nil))

		doc, err = v.CreateDID("testnet", WithUpdatePublicKey(pubKey), WithRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "list of endpoints is empty")
		require.Nil(t, doc)
	})

	t.Run("test error from send create sidetree request", func(t *testing.T) {
		v := New()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ed25519UpdatePubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		// failed to create http request
		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "http://[]%20%/"}}, nil
			}}

		doc, err := v.CreateDID("testnet", WithRecoveryPublicKey(ed25519RecoveryPubKey),
			WithUpdatePublicKey(ed25519UpdatePubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create http request")
		require.Nil(t, doc)

		// test failed to send request
		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		doc, err = v.CreateDID("testnet", WithRecoveryPublicKey(ed25519RecoveryPubKey),
			WithUpdatePublicKey(ed25519UpdatePubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send request")
		require.Nil(t, doc)

		// test http status not equal 200
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		doc, err = v.CreateDID("testnet", WithRecoveryPublicKey(ed25519RecoveryPubKey),
			WithUpdatePublicKey(ed25519UpdatePubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "got unexpected response")
		require.Nil(t, doc)

		// test failed to parse did
		serv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err1 := (&did.Doc{ID: "did1"}).JSONBytes()
			require.NoError(t, err1)
			_, err1 = fmt.Fprint(w, string(bytes))
			require.NoError(t, err1)
		}))
		defer serv.Close()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		doc, err = v.CreateDID("testnet", WithRecoveryPublicKey(ed25519RecoveryPubKey),
			WithUpdatePublicKey(ed25519UpdatePubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse public DID document")
		require.Nil(t, doc)
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			b, err := json.Marshal(didResolution{Context: "https://www.w3.org/ns/did-resolution/v1",
				DIDDocument: bytes})
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(b))
			require.NoError(t, err)
		}))
		defer serv.Close()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecUpdatePrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecPubKeyBytes := elliptic.Marshal(ecPrivKey.PublicKey.Curve, ecPrivKey.PublicKey.X, ecPrivKey.PublicKey.Y)

		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		doc, err := v.CreateDID("testnet", WithRecoveryPublicKey(ed25519RecoveryPubKey),
			WithUpdatePublicKey(ecUpdatePrivKey.Public()),
			WithPublicKey(&PublicKey{ID: "key1",
				Type: JWSVerificationKey2020, Encoding: PublicKeyEncodingJwk, KeyType: Ed25519KeyType,
				Value:    ed25519RecoveryPubKey,
				Purposes: []string{KeyPurposeVerificationMethod}}),
			WithPublicKey(&PublicKey{ID: "key2",
				Type:     JWSVerificationKey2020,
				Encoding: PublicKeyEncodingJwk,
				Value:    ecPubKeyBytes,
				KeyType:  P256KeyType,
				Purposes: []string{KeyPurposeVerificationMethod},
			}),
			WithService(&did.Service{ID: "srv1", Type: "type", ServiceEndpoint: "http://example.com",
				Properties: map[string]interface{}{"priority": "1"}}))
		require.NoError(t, err)
		require.Equal(t, "did1", doc.ID)
	})

	t.Run("test create DID - invalid key type", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ed25519UpdatePubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		doc, err := v.CreateDID("testnet", WithRecoveryPublicKey(ed25519RecoveryPubKey),
			WithUpdatePublicKey(ed25519UpdatePubKey), WithPublicKey(&PublicKey{ID: "#key1",
				Type:     JWSVerificationKey2020,
				Encoding: PublicKeyEncodingJwk,
				KeyType:  "InvalidKeyType",
			}),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key type: InvalidKeyType")
		require.Nil(t, doc)
	})

	t.Run("test create DID - EC key error", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		ed25519RecoveryPubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ed25519UpdatePubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		ed25519PubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		doc, err := v.CreateDID("testnet", WithRecoveryPublicKey(ed25519RecoveryPubKey),
			WithUpdatePublicKey(ed25519UpdatePubKey),
			WithPublicKey(&PublicKey{ID: "#key1",
				Type:     JWSVerificationKey2020,
				Encoding: PublicKeyEncodingJwk,
				KeyType:  P256KeyType,
				Value:    ed25519PubKey,
			}),
		)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid EC key")
		require.Nil(t, doc)
	})

	t.Run("test unsupported recovery public key type", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		doc, err := v.CreateDID("testnet", WithRecoveryPublicKey("wrongkey"),
			WithUpdatePublicKey("wrongvalue"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get recovery key")
		require.Nil(t, doc)
	})

	t.Run("test recovery public key empty", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		doc, err := v.CreateDID("testnet")
		require.Error(t, err)
		require.Contains(t, err.Error(), "recovery public key is required")
		require.Nil(t, doc)
	})

	t.Run("test update public key empty", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		doc, err := v.CreateDID("testnet", WithRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "update public key is required")
		require.Nil(t, doc)
	})

	t.Run("test unsupported public key encoding", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bytes, err := (&did.Doc{ID: "did1", Context: []string{did.Context}}).JSONBytes()
			require.NoError(t, err)
			_, err = fmt.Fprint(w, string(bytes))
			require.NoError(t, err)
		}))
		defer serv.Close()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		doc, err := v.CreateDID("testnet", WithRecoveryPublicKey(pubKey), WithUpdatePublicKey(pubKey),
			WithPublicKey(&PublicKey{ID: "#key2",
				Type: JWSVerificationKey2020, Encoding: "wrong", Value: []byte("wrongValue")}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "public key encoding not supported")
		require.Nil(t, doc)
	})

	t.Run("test opts", func(t *testing.T) {
		// test WithTLSConfig
		var opts []Option
		opts = append(opts, WithTLSConfig(&tls.Config{ServerName: "test", MinVersion: tls.VersionTLS12}),
			WithAuthToken("tk1"))

		c := &Client{}

		// Apply options
		for _, opt := range opts {
			opt(c)
		}

		require.Equal(t, "test", c.tlsConfig.ServerName)
		require.Equal(t, "Bearer tk1", c.authToken)

		// test WithPublicKey
		var createOpts []CreateDIDOption
		createOpts = append(createOpts, WithPublicKey(&PublicKey{ID: "#key-2"}))

		createDIDOpts := &CreateDIDOpts{}
		// Apply options
		for _, opt := range createOpts {
			opt(createDIDOpts)
		}

		require.Equal(t, 1, len(createDIDOpts.publicKeys))
		require.Equal(t, "#key-2", createDIDOpts.publicKeys[0].ID)

		// test WithService and  WithSidetreeEndpoint
		createOpts = make([]CreateDIDOption, 0)
		createOpts = append(createOpts, WithService(&did.Service{ID: "serviceID"}),
			WithSidetreeEndpoint("sidetree"))

		createDIDOpts = &CreateDIDOpts{}
		// Apply options
		for _, opt := range createOpts {
			opt(createDIDOpts)
		}

		require.Equal(t, 1, len(createDIDOpts.services))
		require.Equal(t, "serviceID", createDIDOpts.services[0].ID)
		require.Equal(t, "sidetree", createDIDOpts.sidetreeEndpoints[0].URL)
	})
}

func Test_unwrapPubKeyJWK(t *testing.T) {
	t.Run("no wrapping", func(t *testing.T) {
		key := PublicKey{Value: []byte("abcd")}
		key2, err := unwrapPubKeyJWK(key)
		require.NoError(t, err)
		require.Contains(t, string(key2.Value), "abcd")
	})

	t.Run("unwrap wrapped jwk", func(t *testing.T) {
		key := PublicKey{Value: []byte(`{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "test value"
}`)}
		key2, err := unwrapPubKeyJWK(key)
		require.NoError(t, err)
		require.Contains(t, string(key2.Value), "test value")
	})

	t.Run("error unsupported type", func(t *testing.T) {
		key := PublicKey{Value: []byte(`{
          "kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"enc",
          "kid":"1"}`)}
		_, err := unwrapPubKeyJWK(key)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported PublicKey source key type")
	})
}

func discoveryMock(endpoints []*models.Endpoint, err error) *mockdiscovery.MockDiscoveryService {
	return &mockdiscovery.MockDiscoveryService{
		GetEndpointsFunc: func(string) ([]*models.Endpoint, error) {
			return endpoints, err
		},
	}
}

func selectionMock(endpoints []*models.Endpoint, err error) *mockselection.MockSelectionService {
	return &mockselection.MockSelectionService{
		SelectEndpointsFunc: func(string, []*models.Endpoint) ([]*models.Endpoint, error) {
			return endpoints, err
		},
	}
}
