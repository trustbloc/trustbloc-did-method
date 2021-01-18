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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/stretchr/testify/require"
	"github.com/trustbloc/sidetree-core-go/pkg/commitment"
	"github.com/trustbloc/sidetree-core-go/pkg/jws"
	"github.com/trustbloc/sidetree-core-go/pkg/util/pubkey"

	"github.com/trustbloc/trustbloc-did-method/pkg/did/doc"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/deactivate"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/recovery"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/update"
	mockconfig "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/config"
	mockdiscovery "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/discovery"
	mockendpoint "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/endpoint"
	mockselection "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/selection"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/endpoint"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

func TestClient_DeactivateDID(t *testing.T) {
	t.Run("test domain is empty", func(t *testing.T) {
		v := New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123", "", deactivate.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "domain is empty")
	})

	t.Run("test signing key empty", func(t *testing.T) {
		v := New()

		err := v.DeactivateDID("did:ex:123", "testnet")
		require.Error(t, err)
		require.Contains(t, err.Error(), "signing key is required")
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v.endpointService = endpoint.NewService(
			discoveryMock([]*models.Endpoint{}, fmt.Errorf("discover error")),
			selectionMock([]*models.Endpoint{}, nil))

		err = v.DeactivateDID("did:ex:123", "testnet", deactivate.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "discover error")
	})

	t.Run("test failed to get sidetree config", func(t *testing.T) {
		v := New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return nil, fmt.Errorf("failed to get sidetree config")
			}}

		err = v.DeactivateDID("did:ex:123", "testnet", deactivate.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get sidetree config")
	})

	t.Run("test unsupported signing key", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		err := v.DeactivateDID("did:ex:123", "testnet", deactivate.WithSigningKey("www"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported")
	})

	t.Run("test error from unique suffix", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("wrong", "testnet", deactivate.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unique suffix not provided in id")
	})

	t.Run("test error from send request", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v := New(WithAuthToken("tk1"))

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123", "testnet", deactivate.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send deactivate sidetree request")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer serv.Close()

		v := New(WithAuthToken("tk1"))

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(pubKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.DeactivateDID("did:ex:123", "",
			deactivate.WithSigningKey(privKey), deactivate.WithRevealValue(rv),
			deactivate.WithSidetreeEndpoint(serv.URL), deactivate.WithSigningKeyID("k1"))
		require.NoError(t, err)

		// deactivate did without reveal value (issue-246)
		err = v.DeactivateDID("did:ex:123", "",
			deactivate.WithSigningKey(privKey),
			deactivate.WithSidetreeEndpoint(serv.URL), deactivate.WithSigningKeyID("k1"))
		require.NoError(t, err)
	})
}

func TestClient_RecoverDID(t *testing.T) {
	t.Run("test domain is empty", func(t *testing.T) {
		v := New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", "", recovery.WithNextUpdatePublicKey(pubKey),
			recovery.WithNextRecoveryPublicKey(pubKey), recovery.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "domain is empty")
	})

	t.Run("test failed to get sidetree config", func(t *testing.T) {
		v := New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return nil, fmt.Errorf("failed to get sidetree config")
			}}

		err = v.RecoverDID("did:ex:123", "testnet", recovery.WithNextUpdatePublicKey(pubKey),
			recovery.WithNextRecoveryPublicKey(pubKey), recovery.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get sidetree config")
	})

	t.Run("test next recovery key empty", func(t *testing.T) {
		v := New()

		err := v.RecoverDID("did:ex:123", "testnet")
		require.Error(t, err)
		require.Contains(t, err.Error(), "next recovery public key is required")
	})

	t.Run("test next update key empty", func(t *testing.T) {
		v := New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", "testnet", recovery.WithNextRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "next update public key is required")
	})

	t.Run("test signing key empty", func(t *testing.T) {
		v := New()

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", "testnet", recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "signing key is required")
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v.endpointService = endpoint.NewService(
			discoveryMock([]*models.Endpoint{}, fmt.Errorf("discover error")),
			selectionMock([]*models.Endpoint{}, nil))

		err = v.RecoverDID("did:ex:123", "testnet", recovery.WithNextUpdatePublicKey(pubKey),
			recovery.WithNextRecoveryPublicKey(pubKey), recovery.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "discover error")
	})

	t.Run("test failed to get next recovery key", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", "testnet", recovery.WithSigningKey(privKey),
			recovery.WithNextRecoveryPublicKey([]byte("wrong")), recovery.WithNextUpdatePublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next recovery key")
	})

	t.Run("test failed to get next update key", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", "testnet", recovery.WithSigningKey(privKey),
			recovery.WithNextUpdatePublicKey([]byte("wrong")), recovery.WithNextRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next update key")
	})

	t.Run("test unsupported signing key", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", "testnet", recovery.WithSigningKey("www"),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithNextRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported")
	})

	t.Run("test error from unique suffix", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("wrong", "testnet", recovery.WithSigningKey(privKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithNextRecoveryPublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unique suffix not provided in id")
	})

	t.Run("test error parse public key", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", "testnet", recovery.WithSigningKey(ecPrivKey),
			recovery.WithSigningKeyID("k1"), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{ID: "key3",
				Encoding: doc.PublicKeyEncodingJwk, KeyType: doc.Ed25519KeyType, Value: []byte(`{
          "kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"enc",
          "kid":"1"}`)}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported PublicKey source key type")
	})

	t.Run("test error from send request", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer serv.Close()

		v := New(WithAuthToken("tk1"))

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", "",
			recovery.WithSidetreeEndpoint(serv.URL), recovery.WithSigningKey(ecPrivKey),
			recovery.WithSigningKeyID("k1"), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{ID: "key3",
				Encoding: doc.PublicKeyEncodingJwk, KeyType: doc.Ed25519KeyType, Value: pubKey}),
			recovery.WithService(&did.Service{ID: "svc3"}))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to send recover sidetree request")
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

		v := New(WithAuthToken("tk1"))

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(&signingKey.PublicKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.RecoverDID("did:ex:123", "", recovery.WithSidetreeEndpoint(serv.URL),
			recovery.WithSigningKey(signingKey), recovery.WithRevealValue(rv),
			recovery.WithSigningKeyID("k1"), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{ID: "key3",
				Encoding: doc.PublicKeyEncodingJwk, KeyType: doc.Ed25519KeyType, Value: pubKey}),
			recovery.WithService(&did.Service{ID: "svc3"}))
		require.NoError(t, err)

		// update did without reveal value (issue-246)
		err = v.RecoverDID("did:ex:123", "", recovery.WithSidetreeEndpoint(serv.URL),
			recovery.WithSigningKey(signingKey),
			recovery.WithSigningKeyID("k1"), recovery.WithNextRecoveryPublicKey(pubKey),
			recovery.WithNextUpdatePublicKey(pubKey), recovery.WithPublicKey(&doc.PublicKey{ID: "key3",
				Encoding: doc.PublicKeyEncodingJwk, KeyType: doc.Ed25519KeyType, Value: pubKey}),
			recovery.WithService(&did.Service{ID: "svc3"}))
		require.NoError(t, err)
	})
}

func TestClient_UpdateDID(t *testing.T) {
	t.Run("test domain is empty", func(t *testing.T) {
		v := New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", "", update.WithNextUpdatePublicKey(pubKey),
			update.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "domain is empty")
	})

	t.Run("test failed to get sidetree config", func(t *testing.T) {
		v := New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return nil, fmt.Errorf("failed to get sidetree config")
			}}

		err = v.UpdateDID("did:ex:123", "testnet", update.WithNextUpdatePublicKey(pubKey),
			update.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get sidetree config")
	})

	t.Run("test signing key empty", func(t *testing.T) {
		v := New()

		err := v.UpdateDID("did:ex:123", "testnet")
		require.Error(t, err)
		require.Contains(t, err.Error(), "signing public key is required")
	})

	t.Run("test next updates key empty", func(t *testing.T) {
		v := New()

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", "testnet", update.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "next update public key is required")
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := New()

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		v.endpointService = endpoint.NewService(
			discoveryMock([]*models.Endpoint{}, fmt.Errorf("discover error")),
			selectionMock([]*models.Endpoint{}, nil))

		err = v.UpdateDID("did:ex:123", "testnet", update.WithNextUpdatePublicKey(pubKey),
			update.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "discover error")

		v.endpointService = endpoint.NewService(
			discoveryMock(nil, nil),
			selectionMock(nil, fmt.Errorf("select error")))

		err = v.UpdateDID("did:ex:123", "testnet", update.WithNextUpdatePublicKey(pubKey),
			update.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "select error")

		v.endpointService = endpoint.NewService(
			discoveryMock(nil, nil),
			selectionMock(nil, nil))

		err = v.UpdateDID("did:ex:123", "testnet", update.WithNextUpdatePublicKey(pubKey),
			update.WithSigningKey(privKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "list of endpoints is empty")
	})

	t.Run("test failed to get next update key", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", "testnet", update.WithSigningKey(privKey),
			update.WithNextUpdatePublicKey([]byte("wrong")))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get next update key")
	})

	t.Run("test unsupported signing key", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", "testnet", update.WithSigningKey("www"),
			update.WithNextUpdatePublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported")
	})

	t.Run("test error from unique suffix", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		err = v.UpdateDID("wrong", "testnet", update.WithSigningKey(privKey),
			update.WithNextUpdatePublicKey(pubKey))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unique suffix not provided in id")
	})

	t.Run("test success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer serv.Close()

		v := New(WithAuthToken("tk1"))

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: serv.URL}}, nil
			}}

		v.configService = &mockconfig.MockConfigService{
			GetSidetreeConfigFunc: func(s string) (*models.SidetreeConfig, error) {
				return &models.SidetreeConfig{MultiHashAlgorithm: 18}, nil
			}}

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		signingPubKeyJWK, err := pubkey.GetPublicKeyJWK(&signingKey.PublicKey)
		require.NoError(t, err)

		rv, err := commitment.GetRevealValue(signingPubKeyJWK, 18)
		require.NoError(t, err)

		err = v.UpdateDID("did:ex:123", "",
			update.WithSidetreeEndpoint(serv.URL), update.WithSigningKey(signingKey), update.WithRevealValue(rv),
			update.WithNextUpdatePublicKey(pubKey), update.WithRemoveService("svc1"),
			update.WithRemoveService("svc1"), update.WithRemovePublicKey("k1"),
			update.WithRemovePublicKey("k2"), update.WithAddPublicKey(&doc.PublicKey{ID: "key3",
				Encoding: doc.PublicKeyEncodingJwk, KeyType: doc.Ed25519KeyType, Value: pubKey}),
			update.WithAddService(&did.Service{ID: "svc3"}))
		require.NoError(t, err)

		// update did without reveal value (issue-246)
		err = v.UpdateDID("did:ex:123", "",
			update.WithSidetreeEndpoint(serv.URL), update.WithSigningKey(signingKey),
			update.WithNextUpdatePublicKey(pubKey), update.WithRemoveService("svc1"),
			update.WithRemoveService("svc1"), update.WithRemovePublicKey("k1"),
			update.WithRemovePublicKey("k2"), update.WithAddPublicKey(&doc.PublicKey{ID: "key3",
				Encoding: doc.PublicKeyEncodingJwk, KeyType: doc.Ed25519KeyType, Value: pubKey}),
			update.WithAddService(&did.Service{ID: "svc3"}))
		require.NoError(t, err)
	})
}

func Test_unwrapPubKeyJWK(t *testing.T) {
	t.Run("no wrapping", func(t *testing.T) {
		key := doc.PublicKey{Value: []byte("abcd")}
		key2, err := unwrapPubKeyJWK(key)
		require.NoError(t, err)
		require.Contains(t, string(key2.Value), "abcd")
	})

	t.Run("unwrap wrapped jwk", func(t *testing.T) {
		key := doc.PublicKey{Value: []byte(`{
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
		key := doc.PublicKey{Value: []byte(`{
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

func Test_defaultRevealValue(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rv := defaultRevealValue(&jws.JWK{}, 18)
		require.NotEmpty(t, rv)
	})
	t.Run("error - invalid multihash code", func(t *testing.T) {
		rv := defaultRevealValue(&jws.JWK{}, 55)
		require.Empty(t, rv)
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
