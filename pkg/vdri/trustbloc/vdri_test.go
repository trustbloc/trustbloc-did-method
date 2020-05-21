/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package trustbloc

import (
	"crypto/tls"
	"fmt"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/stretchr/testify/require"

	mockendpoint "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/endpoint"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

func TestVDRI_Accept(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v := New()
		require.True(t, v.Accept("trustbloc"))
	})

	t.Run("test return false", func(t *testing.T) {
		v := New()
		require.False(t, v.Accept("bloc1"))
	})
}

func TestVDRI_Store(t *testing.T) {
	t.Run("test error", func(t *testing.T) {
		v := New()
		err := v.Store(nil, nil)
		require.NoError(t, err)
	})
}

func TestVDRI_Build(t *testing.T) {
	t.Run("test error", func(t *testing.T) {
		v := New()
		_, err := v.Build(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "build method not supported for did bloc")
	})
}

func TestVDRI_Read(t *testing.T) {
	t.Run("test error from get http vdri for resolver url", func(t *testing.T) {
		v := New(WithResolverURL("url"))

		_, err := v.getHTTPVDRI("")
		require.Error(t, err)
		require.Contains(t, err.Error(), "empty url")

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return nil, fmt.Errorf("get http vdri error")
		}

		doc, err := v.Read("did")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get http vdri error")
		require.Nil(t, doc)
	})

	t.Run("test error from http vdri build for resolver url", func(t *testing.T) {
		v := New(WithResolverURL("url"))

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return &mockvdri.MockVDRI{
				ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
					return nil, fmt.Errorf("read error")
				}}, nil
		}

		doc, err := v.Read("did")
		require.Error(t, err)
		require.Contains(t, err.Error(), "read error")
		require.Nil(t, doc)
	})

	t.Run("test success for resolver url", func(t *testing.T) {
		v := New(WithResolverURL("url"))

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return &mockvdri.MockVDRI{
				ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
					return &did.Doc{ID: "did"}, nil
				}}, nil
		}

		doc, err := v.Read("did")
		require.NoError(t, err)
		require.Equal(t, "did", doc.ID)
	})

	t.Run("test error parsing did", func(t *testing.T) {
		v := New()

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return nil, nil
		}

		doc, err := v.Read("did:1223")
		require.Error(t, err)
		require.Contains(t, err.Error(), "wrong did did:1223")
		require.Nil(t, doc)
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return nil, fmt.Errorf("discover error")
			}}

		doc, err := v.Read("did:trustbloc:testnet:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "discover error")
		require.Nil(t, doc)

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return nil, fmt.Errorf("select error")
			}}

		doc, err = v.Read("did:trustbloc:testnet:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "select error")
		require.Nil(t, doc)

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return nil, nil
			}}

		doc, err = v.Read("did:trustbloc:testnet:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "list of endpoints is empty")
		require.Nil(t, doc)
	})

	t.Run("test error from get http vdri", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return nil, fmt.Errorf("get http vdri error")
		}

		doc, err := v.Read("did:trustbloc:testnet:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get http vdri error")
		require.Nil(t, doc)
	})

	t.Run("test error from http vdri read", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}}, nil
			}}

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return &mockvdri.MockVDRI{
				ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
					return nil, fmt.Errorf("read error")
				}}, nil
		}

		doc, err := v.Read("did:trustbloc:testnet:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "read error")
		require.Nil(t, doc)
	})

	//nolint:gocritic
	// t.Run("test error from mismatch", func(t *testing.T) {
	// 	v := New()
	//
	// 	v.endpointService = &mockendpoint.MockEndpointService{
	// 		GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
	// 			return []*models.Endpoint{{URL: "url"}, {URL: "url.2"}}, nil
	// 		}}
	//
	// 	counter := 0
	//
	// 	v.getHTTPVDRI = func(url string) (v vdri, err error) {
	// 		return &mockvdri.MockVDRI{
	// 			ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
	// 				counter++
	// 				return generateDIDDoc("test:" + string(counter)), nil
	// 			}}, nil
	// 	}
	//
	// 	_, err := v.Read("did:trustbloc:testnet:123")
	// 	require.Error(t, err)
	// 	require.Contains(t, err.Error(), "mismatch")
	// })

	t.Run("test success", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}, {URL: "url.2"}}, nil
			}}

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return &mockvdri.MockVDRI{
				ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
					return &did.Doc{ID: "did:trustbloc:testnet:123"}, nil
				}}, nil
		}

		doc, err := v.Read("did:trustbloc:testnet:123")
		require.NoError(t, err)
		require.Equal(t, "did:trustbloc:testnet:123", doc.ID)
	})
}

func TestVDRI_Close(t *testing.T) {
	v := New()
	require.NoError(t, v.Close())
}

func Test_canonicalizeDoc(t *testing.T) {
	var docs = [][2]string{
		{`{
  "@context": ["https://w3id.org/did/v1"],
  "publicKey": [{
    "id": "did:example:123456789abcdefghi#keys-3",
    "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
    "type": "Secp256k1VerificationKey2018",
    "controller": "did:example:123456789abcdefghi"
  }],
  "id": "did:example:123456789abcdefghi",
  "authentication": [
    {
      "id": "did:example:123456789abcdefghi#keys-2",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    "did:example:123456789abcdefghi#keys-3"
  ],
  "service": [{
    "id": "did:example:123456789abcdefghi#oidc",
    "type": "OpenIdConnectVersion1.0Service",
    "serviceEndpoint": "https://openid.example.com/"
  }, {
    "id": "did:example:123456789abcdefghi#messaging",
    "type": "MessagingService",
    "serviceEndpoint": "https://example.com/messages/8377464"
  }, {
    "id": "did:example:123456789abcdefghi#vcStore",
    "type": "CredentialRepositoryService",
    "serviceEndpoint": "https://repository.example.com/service/8377464"
  }, {
    "id": "did:example:123456789abcdefghi#xdi",
    "serviceEndpoint": "https://xdi.example.com/8377464",
    "type": "XdiService"
  }, {
    "type": "HubService",
    "id": "did:example:123456789abcdefghi#hub",
    "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/"
  }, {
    "id": "did:example:123456789abcdefghi#inbox",
    "description": "My public social inbox",
    "type": "SocialWebInboxService",
    "serviceEndpoint": "https://social.example.com/83hfh37dj",
    "spamCost": {
      "amount": "0.50",
      "currency": "USD"
    }
  }]
}`,
			`{
  "@context": ["https://w3id.org/did/v1"],
  "publicKey": [{
    "id": "did:example:123456789abcdefghi#keys-3",
    "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
    "type": "Secp256k1VerificationKey2018",
    "controller": "did:example:123456789abcdefghi"
  }],
  "id": "did:example:123456789abcdefghi",
  "authentication": [
    {
      "id": "did:example:123456789abcdefghi#keys-2",
      "type": "Ed25519VerificationKey2018",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
    },
    "did:example:123456789abcdefghi#keys-3"
  ],
  "service": [{
    "id": "did:example:123456789abcdefghi#messaging",
    "type": "MessagingService",
    "serviceEndpoint": "https://example.com/messages/8377464"
  }, {
    "id": "did:example:123456789abcdefghi#oidc",
    "type": "OpenIdConnectVersion1.0Service",
    "serviceEndpoint": "https://openid.example.com/"
  }, {
    "id": "did:example:123456789abcdefghi#vcStore",
    "type": "CredentialRepositoryService",
    "serviceEndpoint": "https://repository.example.com/service/8377464"
  }, {
    "id": "did:example:123456789abcdefghi#xdi",
    "serviceEndpoint": "https://xdi.example.com/8377464",
    "type": "XdiService"
  }, {
    "type": "HubService",
    "id": "did:example:123456789abcdefghi#hub",
    "serviceEndpoint": "https://hub.example.com/.identity/did:example:0123456789abcdef/"
  }, {
    "id": "did:example:123456789abcdefghi#inbox",
    "description": "My public social inbox",
    "type": "SocialWebInboxService",
    "serviceEndpoint": "https://social.example.com/83hfh37dj",
    "spamCost": {
      "amount": "0.50",
      "currency": "USD"
    }
  }]
}`},
		{`{
  "@context": ["https://w3id.org/did/v1"],
  "publicKey": [{
    "id": "did:example:123456789abcdefghi#keys-3",
    "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
    "type": "Secp256k1VerificationKey2018",
    "controller": "did:example:123456789abcdefghi"
  }],
  "id": "did:example:123456789abcdefghi",
  "authentication": [
    {
      "id": "did:example:123456789abcdefghi#keys-2",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyJwk":{
        "kty":"OKP",
        "crv":"Ed25519",
        "x":"60-uLNeLPAT-gaV_7_9_g330m0aLRlqk-LEnQvz2lv0"
      },
      "type":"JwsVerificationKey2020"
    },
    "did:example:123456789abcdefghi#keys-3"
  ],
  "service": [{
    "id": "did:example:123456789abcdefghi#oidc",
    "type": "OpenIdConnectVersion1.0Service",
    "serviceEndpoint": "https://openid.example.com/"
  }, {
    "id": "did:example:123456789abcdefghi#messaging",
    "type": "MessagingService",
    "serviceEndpoint": "https://example.com/messages/8377464"
  }]
}`,
			`{
  "service": [ {
    "type": "MessagingService",
    "serviceEndpoint": "https://example.com/messages/8377464",
    "id": "did:example:123456789abcdefghi#messaging"
  }, {
    "id": "did:example:123456789abcdefghi#oidc",
    "serviceEndpoint": "https://openid.example.com/",
    "type": "OpenIdConnectVersion1.0Service"
  }],
  "id": "did:example:123456789abcdefghi",
  "authentication": [
    {
      "id": "did:example:123456789abcdefghi#keys-2",
      "type":"JwsVerificationKey2020",
      "controller": "did:example:123456789abcdefghi",
      "publicKeyJwk":{
        "crv":"Ed25519",
        "x":"60-uLNeLPAT-gaV_7_9_g330m0aLRlqk-LEnQvz2lv0",
        "kty":"OKP"
      }
    },
    "did:example:123456789abcdefghi#keys-3"
  ],
  "@context": ["https://w3id.org/did/v1"],
  "publicKey": [{
    "id": "did:example:123456789abcdefghi#keys-3",
    "publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV",
    "type": "Secp256k1VerificationKey2018",
    "controller": "did:example:123456789abcdefghi"
  }]
}`},
	}

	_ = `{
		"controller":"did:trustbloc:testnet.trustbloc.local:EiDDTwzrFVAmnsPG8D10MNJ-Ga5OH_KsNX8uLGmirWXP-g",
		"id":"did:trustbloc:testnet.trustbloc.local:EiDDTwzrFVAmnsPG8D10MNJ-Ga5OH_KsNX8uLGmirWXP-g#key-1",
		"publicKeyJwk":{
			"kty":"OKP",
			"crv":"Ed25519",
			"x":"60-uLNeLPAT-gaV_7_9_g330m0aLRlqk-LEnQvz2lv0"
		},
		"type":"JwsVerificationKey2020"
	}`

	t.Run("test canonicalization of equal docs", func(t *testing.T) {
		for _, pair := range docs {
			doc1, err := did.ParseDocument([]byte(pair[0]))
			require.NoError(t, err)
			doc2, err := did.ParseDocument([]byte(pair[1]))
			require.NoError(t, err)

			doc1Canonicalized, err := canonicalizeDoc(doc1)
			require.NoError(t, err)
			doc2Canonicalized, err := canonicalizeDoc(doc2)
			require.NoError(t, err)

			require.Equal(t, doc1Canonicalized, doc2Canonicalized)
		}
	})
}

func TestOpts(t *testing.T) {
	t.Run("test opts", func(t *testing.T) {
		// test WithTLSConfig
		var opts []Option
		opts = append(opts, WithTLSConfig(&tls.Config{ServerName: "test"}), WithAuthToken("tk1"))

		v := &VDRI{}

		// Apply options
		for _, opt := range opts {
			opt(v)
		}

		require.Equal(t, "test", v.tlsConfig.ServerName)
		require.Equal(t, "tk1", v.authToken)
	})
}

//nolint:deadcode,unused
func generateDIDDoc(id string) *did.Doc {
	t := time.Unix(0, 0)

	return &did.Doc{
		Context: nil,
		ID:      id,
		PublicKey: []did.PublicKey{{
			ID:         "",
			Type:       "",
			Controller: "",
			Value:      []byte{0},
		}},
		Service: []did.Service{{
			ID:              "",
			Type:            "",
			Priority:        0,
			RecipientKeys:   []string{""},
			RoutingKeys:     []string{""},
			ServiceEndpoint: "",
			Properties:      map[string]interface{}{},
		}},
		Authentication: []did.VerificationMethod{{PublicKey: did.PublicKey{
			ID:         "",
			Type:       "",
			Controller: "",
			Value:      []byte{0},
		}}},
		Created: nil,
		Updated: nil,
		Proof: []did.Proof{{
			Type:       "",
			Created:    &t,
			Creator:    "",
			ProofValue: nil,
			Domain:     "",
			Nonce:      nil,
		}},
	}
}
