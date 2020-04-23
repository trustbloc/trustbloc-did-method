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

	t.Run("test error from mismatch", func(t *testing.T) {
		v := New()

		v.endpointService = &mockendpoint.MockEndpointService{
			GetEndpointsFunc: func(domain string) (endpoints []*models.Endpoint, err error) {
				return []*models.Endpoint{{URL: "url"}, {URL: "url.2"}}, nil
			}}

		counter := 0

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return &mockvdri.MockVDRI{
				ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
					counter++
					return generateDIDDoc("test:" + string(counter)), nil
				}}, nil
		}

		_, err := v.Read("did:trustbloc:testnet:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "mismatch")
	})

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

func TestOpts(t *testing.T) {
	t.Run("test opts", func(t *testing.T) {
		// test WithTLSConfig
		var opts []Option
		opts = append(opts, WithTLSConfig(&tls.Config{ServerName: "test"}))

		v := &VDRI{}

		// Apply options
		for _, opt := range opts {
			opt(v)
		}

		require.Equal(t, "test", v.tlsConfig.ServerName)
	})
}

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
