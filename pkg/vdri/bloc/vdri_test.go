/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package bloc

import (
	"fmt"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	mockvdri "github.com/hyperledger/aries-framework-go/pkg/mock/vdri"
	"github.com/stretchr/testify/require"

	mockdiscovery "github.com/trustbloc/bloc-did-method/pkg/internal/mock/discovery"
	mockselection "github.com/trustbloc/bloc-did-method/pkg/internal/mock/selection"
	"github.com/trustbloc/bloc-did-method/pkg/vdri/bloc/endpoint"
)

func TestVDRI_Accept(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		v := New()
		require.True(t, v.Accept("bloc"))
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
	t.Run("test domain is empty", func(t *testing.T) {
		v := New()

		doc, err := v.Build(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "domain is empty")
		require.Nil(t, doc)
	})

	t.Run("test error from get endpoints", func(t *testing.T) {
		v := New(WithDomain("testnet"))

		v.discovery = &mockdiscovery.MockDiscoveryService{
			GetEndpointsFunc: func(domain string) (endpoints []*endpoint.Endpoint, err error) {
				return nil, fmt.Errorf("discover error")
			}}

		doc, err := v.Build(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "discover error")
		require.Nil(t, doc)

		v.discovery = &mockdiscovery.MockDiscoveryService{
			GetEndpointsFunc: func(domain string) (endpoints []*endpoint.Endpoint, err error) {
				return nil, nil
			}}
		v.selection = &mockselection.MockSelectionService{
			SelectEndpointsFunc: func(endpoint []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
				return nil, fmt.Errorf("select error")
			}}

		doc, err = v.Build(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "select error")
		require.Nil(t, doc)

		v.selection = &mockselection.MockSelectionService{
			SelectEndpointsFunc: func(endpoint []*endpoint.Endpoint) ([]*endpoint.Endpoint, error) {
				return nil, nil
			}}

		doc, err = v.Build(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "list of endpoints is empty")
		require.Nil(t, doc)
	})

	t.Run("test error from get http vdri", func(t *testing.T) {
		v := New(WithDomain("testnet"))

		v.discovery = &mockdiscovery.MockDiscoveryService{
			GetEndpointsFunc: func(domain string) (endpoints []*endpoint.Endpoint, err error) {
				return []*endpoint.Endpoint{{URL: "url"}}, nil
			}}

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return nil, fmt.Errorf("get http vdri error")
		}

		doc, err := v.Build(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "get http vdri error")
		require.Nil(t, doc)
	})

	t.Run("test error from http vdri build", func(t *testing.T) {
		v := New(WithDomain("testnet"))

		v.discovery = &mockdiscovery.MockDiscoveryService{
			GetEndpointsFunc: func(domain string) (endpoints []*endpoint.Endpoint, err error) {
				return []*endpoint.Endpoint{{URL: "url"}}, nil
			}}

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return &mockvdri.MockVDRI{
				BuildFunc: func(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (doc *did.Doc, err error) {
					return nil, fmt.Errorf("build error")
				}}, nil
		}

		doc, err := v.Build(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "build error")
		require.Nil(t, doc)
	})

	t.Run("test success", func(t *testing.T) {
		v := New(WithDomain("testnet"))

		v.discovery = &mockdiscovery.MockDiscoveryService{
			GetEndpointsFunc: func(domain string) (endpoints []*endpoint.Endpoint, err error) {
				return []*endpoint.Endpoint{{URL: "url"}}, nil
			}}

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return &mockvdri.MockVDRI{
				BuildFunc: func(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (doc *did.Doc, err error) {
					return &did.Doc{ID: "did"}, nil
				}}, nil
		}

		doc, err := v.Build(nil)
		require.NoError(t, err)
		require.Equal(t, "did", doc.ID)
	})
}

func TestVDRI_Read(t *testing.T) {
	t.Run("test error from get http vdri for resolver url", func(t *testing.T) {
		v := New(WithResolverURL("url"))

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

		v.discovery = &mockdiscovery.MockDiscoveryService{
			GetEndpointsFunc: func(domain string) (endpoints []*endpoint.Endpoint, err error) {
				return nil, fmt.Errorf("discover error")
			}}

		doc, err := v.Read("did:bloc:testnet:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "discover error")
		require.Nil(t, doc)
	})

	t.Run("test error from get http vdri", func(t *testing.T) {
		v := New()

		v.discovery = &mockdiscovery.MockDiscoveryService{
			GetEndpointsFunc: func(domain string) (endpoints []*endpoint.Endpoint, err error) {
				return []*endpoint.Endpoint{{URL: "url"}}, nil
			}}

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return nil, fmt.Errorf("get http vdri error")
		}

		doc, err := v.Read("did:bloc:testnet:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "get http vdri error")
		require.Nil(t, doc)
	})

	t.Run("test error from http vdri read", func(t *testing.T) {
		v := New()

		v.discovery = &mockdiscovery.MockDiscoveryService{
			GetEndpointsFunc: func(domain string) (endpoints []*endpoint.Endpoint, err error) {
				return []*endpoint.Endpoint{{URL: "url"}}, nil
			}}

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return &mockvdri.MockVDRI{
				ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
					return nil, fmt.Errorf("read error")
				}}, nil
		}

		doc, err := v.Read("did:bloc:testnet:123")
		require.Error(t, err)
		require.Contains(t, err.Error(), "read error")
		require.Nil(t, doc)
	})

	t.Run("test success", func(t *testing.T) {
		v := New()

		v.discovery = &mockdiscovery.MockDiscoveryService{
			GetEndpointsFunc: func(domain string) (endpoints []*endpoint.Endpoint, err error) {
				return []*endpoint.Endpoint{{URL: "url"}}, nil
			}}

		v.getHTTPVDRI = func(url string) (v vdri, err error) {
			return &mockvdri.MockVDRI{
				ReadFunc: func(didID string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
					return &did.Doc{ID: "did:bloc:testnet:123"}, nil
				}}, nil
		}

		doc, err := v.Read("did:bloc:testnet:123")
		require.NoError(t, err)
		require.Equal(t, "did:bloc:testnet:123", doc.ID)
	})
}

func TestVDRI_BuildSideTreeRequest(t *testing.T) {
	t.Run("test success", func(t *testing.T) {
		r, err := buildSideTreeRequest([]byte("doc"))
		require.NoError(t, err)
		require.NotNil(t, r)
	})
}

func TestVDRI_Close(t *testing.T) {
	v := New()
	require.NoError(t, v.Close())
}
