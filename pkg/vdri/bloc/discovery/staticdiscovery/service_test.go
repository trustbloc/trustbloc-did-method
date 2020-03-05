/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package staticdiscovery

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/trustbloc/bloc-did-method/pkg/vdri/bloc/config"
)

func TestDiscoveryService_GetEndpoints(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		shData1, err := dummyStakeholderConfig("bar.baz", []string{
			"https://bar.baz/webapi/123456", "https://bar.baz/webapi/654321"})
		require.NoError(t, err)

		shFile1 := dummyJWSWrap(shData1)
		stakeholderServ1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, shFile1)
		}))
		defer stakeholderServ1.Close()

		shData2, err := dummyStakeholderConfig("baz.qux", []string{
			"https://baz.qux/iyoubhlkn/", "https://baz.foo/ukjhjtfyw/"})
		require.NoError(t, err)

		shFile2 := dummyJWSWrap(shData2)
		stakeholderServ2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, shFile2)
		}))
		defer stakeholderServ2.Close()

		consortiumData, err := dummyConsortiumConfig("foo.bar", []config.StakeholderListElement{
			{
				Domain: stakeholderServ1.URL,
			},
			{
				Domain: stakeholderServ2.URL,
			},
		})
		require.NoError(t, err)

		consortiumFile := dummyJWSWrap(consortiumData)

		consortiumServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer consortiumServ.Close()

		s := NewService()
		endpoints, err := s.GetEndpoints(consortiumServ.URL)
		require.NoError(t, err)
		require.Len(t, endpoints, 4)
		require.Equal(t, "https://bar.baz/webapi/123456", endpoints[0].URL)
	})

	t.Run("failure: consortium server failure", func(t *testing.T) {
		consortiumServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
		}))
		defer consortiumServ.Close()

		s := NewService()
		_, err := s.GetEndpoints(consortiumServ.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "error 500")
	})

	t.Run("failure: stakeholder server failure", func(t *testing.T) {
		stakeholderServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
		}))
		defer stakeholderServ.Close()

		consortiumData, err := dummyConsortiumConfig("foo.bar", []config.StakeholderListElement{
			{
				Domain: stakeholderServ.URL,
			},
		})
		require.NoError(t, err)

		consortiumFile := dummyJWSWrap(consortiumData)

		consortiumServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer consortiumServ.Close()

		s := NewService()
		_, err = s.GetEndpoints(consortiumServ.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "stakeholder config request failed")
	})
}

func TestDiscoveryService_getConsortiumData(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		consortiumData, err := dummyConsortiumConfig("foo.bar", []config.StakeholderListElement{
			{
				Domain: "bar.baz",
			},
			{
				Domain: "baz.qux",
			},
		})
		require.NoError(t, err)

		consortiumFile := dummyJWSWrap(consortiumData)

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer serv.Close()

		ds := NewService()

		conf, err := ds.getConsortium(serv.URL, "foo.bar")
		require.NoError(t, err)

		require.Equal(t, "foo.bar", conf.Config.Domain)
	})

	t.Run("failure: can't reach server", func(t *testing.T) {
		ds := NewService()

		_, err := ds.getConsortium("https://0.0.0.0:8080", "foo.bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection refused")
	})

	t.Run("failure: bad response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
		}))
		defer serv.Close()

		ds := NewService()

		_, err := ds.getConsortium(serv.URL, "foo.bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "consortium config request failed")
	})

	t.Run("failure: empty response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer serv.Close()

		ds := NewService()

		_, err := ds.getConsortium(serv.URL, "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "consortium config data should be a JWS")
	})
}

func TestDiscoveryService_getStakeholderData(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		stakeholderData, err := dummyStakeholderConfig("foo.bar", []string{
			"endpoint.website/go/here/",
			"endpoint.website/here/too/",
		})
		require.NoError(t, err)

		stakeholderFile := dummyJWSWrap(stakeholderData)

		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, stakeholderFile)
		}))
		defer serv.Close()

		ds := NewService()

		conf, err := ds.getStakeholder(serv.URL, "foo.bar")
		require.NoError(t, err)

		require.Equal(t, "foo.bar", conf.Config.Domain)
	})

	t.Run("failure: can't reach server", func(t *testing.T) {
		ds := NewService()

		_, err := ds.getStakeholder("https://0.0.0.0:8080", "foo.bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "connection refused")
	})

	t.Run("failure: bad response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
		}))
		defer serv.Close()

		ds := NewService()

		_, err := ds.getStakeholder(serv.URL, "foo.bar")
		require.Error(t, err)
		require.Contains(t, err.Error(), "stakeholder config request failed")
	})

	t.Run("failure: empty response", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer serv.Close()

		ds := NewService()

		_, err := ds.getStakeholder(serv.URL, "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "stakeholder config data should be a JWS")
	})
}

func dummyJWSWrap(data string) string {
	dataB64 := base64.RawURLEncoding.EncodeToString([]byte(data))
	return `{"payload":"` + dataB64 + `","signatures":[{"header":{"kid":""}, "signature":""}]}`
}

func dummyConsortiumConfig(consortiumDomain string, stakeholders []config.StakeholderListElement) (string, error) {
	cc := config.Consortium{
		Domain:       consortiumDomain,
		Policy:       config.ConsortiumPolicy{Cache: config.CacheControl{MaxAge: 0}},
		Stakeholders: stakeholders,
		Previous:     "",
	}

	out, err := json.Marshal(cc)
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func dummyStakeholderConfig(stakeholderDomain string, endpoints []string) (string, error) {
	sc := config.Stakeholder{
		Domain:    stakeholderDomain,
		DID:       "",
		Config:    config.StakeholderSettings{Cache: config.CacheControl{MaxAge: 0}},
		Endpoints: endpoints,
		Previous:  "",
	}

	out, err := json.Marshal(sc)
	if err != nil {
		return "", err
	}

	return string(out), nil
}

func Test_configURL(t *testing.T) {
	tests := [][2]string{ // first element is the test value, second is the correct value
		{
			configURL("http://foo.example.com", "foo.example.com"),
			"http://foo.example.com/.well-known/did-bloc/foo.example.com.json",
		},
		{ // adds http:// to the front of a domain
			configURL("foo.example.com", "foo.example.com"),
			"http://foo.example.com/.well-known/did-bloc/foo.example.com.json",
		},
		{ // doesn't work with full URLs in the domain field
			configURL("foo.example.com", "http://foo.example.com"),
			"http://foo.example.com/.well-known/did-bloc/http://foo.example.com.json",
		},
		{
			configURL("http://foo.example.com", "bar.baz.qux"),
			"http://foo.example.com/.well-known/did-bloc/bar.baz.qux.json",
		},
		{
			configURL("a", "b"),
			"http://a/.well-known/did-bloc/b.json",
		},
		{ // doesn't recognize urls that aren't http:// or https://
			configURL("ws:abcdefg", "hijklmn"),
			"http://ws:abcdefg/.well-known/did-bloc/hijklmn.json",
		},
		{ // doesn't work well with malformed urls
			configURL("http:/abcdefg", "hijklmn"),
			"http://http:/abcdefg/.well-known/did-bloc/hijklmn.json",
		},
	}

	for _, test := range tests {
		require.Equal(t, test[1], test[0])
	}
}
