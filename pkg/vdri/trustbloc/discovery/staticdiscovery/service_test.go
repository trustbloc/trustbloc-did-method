/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package staticdiscovery

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	mockmodels "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/models"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/httpconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

func TestDiscoveryService_GetEndpoints(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		shData1, err := mockmodels.DummyStakeholderJSON("bar.baz", []string{
			"https://bar.baz/webapi/123456", "https://bar.baz/webapi/654321"})
		require.NoError(t, err)

		shFile1 := mockmodels.DummyJWSWrap(shData1)
		stakeholderServ1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, shFile1)
		}))
		defer stakeholderServ1.Close()

		shData2, err := mockmodels.DummyStakeholderJSON("baz.qux", []string{
			"https://baz.qux/iyoubhlkn/", "https://baz.foo/ukjhjtfyw/"})
		require.NoError(t, err)

		shFile2 := mockmodels.DummyJWSWrap(shData2)
		stakeholderServ2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, shFile2)
		}))
		defer stakeholderServ2.Close()

		consortiumData, err := mockmodels.DummyConsortiumJSON("foo.bar", []models.StakeholderListElement{
			{
				Domain: stakeholderServ1.URL,
			},
			{
				Domain: stakeholderServ2.URL,
			},
		})
		require.NoError(t, err)

		consFile := mockmodels.DummyJWSWrap(consortiumData)
		consortiumServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consFile)
		}))
		defer stakeholderServ2.Close()

		s := NewService(httpconfig.NewService(httpconfig.WithTLSConfig(&tls.Config{})))
		endpoints, err := s.GetEndpoints(consortiumServ.URL)
		require.NoError(t, err)
		require.Len(t, endpoints, 4)
	})

	t.Run("failure: stakeholder server failure", func(t *testing.T) {
		stakeholderServ := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(500)
		}))
		defer stakeholderServ.Close()

		consortiumData, err := mockmodels.DummyConsortiumJSON("foo.bar", []models.StakeholderListElement{
			{
				Domain: stakeholderServ.URL,
			},
		})
		require.NoError(t, err)

		consortiumFile := mockmodels.DummyJWSWrap(consortiumData)
		consortiumServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, consortiumFile)
		}))
		defer consortiumServer.Close()

		s := NewService(httpconfig.NewService(httpconfig.WithTLSConfig(&tls.Config{})))
		_, err = s.GetEndpoints(consortiumServer.URL)
		require.Error(t, err)
		require.Contains(t, err.Error(), "stakeholder config request failed")
	})
}
