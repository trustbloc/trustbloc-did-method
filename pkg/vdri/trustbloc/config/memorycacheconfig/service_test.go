/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package memorycacheconfig

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	mockconfig "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/config"
	mockmodels "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/models"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

func TestConfigService_GetConsortium(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		consortiumData := mockmodels.DummyConsortium("foo.bar", []models.StakeholderListElement{
			{
				Domain: "bar.baz",
			},
			{
				Domain: "baz.qux",
			},
		})
		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{Config: consortiumData}, nil
			}})

		conf, err := cs.GetConsortium("foo.bar", "foo.bar")
		require.NoError(t, err)

		require.Equal(t, "foo.bar", conf.Config.Domain)
	})

	t.Run("success - demonstrate caching", func(t *testing.T) {
		consortiumData := mockmodels.DummyConsortium("foo.bar", []models.StakeholderListElement{
			{
				Domain: "bar.baz",
			},
			{
				Domain: "baz.qux",
			},
		})

		// Note: this test will fail if it takes more than 1000 seconds, meaning the cache stales
		consortiumData.Policy.Cache.MaxAge = 1000

		callCount := 0

		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				callCount++
				if callCount > 1 {
					return nil, fmt.Errorf("double-call")
				}

				return &models.ConsortiumFileData{Config: consortiumData}, nil
			}})

		// Call multiple times, which should fail if the wrapped service is called multiple times
		// indicating that there's no caching
		for i := 0; i < 5; i++ {
			conf, err := cs.GetConsortium("foo.bar", "foo.bar")
			require.NoError(t, err)

			require.Equal(t, "foo.bar", conf.Config.Domain)
		}
	})

	t.Run("success - re-call wrapped service when cache times out", func(t *testing.T) {
		consortiumData := mockmodels.DummyConsortium("foo.bar", []models.StakeholderListElement{
			{
				Domain: "bar.baz",
			},
			{
				Domain: "baz.qux",
			},
		})

		consortiumData.Policy.Cache.MaxAge = 0

		callCount := 0

		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				callCount++
				if callCount > 1 {
					return nil, fmt.Errorf("double-call")
				}

				return &models.ConsortiumFileData{Config: consortiumData}, nil
			}})

		// Call multiple times, which should fail if the wrapped service is called multiple times
		// indicating that there's no caching
		conf, err := cs.GetConsortium("foo.bar", "foo.bar")
		require.NoError(t, err)

		require.Equal(t, "foo.bar", conf.Config.Domain)

		_, err = cs.GetConsortium("foo.bar", "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "double-call")
	})

	t.Run("failure - nil pointer", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetConsortiumFunc: func(u string, d string) (*models.ConsortiumFileData, error) {
				return &models.ConsortiumFileData{Config: nil}, nil
			}})

		_, err := cs.GetConsortium("foo.bar", "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "nil")
	})
}

func TestConfigService_GetStakeholder(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		stakeholder := mockmodels.DummyStakeholder("foo.bar", []string{
			"endpoint.website/go/here/",
			"endpoint.website/here/too/",
		})

		cs := NewService(&mockconfig.MockConfigService{
			GetStakeholderFunc: func(u string, d string) (*models.StakeholderFileData, error) {
				return &models.StakeholderFileData{Config: stakeholder}, nil
			}})

		conf, err := cs.GetStakeholder("foo.bar", "foo.bar")
		require.NoError(t, err)

		require.Equal(t, "foo.bar", conf.Config.Domain)
	})

	t.Run("success - demonstrate caching", func(t *testing.T) {
		stakeholder := mockmodels.DummyStakeholder("foo.bar", []string{"foo", "bar"})

		// Note: this test will fail if it takes more than 1000 seconds, meaning the cache stales
		stakeholder.Policy.Cache.MaxAge = 1000

		callCount := 0

		cs := NewService(&mockconfig.MockConfigService{
			GetStakeholderFunc: func(u string, d string) (*models.StakeholderFileData, error) {
				callCount++
				if callCount > 1 {
					return nil, fmt.Errorf("double-call")
				}

				return &models.StakeholderFileData{Config: stakeholder}, nil
			}})

		// Call multiple times, which should fail if the wrapped service is called multiple times
		// indicating that there's no caching
		for i := 0; i < 5; i++ {
			conf, err := cs.GetStakeholder("foo.bar", "foo.bar")
			require.NoError(t, err)

			require.Equal(t, "foo.bar", conf.Config.Domain)
		}
	})

	t.Run("success - re-call wrapped service when cache times out", func(t *testing.T) {
		stakeholder := mockmodels.DummyStakeholder("foo.bar", []string{"foo", "bar"})

		stakeholder.Policy.Cache.MaxAge = 0

		callCount := 0

		cs := NewService(&mockconfig.MockConfigService{
			GetStakeholderFunc: func(u string, d string) (*models.StakeholderFileData, error) {
				callCount++
				if callCount > 1 {
					return nil, fmt.Errorf("double-call")
				}

				return &models.StakeholderFileData{Config: stakeholder}, nil
			}})

		// Call multiple times, which should fail if the wrapped service is called multiple times
		// indicating that there's no caching
		conf, err := cs.GetStakeholder("foo.bar", "foo.bar")
		require.NoError(t, err)

		require.Equal(t, "foo.bar", conf.Config.Domain)

		_, err = cs.GetStakeholder("foo.bar", "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "double-call")
	})

	t.Run("failure - nil pointer", func(t *testing.T) {
		cs := NewService(&mockconfig.MockConfigService{
			GetStakeholderFunc: func(u string, d string) (*models.StakeholderFileData, error) {
				return &models.StakeholderFileData{Config: nil}, nil
			}})

		_, err := cs.GetStakeholder("foo.bar", "foo.bar")
		require.Error(t, err)

		require.Contains(t, err.Error(), "nil")
	})
}
