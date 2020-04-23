/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package models_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	mockmodels "github.com/trustbloc/trustbloc-did-method/pkg/internal/mock/models"
	. "github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// nolint: gochecknoglobals
var payload = `
{
	"domain": "foo.bar",
	"policy": {
		"cache": {"max_age": 123456789}
	},
	"members": [
		{
			"domain": "bar.baz",
			"did": "did:trustbloc:foo.bar:zQ1234567890987654321"
		},
		{
			"domain": "baz.qux",
			"did": "did:trustbloc:foo.bar:zQ0987654321234567890"
		}
	],
	"previous": ""
}
`

func Test_ParseConsortium(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		jws := mockmodels.DummyJWSWrap(payload)

		cData, err := ParseConsortium([]byte(jws))
		require.NoError(t, err)

		require.Equal(t, "foo.bar", cData.Config.Domain)
		require.Equal(t, payload, string(cData.JWS.UnsafePayloadWithoutVerification()))
	})

	t.Run("failure: not valid JSON", func(t *testing.T) {
		jws := `{`

		_, err := ParseConsortium([]byte(jws))
		require.Error(t, err)
		require.Contains(t, err.Error(), "config data should be a JWS")
	})

	t.Run("failure: not a JWS", func(t *testing.T) {
		jws := `{"foo":"bar"}`

		_, err := ParseConsortium([]byte(jws))
		require.Error(t, err)
		require.Contains(t, err.Error(), "config data should be a JWS")
	})

	t.Run("failure: malformed payload", func(t *testing.T) {
		jws := mockmodels.DummyJWSWrap(`@@bad data@@`)

		_, err := ParseConsortium([]byte(jws))
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})
}
