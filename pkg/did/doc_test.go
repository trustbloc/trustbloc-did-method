/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"testing"

	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

func TestPublicKey_GetValueFromJWK(t *testing.T) {
	t.Run("success - ed25519 value", func(t *testing.T) {
		keyJSON := `{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": ""
}`
		jwk := jose.JSONWebKey{}

		err := jwk.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		pk := PublicKey{}

		err = pk.GetValueFromJWK(&jwk)
		require.NoError(t, err)
	})

	t.Run("failure - unsupported key type", func(t *testing.T) {
		keyJSON := `{
	"kty":"EC",
	"crv":"P-256",
	"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
	"y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
	"use":"enc",
	"kid":"1"
}`

		jwk := jose.JSONWebKey{}

		err := jwk.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		pk := PublicKey{}

		err = pk.GetValueFromJWK(&jwk)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported")
	})
}
