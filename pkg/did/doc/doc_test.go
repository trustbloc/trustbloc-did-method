/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package doc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	ariesdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

func TestDoc_JSONBytes(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		ecPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecPubKeyBytes := elliptic.Marshal(ecPrivKey.PublicKey.Curve, ecPrivKey.PublicKey.X, ecPrivKey.PublicKey.Y)

		didDOc := Doc{PublicKey: []PublicKey{{ID: "key1", Encoding: PublicKeyEncodingJwk, KeyType: Ed25519KeyType,
			Value: pubKey}, {ID: "key2", Encoding: PublicKeyEncodingJwk, KeyType: P256KeyType, Value: ecPubKeyBytes}},
			Service: []ariesdid.Service{{ID: "svc1", Properties: map[string]interface{}{"k1": "v1"}}}}
		_, err = didDOc.JSONBytes()

		require.NoError(t, err)
	})

	t.Run("error encoding not supported", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDOc := Doc{PublicKey: []PublicKey{{ID: "key1", Encoding: "wrong", KeyType: Ed25519KeyType,
			Value: pubKey}}, Service: []ariesdid.Service{{ID: "svc1"}}}
		_, err = didDOc.JSONBytes()

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key encoding not supported")
	})

	t.Run("error key not supported", func(t *testing.T) {
		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		didDOc := Doc{PublicKey: []PublicKey{{ID: "key1", Encoding: PublicKeyEncodingJwk, KeyType: "wrong",
			Value: pubKey}}, Service: []ariesdid.Service{{ID: "svc1"}}}
		_, err = didDOc.JSONBytes()

		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid key type: wrong")
	})
}

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
