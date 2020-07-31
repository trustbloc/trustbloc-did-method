/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didconfiguration

import (
	"testing"

	"github.com/square/go-jose/v3"
	"github.com/stretchr/testify/require"
)

const (
	keyJSON = `{
  "kty": "OKP",
  "kid": "key1",
  "d": "CSLczqR1ly2lpyBcWne9gFKnsjaKJw0dKfoSQu7lNvg",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`
)

func TestCreateDIDConfiguration(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		conf, err := CreateDIDConfiguration("domain.website", "did:example:123abc", 0, &sigKey)
		require.NoError(t, err)

		require.Len(t, conf.Entries, 1)
		require.Equal(t, conf.Entries[0].DID, "did:example:123abc")
	})

	t.Run("failure", func(t *testing.T) {
		keyJSON := `{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`

		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		_, err = CreateDIDConfiguration("domain.website", "did:example:123abc", 0, &sigKey)
		require.Error(t, err)

		require.Contains(t, err.Error(), "can't create")
	})
}

func TestCreateDomainLinkageAssertion(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		dla, err := createDomainLinkageAssertion("domain.website", "did:example:123abc", 0, &sigKey)
		require.NoError(t, err)

		require.Equal(t, dla.DID, "did:example:123abc")
	})

	t.Run("failure - bad key", func(t *testing.T) {
		keyJSON := `{
  "kty": "OKP",
  "kid": "key1",
  "crv": "Ed25519",
  "x": "badKey"
}`

		var key jose.JSONWebKey
		err := key.UnmarshalJSON([]byte(keyJSON))
		require.NoError(t, err)

		sigKey := jose.SigningKey{Key: key, Algorithm: jose.EdDSA}

		_, err = createDomainLinkageAssertion("domain.website", "did:example:123abc", 0, &sigKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "can't construct signer")
	})
}
