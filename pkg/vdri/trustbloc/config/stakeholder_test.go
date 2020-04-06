/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// nolint: gochecknoglobals
var exampleStakeholders = []string{`{
	"domain": "bar.baz",
	"did": "did:trustbloc:foo.bar:zQ1234567890987654321",
	"policy": {
		"cache": {"max-age": 123456789}
	},
	"endpoints": [
		"https://bar.baz/webapi/123456",
		"https://bar.baz/webapi/654321"
	],
	"previous": "testTest12345"
}`,
	`{
	"domain": "baz.qux",
	"did": "did:trustbloc:foo.bar:zQ0987654321234567890",
	"policy": {
		"cache": {"max-age": 123456789}
	},
	"endpoints": [
		"https://baz.qux/iyoubhlkn/",
		"https://baz.foo/ukjhjtfyw/"
	],
	"previous": "testTest67890"
}`}

func Test_ParseStakeholder(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		jws := dummyJWSWrap(exampleStakeholders[0])

		cData, err := ParseStakeholder([]byte(jws))
		require.NoError(t, err)

		require.Equal(t, "bar.baz", cData.Config.Domain)
		require.Equal(t, exampleStakeholders[0], string(cData.JWS.UnsafePayloadWithoutVerification()))
	})

	t.Run("failure: not JWS", func(t *testing.T) {
		jws := `{aaaaaaa`
		_, err := ParseStakeholder([]byte(jws))
		require.Error(t, err)
		require.Contains(t, err.Error(), "stakeholder config data should be a JWS")
	})

	t.Run("failure: malformed stakeholder within JWS", func(t *testing.T) {
		jws := dummyJWSWrap(`{"bad":"data"`)

		_, err := ParseStakeholder([]byte(jws))
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end")
	})
}
