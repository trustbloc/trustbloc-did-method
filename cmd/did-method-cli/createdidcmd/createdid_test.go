/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createdidcmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	flag          = "--"
	publickeyData = `
[
 {
  "type": "Ed25519VerificationKey2018",
  "purposes": ["verificationMethod"],
  "jwkPath": "%s"
 },
 {
  "type": "JwsVerificationKey2020",
  "purposes": ["verificationMethod"],
  "jwkPath": "%s"
 }
]`

	jwkPrivateKeyData = `
{
  "kty": "OKP",
  "kid": "key1",
  "d": "CSLczqR1ly2lpyBcWne9gFKnsjaKJw0dKfoSQu7lNvg",
  "crv": "Ed25519",
  "x": "bWRCy8DtNhRO3HdKTFB2eEG5Ac1J00D0DQPffOwtAD0"
}`
	jwk1Data = `
{
  "kty":"OKP",
  "kid": "key1",
  "crv":"Ed25519",
  "x":"o1bG1U7G3CNbtALMafUiFOq8ODraTyVTmPtRDO1QUWg",
  "y":""
}`
	jwk2Data = `
{
  "kty":"EC",
  "kid": "key2",
  "crv":"P-256",
  "x":"bGM9aNufpKNPxlkyacU1hGhQXm_aC8hIzSVeKDpwjBw",
  "y":"PfdmCOtIdVY2B6ucR4oQkt6evQddYhOyHoDYCaI2BJA"
}`

	pkPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFoxLiiZZYCh8XOZE0MXUYIgCrwIq
ho+LGIVUXDNaduiNfpLmk5MXS5Q7WQAMgaJBRyRldIvbrNWqph4DH2gdKQ==
-----END PUBLIC KEY-----`

	servicesData = `[
  {
    "id": "svc1",
    "type": "type1",
    "priority": 1,
    "routingKeys": ["key1"],
    "recipientKeys": ["key1"],
    "serviceEndpoint": "http://www.example.com"
  },
  {
    "id": "svc2",
    "type": "type2",
    "priority": 2,
    "routingKeys": ["key2"],
    "recipientKeys": ["key2"],
    "serviceEndpoint": "http://www.example.com"
  }
]`
)

func TestRecoveryKey(t *testing.T) {
	t.Run("test recovery key empty", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		var args []string
		args = append(args, domainArg()...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--recoverykey) or key file (--recoverykey-file) is required")
	})

	t.Run("test both recovery key and recovery key file exist", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, recoveryKeyFlagNameArg("key")...)
		args = append(args, recoveryKeyFileFlagNameArg("./file")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "only one of key (--recoverykey) or key file (--recoverykey-file) may be specified")
	})

	t.Run("test recovery key wrong pem", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, recoveryKeyFlagNameArg("w")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key not found in PEM")
	})

	t.Run("test recovery key success", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, recoveryKeyFileFlagNameArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--updatekey) or key file (--updatekey-file) is required")
	})
}

func TestService(t *testing.T) {
	t.Run("test services wrong path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, recoveryKeyFileFlagNameArg(file.Name())...)
		args = append(args, updateKeyFileFlagNameArg(file.Name())...)
		args = append(args, servicesFileArg("./wrong")...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("test services success", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		servicesFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = servicesFile.WriteString(servicesData)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(servicesFile.Name())) }()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, recoveryKeyFileFlagNameArg(file.Name())...)
		args = append(args, updateKeyFileFlagNameArg(file.Name())...)
		args = append(args, servicesFileArg(servicesFile.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to get endpoints")
	})
}

func TestGetPublicKeys(t *testing.T) {
	t.Run("test public key invalid path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, publicKeyFileArg("./wrongfile")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "open wrongfile: no such file or directory")
	})

	t.Run("test public key invalid jwk path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(publickeyData)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, publicKeyFileArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("test public key type not supported", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		jwk1File, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = jwk1File.WriteString(jwkPrivateKeyData)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(jwk1File.Name())) }()

		jwk2File, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = jwk2File.WriteString(jwk2Data)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(jwk2File.Name())) }()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(publickeyData, jwk1File.Name(), jwk2File.Name()))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, publicKeyFileArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported")
	})

	t.Run("test public key success", func(t *testing.T) {
		os.Clearenv()
		cmd := GetCreateDIDCmd()

		jwk1File, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = jwk1File.WriteString(jwk1Data)
		require.NoError(t, err)

		jwk2File, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = jwk2File.WriteString(jwk2Data)
		require.NoError(t, err)

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(publickeyData, jwk1File.Name(), jwk2File.Name()))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, domainArg()...)
		args = append(args, publicKeyFileArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--recoverykey) or key file (--recoverykey-file) is required")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	os.Clearenv()

	startCmd := GetCreateDIDCmd()

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func domainArg() []string {
	return []string{flag + domainFlagName, "domain"}
}

func publicKeyFileArg(value string) []string {
	return []string{flag + publicKeyFileFlagName, value}
}

func recoveryKeyFlagNameArg(value string) []string {
	return []string{flag + recoveryKeyFlagName, value}
}

func recoveryKeyFileFlagNameArg(value string) []string {
	return []string{flag + recoveryKeyFileFlagName, value}
}

func updateKeyFileFlagNameArg(value string) []string {
	return []string{flag + updateKeyFileFlagName, value}
}

func servicesFileArg(value string) []string {
	return []string{flag + serviceFileFlagName, value}
}
