/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package updatedidcmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
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

	privateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,A6CD57B60A99920E21D34C0C1E0D90D5

LaYVtZ4SsMthe6NjybSCQa4jOSOtCKEpO3wmbeSBYldJXXrDU4gOSVFiHJ45hTJP
Q7UGQKWNHeITH8NQlkmcySEKnaI9uyOkcb6TIvklapHCAF8cUf1kCHU10Eo0RTMI
2tJs7NW6oA4ZNi/o3xYVKVQ1R0lrgQGv9zatOupVPtQ=
-----END EC PRIVATE KEY-----
`

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

func TestMissingArg(t *testing.T) {
	t.Run("test did uri is missing", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		var args []string
		args = append(args, domainArg()...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "Neither did-uri (command line flag) nor "+
			"DID_METHOD_CLI_DID_URI (environment variable) have been set.")
	})
}

func TestParseKey(t *testing.T) {
	t.Run("test failed to parse private key", func(t *testing.T) {
		_, err := parsePrivateKey([]byte("wrong"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to parse private key")
	})

	t.Run("test parse pkcs8 private key", func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)

		b, err := x509.MarshalPKCS8PrivateKey(privateKey)
		require.NoError(t, err)

		_, err = parsePrivateKey(b)
		require.NoError(t, err)
	})

	t.Run("test found unknown private key type in PKCS#8 wrapping", func(t *testing.T) {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		b, err := x509.MarshalPKCS8PrivateKey(pk)
		require.NoError(t, err)

		_, err = parsePrivateKey(b)
		require.Error(t, err)
		require.Contains(t, err.Error(), "found unknown private key type in PKCS#8 wrapping")
	})
}

func TestKey(t *testing.T) {
	t.Run("test signing key empty", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, sidetreeURLArg("url")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--signingkey) or key file (--signingkey-file) is required")
	})

	t.Run("test both signing key and signing key file exist", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyFlagNameArg("key")...)
		args = append(args, signingKeyFileFlagNameArg("./file")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "only one of key (--signingkey) or key file (--signingkey-file) may be specified")
	})

	t.Run("test signing key wrong pem", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyFlagNameArg("w")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "private key not found in PEM")
	})

	t.Run("test next update key wrong pem", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyPasswordArg()...)
		args = append(args, signingKeyFileFlagNameArg(file.Name())...)
		args = append(args, nextUpdateKeyFlagNameArg("w")...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "public key not found in PEM")
	})

	t.Run("test signing key success", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyFileFlagNameArg(file.Name())...)
		args = append(args, signingKeyPasswordArg()...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--nextupdatekey) or key file (--nextupdatekey-file) is required")
	})
}

func TestService(t *testing.T) {
	t.Run("test services wrong path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		privateKeyFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = privateKeyFile.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(privateKeyFile.Name())) }()

		publicKeyFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = publicKeyFile.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(publicKeyFile.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, signingKeyFileFlagNameArg(privateKeyFile.Name())...)
		args = append(args, nextUpdateKeyFileFlagNameArg(publicKeyFile.Name())...)
		args = append(args, addServicesFileArg("./wrong")...)
		args = append(args, signingKeyPasswordArg()...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("test services success", func(t *testing.T) {
		serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer serv.Close()

		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		privateKeyFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = privateKeyFile.WriteString(privateKeyPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(privateKeyFile.Name())) }()

		publicKeyFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = publicKeyFile.WriteString(pkPEM)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(publicKeyFile.Name())) }()

		servicesFile, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = servicesFile.WriteString(servicesData)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(servicesFile.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, sidetreeURLArg(serv.URL)...)
		args = append(args, signingKeyFileFlagNameArg(privateKeyFile.Name())...)
		args = append(args, nextUpdateKeyFileFlagNameArg(publicKeyFile.Name())...)
		args = append(args, addServicesFileArg(servicesFile.Name())...)
		args = append(args, removeServiceIDArg("svc1")...)
		args = append(args, removePublicKeyIDArg("key1")...)
		args = append(args, signingKeyPasswordArg()...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.NoError(t, err)
	})
}

func TestGetPublicKeys(t *testing.T) {
	t.Run("test public key invalid path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, addPublicKeyFileArg("./wrongfile")...)

		cmd.SetArgs(args)
		err := cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "open wrongfile: no such file or directory")
	})

	t.Run("test public key invalid jwk path", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(publickeyData)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, addPublicKeyFileArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "no such file or directory")
	})

	t.Run("test public key type not supported", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

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
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, addPublicKeyFileArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "key not supported")
	})

	t.Run("test public key success", func(t *testing.T) {
		os.Clearenv()
		cmd := GetUpdateDIDCmd()

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
		args = append(args, didURIArg()...)
		args = append(args, domainArg()...)
		args = append(args, addPublicKeyFileArg(file.Name())...)

		cmd.SetArgs(args)
		err = cmd.Execute()

		require.Error(t, err)
		require.Contains(t, err.Error(), "either key (--signingkey) or key file (--signingkey-file) is require")
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	os.Clearenv()

	startCmd := GetUpdateDIDCmd()

	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func domainArg() []string {
	return []string{flag + domainFlagName, "domain"}
}

func signingKeyPasswordArg() []string {
	return []string{flag + signingKeyPasswordFlagName, "123"}
}

func sidetreeURLArg(value string) []string {
	return []string{flag + sidetreeURLFlagName, value}
}

func didURIArg() []string {
	return []string{flag + didURIFlagName, "did:ex:123"}
}

func addPublicKeyFileArg(value string) []string {
	return []string{flag + addPublicKeyFileFlagName, value}
}

func signingKeyFlagNameArg(value string) []string {
	return []string{flag + signingKeyFlagName, value}
}

func signingKeyFileFlagNameArg(value string) []string {
	return []string{flag + signingKeyFileFlagName, value}
}

func nextUpdateKeyFlagNameArg(value string) []string {
	return []string{flag + nextUpdateKeyFlagName, value}
}

func nextUpdateKeyFileFlagNameArg(value string) []string {
	return []string{flag + nextUpdateKeyFileFlagName, value}
}

func addServicesFileArg(value string) []string {
	return []string{flag + addServiceFileFlagName, value}
}

func removeServiceIDArg(value string) []string {
	return []string{flag + removeServiceIDFlagName, value}
}

func removePublicKeyIDArg(value string) []string {
	return []string{flag + removePublicKeyIDFlagName, value}
}
