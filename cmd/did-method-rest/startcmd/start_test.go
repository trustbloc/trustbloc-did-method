/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const flag = "--"

type mockServer struct {
	serveHandler func(string, http.Handler) error
}

func (s *mockServer) ListenAndServe(host string, handler http.Handler) error {
	if s.serveHandler == nil {
		return nil
	}

	return s.serveHandler(host, handler)
}

func TestListenAndServe(t *testing.T) {
	h := HTTPServer{}
	err := h.ListenAndServe("7", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "listen tcp: address 7: missing port in address")
}

func TestStartCmdContents(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.Equal(t, "start", startCmd.Use)
	require.Equal(t, "Start did-method", startCmd.Short)
	require.Equal(t, "Start did-method", startCmd.Long)

	checkFlagPropertiesCorrect(t, startCmd, hostURLFlagName, hostURLFlagShorthand, hostURLFlagUsage)
}

func TestStartCmdWithMissingHostArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := startCmd.Execute()
	require.Error(t, err)
	require.Equal(t,
		"Neither host-url (command line flag) nor DID_METHOD_HOST_URL (environment variable) have been set.",
		err.Error())
}

func TestStartCmdValidArgs(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := getValidArgs()
	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Nil(t, err)
}

func TestStartCmdWithInvalidEnableSignaturesArg(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	args := getValidArgs()
	args = append(args, flag+"enable-signatures", "aaaaaa")

	startCmd.SetArgs(args)

	err := startCmd.Execute()
	require.Error(t, err)
}

func TestStartCmdWithGenesisFile(t *testing.T) {
	const (
		// nolint: lll
		genesisFile = `{
"payload":"eyJkb21haW4iOiJ0ZXN0bmV0LnRydXN0YmxvYy5sb2NhbCIsInBvbGljeSI6eyJjYWNoZSI6eyJtYXhBZ2UiOjI0MTkyMDB9LCJudW1RdWVyaWVzIjoyfSwibWVtYmVycyI6W3siZG9tYWluIjoic3Rha2Vob2xkZXIub25lIiwicHVibGljS2V5Ijp7ImlkIjoiI2tleTEiLCJqd2siOnsia3R5IjoiT0tQIiwia2lkIjoia2V5MSIsImNydiI6IkVkMjU1MTkiLCJ4IjoiYldSQ3k4RHROaFJPM0hkS1RGQjJlRUc1QWMxSjAwRDBEUVBmZk93dEFEMCJ9fX1dLCJwcmV2aW91cyI6ImZvb2JhciJ9",
"protected":"eyJhbGciOiJFZERTQSJ9",
"signature":"r9t2zfeMht4VwbmTtY22hhCykWgR4qkkM1RZYPV6BFVKiLZBpaHVqhnUQ8X1nXzSSMAqTLaKNM9Q1C5ayBxrBw"
}
`

		badFile = `lorem ipsum dolor sit amet`

		badPayload = `{
"payload":"aaaa",
"protected":"eyJhbGciOiJFZERTQSJ9",
"signature":"r9t2zfeMht4VwbmTtY22hhCykWgR4qkkM1RZYPV6BFVKiLZBpaHVqhnUQ8X1nXzSSMAqTLaKNM9Q1C5ayBxrBw"
}
`
		invalidConfig = `{
"payload":"eyJjIjp7fX0",
"protected":"eyJhbGciOiJFZERTQSJ9",
"signature":"r9t2zfeMht4VwbmTtY22hhCykWgR4qkkM1RZYPV6BFVKiLZBpaHVqhnUQ8X1nXzSSMAqTLaKNM9Q1C5ayBxrBw"
}
`
	)

	t.Run("success", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(genesisFile)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := getValidArgs()
		args = append(args, flag+genesisFileFlagName, file.Name())

		startCmd := GetStartCmd(&mockServer{})
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("success: multiple genesis files", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(genesisFile)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := getValidArgs()
		args = append(args,
			flag+genesisFileFlagName, file.Name(),
			flag+genesisFileFlagName, file.Name(),
		)

		startCmd := GetStartCmd(&mockServer{})
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("failure reading genesis file", func(t *testing.T) {
		args := getValidArgs()
		args = append(args, flag+genesisFileFlagName, "./$$$$$$$$$$badfilename.no")

		startCmd := GetStartCmd(&mockServer{})
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "reading genesis file")
	})

	t.Run("failure parsing genesis file", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(badFile)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := getValidArgs()
		args = append(args, flag+genesisFileFlagName, file.Name())

		startCmd := GetStartCmd(&mockServer{})
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "parsing genesis file")
	})

	t.Run("failure parsing genesis config", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(badPayload)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := getValidArgs()
		args = append(args, flag+genesisFileFlagName, file.Name())

		startCmd := GetStartCmd(&mockServer{})
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})

	t.Run("failure: genesis file is invalid config", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(invalidConfig)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		args := getValidArgs()
		args = append(args, flag+genesisFileFlagName, file.Name())

		var mockHandler http.Handler

		server := &mockServer{
			serveHandler: func(host string, handler http.Handler) error {
				mockHandler = handler
				return nil
			},
		}

		startCmd := GetStartCmd(server)
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		mockHandler.ServeHTTP(rw, httptest.NewRequest("", "/resolveDID?did=did:trustbloc:testnet.trustbloc.local:abc", nil))

		res := rw.Result()

		require.Equal(t, http.StatusBadRequest, res.StatusCode)

		body, err := ioutil.ReadAll(res.Body)
		require.NoError(t, err)

		require.NoError(t, res.Body.Close())

		require.Contains(t, string(body), "cached config missing")
	})

	t.Run("success: load genesis file and (fail to) resolve a DID", func(t *testing.T) {
		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(genesisFile)
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		var args []string
		args = append(args, hostURLArg()...)
		args = append(args,
			flag+domainFlagName, "consortium.net",
			flag+genesisFileFlagName, file.Name(),
		)

		var mockHandler http.Handler

		server := &mockServer{
			serveHandler: func(host string, handler http.Handler) error {
				mockHandler = handler
				return nil
			},
		}

		startCmd := GetStartCmd(server)
		startCmd.SetArgs(args)

		err = startCmd.Execute()
		require.NoError(t, err)

		rw := httptest.NewRecorder()

		mockHandler.ServeHTTP(rw, httptest.NewRequest("", "/resolveDID?did=did:trustbloc:testnet.trustbloc.local:abc", nil))

		res := rw.Result()

		require.Equal(t, http.StatusBadRequest, res.StatusCode)

		body, err := ioutil.ReadAll(res.Body)
		require.NoError(t, err)

		require.NoError(t, res.Body.Close())

		require.Contains(t, string(body), "failed to resolve did")
	})
}

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(domainEnvKey, "domain")
	require.NoError(t, err)

	err = startCmd.Execute()
	require.NoError(t, err)
}

func TestInValidModeVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := os.Setenv(modeEnvKey, "invalid")
	require.NoError(t, err)

	err = startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported mode")
}

func TestDomainFlagVar(t *testing.T) {
	t.Run("test domain is optional when mode is resolver", func(t *testing.T) {
		os.Clearenv()

		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "localhost:8080")
		require.NoError(t, err)

		err = os.Setenv(modeEnvKey, string(resolver))
		require.NoError(t, err)

		err = startCmd.Execute()
		require.NoError(t, err)
	})

	t.Run("test domain is required when mode is registrar", func(t *testing.T) {
		os.Clearenv()

		startCmd := GetStartCmd(&mockServer{})

		err := os.Setenv(hostURLEnvKey, "localhost:8080")
		require.NoError(t, err)

		err = os.Setenv(modeEnvKey, string(registrar))
		require.NoError(t, err)

		err = startCmd.Execute()
		require.Error(t, err)
		require.Equal(t,
			"Neither domain (command line flag) nor DID_METHOD_DOMAIN (environment variable) have been set.",
			err.Error())
	})
}

func TestTLSSystemCertPoolInvalidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	require.NoError(t, os.Setenv(hostURLEnvKey, "localhost:8080"))
	require.NoError(t, os.Setenv(tlsSystemCertPoolEnvKey, "wrongvalue"))

	err := startCmd.Execute()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid syntax")
}

func checkFlagPropertiesCorrect(t *testing.T, cmd *cobra.Command, flagName, flagShorthand, flagUsage string) {
	flag := cmd.Flag(flagName)

	require.NotNil(t, flag)
	require.Equal(t, flagName, flag.Name)
	require.Equal(t, flagShorthand, flag.Shorthand)
	require.Equal(t, flagUsage, flag.Usage)
	require.Equal(t, "", flag.Value.String())

	flagAnnotations := flag.Annotations
	require.Nil(t, flagAnnotations)
}

func getValidArgs() []string {
	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, domainArg()...)

	return args
}

func hostURLArg() []string {
	return []string{flag + hostURLFlagName, "localhost:8080"}
}

func domainArg() []string {
	return []string{flag + domainFlagName, "domain"}
}
