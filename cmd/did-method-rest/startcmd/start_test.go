/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/hyperledger/aries-framework-go/pkg/storage"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const flag = "--"

type mockServer struct{}

func (s *mockServer) ListenAndServe(host string, handler http.Handler) error {
	return nil
}

func TestListenAndServe(t *testing.T) {
	h := HTTPServer{}
	err := h.ListenAndServe("7", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "listen tcp: address 7: missing port in address")
}

func TestStartCmdWithBlankArg(t *testing.T) {
	t.Run("test blank database type arg", func(t *testing.T) {
		startCmd := GetStartCmd(&mockServer{})

		args := []string{"--" + hostURLFlagName, "test", "--" + domainFlagName,
			"domain", "--" + databaseTypeFlagName, ""}
		startCmd.SetArgs(args)

		err := startCmd.Execute()
		require.Error(t, err)
		require.Equal(t, "database-type value is empty", err.Error())
	})
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

func TestStartCmdValidArgsEnvVar(t *testing.T) {
	startCmd := GetStartCmd(&mockServer{})

	err := os.Setenv(hostURLEnvKey, "localhost:8080")
	require.NoError(t, err)

	err = os.Setenv(domainEnvKey, "domain")
	require.NoError(t, err)

	err = os.Setenv(databaseTypeEnvKey, databaseTypeMemOption)
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

		err = os.Setenv(databaseTypeEnvKey, databaseTypeMemOption)
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

func TestCreateKMS(t *testing.T) {
	t.Run("test error from create new kms", func(t *testing.T) {
		v, err := createKMS(&MockStoreProvider{
			ErrOpenStoreHandle: fmt.Errorf("error open store")})
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to create new kms")
		require.Nil(t, v)
	})

	t.Run("test success", func(t *testing.T) {
		v, err := createKMS(&MockStoreProvider{})
		require.NoError(t, err)
		require.NotNil(t, v)
	})
}

func TestCreateProvider(t *testing.T) {
	t.Run("test error from create new couchdb", func(t *testing.T) {
		err := startDidMethod(&parameters{databaseType: databaseTypeCouchDBOption})
		require.Error(t, err)
		require.Contains(t, err.Error(), "hostURL for new CouchDB provider can't be blank")
	})

	t.Run("test invalid database type", func(t *testing.T) {
		err := startDidMethod(&parameters{databaseType: "data1"})
		require.Error(t, err)
		require.Contains(t, err.Error(), "database type not set to a valid type")
	})
}

func getValidArgs() []string {
	var args []string
	args = append(args, hostURLArg()...)
	args = append(args, domainArg()...)
	args = append(args, databaseTypeArg()...)

	return args
}

func hostURLArg() []string {
	return []string{flag + hostURLFlagName, "localhost:8080"}
}

func domainArg() []string {
	return []string{flag + domainFlagName, "domain"}
}

func databaseTypeArg() []string {
	return []string{flag + databaseTypeFlagName, databaseTypeMemOption}
}

// MockStoreProvider mock store provider.
type MockStoreProvider struct {
	ErrOpenStoreHandle error
}

// OpenStore opens and returns a store for given name space.
func (s *MockStoreProvider) OpenStore(name string) (storage.Store, error) {
	return nil, s.ErrOpenStoreHandle
}

// Close closes all stores created under this store provider
func (s *MockStoreProvider) Close() error {
	return nil
}

// CloseStore closes store for given name space
func (s *MockStoreProvider) CloseStore(name string) error {
	return nil
}
