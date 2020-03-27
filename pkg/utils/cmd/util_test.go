/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

const (
	flagName = "host-url"
	envKey   = "TEST_HOST_URL"
)

func TestGetUserSetVarFromStringNegative(t *testing.T) {
	os.Clearenv()

	cmd := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test missing both command line argument and environment vars
	env, err := GetUserSetVarFromString(cmd, flagName, envKey, false)
	require.Error(t, err)
	require.Empty(t, env)
	require.Contains(t, err.Error(), "TEST_HOST_URL (environment variable) have been set.")

	// test env var is empty
	err = os.Setenv(envKey, "")
	require.NoError(t, err)

	env, err = GetUserSetVarFromString(cmd, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TEST_HOST_URL value is empty")
	require.Empty(t, env)

	// test arg is empty
	cmd.Flags().StringP(flagName, "", "initial", "")
	args := []string{"--" + flagName, ""}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	env, err = GetUserSetVarFromString(cmd, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "host-url value is empty")
	require.Empty(t, env)
}

func TestGetUserSetVarFromArrayStringNegative(t *testing.T) {
	os.Clearenv()

	cmd := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test missing both command line argument and environment vars
	env, err := GetUserSetVarFromArrayString(cmd, flagName, envKey, false)
	require.Error(t, err)
	require.Empty(t, env)
	require.Contains(t, err.Error(), "TEST_HOST_URL (environment variable) have been set.")

	// test env var is empty
	err = os.Setenv(envKey, "")
	require.NoError(t, err)

	env, err = GetUserSetVarFromArrayString(cmd, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "TEST_HOST_URL value is empty")
	require.Empty(t, env)

	// test arg is empty
	cmd.Flags().StringArrayP(flagName, "", []string{}, "")
	args := []string{"--" + flagName, ""}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	env, err = GetUserSetVarFromArrayString(cmd, flagName, envKey, false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "host-url value is empty")
	require.Empty(t, env)
}

func TestGetUserSetVarFromString(t *testing.T) {
	os.Clearenv()

	cmd := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test env var is set
	hostURL := "localhost:8080"
	err := os.Setenv(envKey, hostURL)
	require.NoError(t, err)

	// test resolution via environment variable
	env, err := GetUserSetVarFromString(cmd, flagName, envKey, false)
	require.NoError(t, err)
	require.Equal(t, hostURL, env)

	// set command line arguments
	cmd.Flags().StringP(flagName, "", "initial", "")
	args := []string{"--" + flagName, "other"}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	// test resolution via command line argument - no environment variable set
	env, err = GetUserSetVarFromString(cmd, flagName, "", false)
	require.NoError(t, err)
	require.Equal(t, "other", env)
}

func TestGetUserSetVarFromArrayString(t *testing.T) {
	os.Clearenv()

	cmd := &cobra.Command{
		Use:   "start",
		Short: "short usage",
		Long:  "long usage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}

	// test env var is set
	hostURL := "localhost:8080"
	err := os.Setenv(envKey, hostURL)
	require.NoError(t, err)

	// test resolution via environment variable
	env, err := GetUserSetVarFromArrayString(cmd, flagName, envKey, false)
	require.NoError(t, err)
	require.Equal(t, []string{hostURL}, env)

	// set command line arguments
	cmd.Flags().StringArrayP(flagName, "", []string{}, "")
	args := []string{"--" + flagName, "other", "--" + flagName, "other1"}
	cmd.SetArgs(args)
	err = cmd.Execute()
	require.NoError(t, err)

	// test resolution via command line argument - no environment variable set
	env, err = GetUserSetVarFromArrayString(cmd, flagName, "", false)
	require.NoError(t, err)
	require.Equal(t, []string{"other", "other1"}, env)
}
