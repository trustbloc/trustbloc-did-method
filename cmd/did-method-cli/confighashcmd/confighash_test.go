/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package confighashcmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

const flag = "--"

// nolint: gochecknoglobals
var configData = `{
  "consortium_data": {
    "domain": "consortium.net",
    "genesis_block": "6e2f978e16b59df1d6a1dfbacb92e7d3eddeb8b3fd825e573138b3fd77d77264",
    "policy": {
      "cache": {
        "max_age": 2419200
      },
      "num_queries": 2,
      "history_hash": "SHA256",
      "sidetree": {
        "hash_algorithm": "SHA256",
        "key_algorithm": "NotARealAlg2018",
        "max_encoded_hash_length": 100,
        "max_operation_size": 8192
      }
    }
  },
  "members_data": [
    {
      "domain": "stakeholder.one",
      "policy": {"cache": {"max_age": 604800}},
      "endpoints": [
        "http://endpoints.stakeholder.one/peer1/",
        "http://endpoints.stakeholder.one/peer2/"
      ],
      "privateKeyJwkPath": "%s"
    }
  ]
}`

func TestConfigHashCmdWithMissingArg(t *testing.T) {
	t.Run("test missing arg config file", func(t *testing.T) {
		cmd := GetConfigHashCmd()

		err := cmd.Execute()

		require.Error(t, err)
		require.Equal(t,
			"Neither config-file (command line flag) nor DID_METHOD_CLI_CONFIG_FILE (environment variable) have been set.",
			err.Error())
	})
}

func TestConfigHashCmd(t *testing.T) {
	t.Run("test wrong config file", func(t *testing.T) {
		cmd := GetConfigHashCmd()

		var args []string
		args = append(args, configFileArg("wrongValue")...)

		cmd.SetArgs(args)

		err := cmd.Execute()
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to read config file")
	})

	t.Run("test create config and write them to file", func(t *testing.T) {
		os.Clearenv()

		file, err := ioutil.TempFile("", "*.json")
		require.NoError(t, err)

		_, err = file.WriteString(fmt.Sprintf(configData))
		require.NoError(t, err)

		defer func() { require.NoError(t, os.Remove(file.Name())) }()

		cmd := GetConfigHashCmd()

		var args []string
		args = append(args, configFileArg(file.Name())...)

		cmd.SetArgs(args)

		err = cmd.Execute()
		require.NoError(t, err)
	})
}

func configFileArg(config string) []string {
	return []string{flag + configFileFlagName, config}
}