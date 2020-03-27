/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// GetUserSetVarFromString returns values either command line flag or environment variable
func GetUserSetVarFromString(cmd *cobra.Command, flagName, envKey string, isOptional bool) (string, error) {
	if cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetString(flagName)
		if err != nil {
			return "", fmt.Errorf(flagName+" flag not found: %s", err)
		}

		if value == "" {
			return "", fmt.Errorf("%s value is empty", flagName)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isOptional || isSet {
		if !isOptional && value == "" {
			return "", fmt.Errorf("%s value is empty", envKey)
		}

		return value, nil
	}

	return "", errors.New("Neither " + flagName + " (command line flag) nor " + envKey +
		" (environment variable) have been set.")
}

// GetUserSetVarFromArrayString returns values either command line flag or environment variable
func GetUserSetVarFromArrayString(cmd *cobra.Command, flagName, envKey string, isOptional bool) ([]string, error) {
	if cmd.Flags().Changed(flagName) {
		value, err := cmd.Flags().GetStringArray(flagName)
		if err != nil {
			return nil, fmt.Errorf(flagName+" flag not found: %s", err)
		}

		if len(value) == 0 {
			return nil, fmt.Errorf("%s value is empty", flagName)
		}

		return value, nil
	}

	value, isSet := os.LookupEnv(envKey)

	if isOptional || isSet {
		if !isOptional && value == "" {
			return nil, fmt.Errorf("%s value is empty", envKey)
		}

		if value == "" {
			return []string{}, nil
		}

		return strings.Split(value, ","), nil
	}

	return nil, errors.New("Neither " + flagName + " (command line flag) nor " + envKey +
		" (environment variable) have been set.")
}
