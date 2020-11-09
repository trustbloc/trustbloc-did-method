/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"log"

	"github.com/spf13/cobra"

	"github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli/confighashcmd"
	"github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli/createconfigcmd"
	"github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli/createdidcmd"
	"github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli/deactivatedidcmd"
	"github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli/recoverdidcmd"
	"github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli/updatedidcmd"
)

func main() {
	rootCmd := &cobra.Command{
		Run: func(cmd *cobra.Command, args []string) {
			cmd.HelpFunc()(cmd, args)
		},
	}

	rootCmd.AddCommand(createconfigcmd.GetCreateConfigCmd())
	rootCmd.AddCommand(confighashcmd.GetConfigHashCmd())
	rootCmd.AddCommand(createdidcmd.GetCreateDIDCmd())
	rootCmd.AddCommand(updatedidcmd.GetUpdateDIDCmd())
	rootCmd.AddCommand(recoverdidcmd.GetRecoverDIDCmd())
	rootCmd.AddCommand(deactivatedidcmd.GetDeactivateDIDCmd())

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Failed to run did method cli: %s", err.Error())
	}
}
