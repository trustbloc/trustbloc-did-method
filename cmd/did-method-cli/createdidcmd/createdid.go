/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createdidcmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/trustbloc-did-method/cmd/did-method-cli/common"
	"github.com/trustbloc/trustbloc-did-method/pkg/did"
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/create"
)

const (
	domainFlagName      = "domain"
	domainFileEnvKey    = "DID_METHOD_CLI_DOMAIN"
	domainFileFlagUsage = "URL to the did:trustbloc consortium's domain. " +
		" Alternatively, this can be set with the following environment variable: " + domainFileEnvKey

	sidetreeURLFlagName  = "sidetree-url"
	sidetreeURLFlagUsage = "Comma-Separated list of sidetree url." +
		" Alternatively, this can be set with the following environment variable: " + sidetreeURLEnvKey
	sidetreeURLEnvKey = "DID_METHOD_CLI_SIDETREE_URL"

	tlsSystemCertPoolFlagName  = "tls-systemcertpool"
	tlsSystemCertPoolFlagUsage = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "DID_METHOD_CLI_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName  = "tls-cacerts"
	tlsCACertsFlagUsage = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "DID_METHOD_CLI_TLS_CACERTS"

	sidetreeWriteTokenFlagName  = "sidetree-write-token"
	sidetreeWriteTokenEnvKey    = "DID_METHOD_CLI_SIDETREE_WRITE_TOKEN" //nolint: gosec
	sidetreeWriteTokenFlagUsage = "The sidetree write token " +
		" Alternatively, this can be set with the following environment variable: " + sidetreeWriteTokenEnvKey

	publicKeyFileFlagName  = "publickey-file"
	publicKeyFileEnvKey    = "DID_METHOD_CLI_PUBLICKEY_FILE"
	publicKeyFileFlagUsage = "publickey file include public keys for Trustbloc DID " +
		" Alternatively, this can be set with the following environment variable: " + publicKeyFileEnvKey

	serviceFileFlagName = "service-file"
	serviceFileEnvKey   = "DID_METHOD_CLI_SERVICE_FILE"
	serviceFlagUsage    = "publickey file include services for Trustbloc DID " +
		" Alternatively, this can be set with the following environment variable: " + serviceFileEnvKey

	recoveryKeyFlagName  = "recoverykey"
	recoveryKeyEnvKey    = "DID_METHOD_CLI_RECOVERYKEY"
	recoveryKeyFlagUsage = "The public key PEM used for recovery of the document." +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyEnvKey

	recoveryKeyFileFlagName  = "recoverykey-file"
	recoveryKeyFileEnvKey    = "DID_METHOD_CLI_RECOVERYKEY_FILE"
	recoveryKeyFileFlagUsage = "The file that contains the public key PEM used for recovery of the document." +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyFileEnvKey

	updateKeyFlagName  = "updatekey"
	updateKeyEnvKey    = "DID_METHOD_CLI_UPDATEKEY"
	updateKeyFlagUsage = "The public key PEM used for validating the signature of the next update of the document." +
		" Alternatively, this can be set with the following environment variable: " + updateKeyEnvKey

	updateKeyFileFlagName  = "updatekey-file"
	updateKeyFileEnvKey    = "DID_METHOD_CLI_UPDATEKEY_FILE"
	updateKeyFileFlagUsage = "The file that contains the public key PEM used for" +
		" validating the signature of the next update of the document." +
		" Alternatively, this can be set with the following environment variable: " + updateKeyFileEnvKey
)

// GetCreateDIDCmd returns the Cobra create did command.
func GetCreateDIDCmd() *cobra.Command {
	createDIDCmd := createDIDCmd()

	createFlags(createDIDCmd)

	return createDIDCmd
}

func createDIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create-did",
		Short: "Create TrustBloc DID",
		Long:  "Create TrustBloc DID",
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCAs, err := getRootCAs(cmd)
			if err != nil {
				return err
			}

			sidetreeWriteToken := cmdutils.GetUserSetOptionalVarFromString(cmd, sidetreeWriteTokenFlagName,
				sidetreeWriteTokenEnvKey)

			domain := cmdutils.GetUserSetOptionalVarFromString(cmd, domainFlagName,
				domainFileEnvKey)

			client := did.New(did.WithAuthToken(sidetreeWriteToken),
				did.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}))

			opts, err := createDIDOption(cmd)
			if err != nil {
				return err
			}

			didDoc, err := client.CreateDID(domain, opts...)
			if err != nil {
				return fmt.Errorf("failed to create did: %w", err)
			}

			bytes, err := didDoc.JSONBytes()
			if err != nil {
				return err
			}

			fmt.Println(string(bytes))

			return nil
		},
	}
}

func getSidetreeURL(cmd *cobra.Command) []create.Option {
	var opts []create.Option

	sidetreeURL := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLFlagName,
		sidetreeURLEnvKey)

	for _, v := range sidetreeURL {
		opts = append(opts, create.WithSidetreeEndpoint(v))
	}

	return opts
}

func createDIDOption(cmd *cobra.Command) ([]create.Option, error) {
	opts, err := getPublicKeys(cmd)
	if err != nil {
		return nil, err
	}

	recoveryKey, err := common.GetKey(cmd, recoveryKeyFlagName, recoveryKeyEnvKey, recoveryKeyFileFlagName,
		recoveryKeyFileEnvKey, nil, false)
	if err != nil {
		return nil, err
	}

	opts = append(opts, create.WithRecoveryPublicKey(recoveryKey))

	updateKey, err := common.GetKey(cmd, updateKeyFlagName, updateKeyEnvKey, updateKeyFileFlagName,
		updateKeyFileEnvKey, nil, false)
	if err != nil {
		return nil, err
	}

	opts = append(opts, create.WithUpdatePublicKey(updateKey))

	serviceOpts, err := getServices(cmd)
	if err != nil {
		return nil, err
	}

	opts = append(opts, serviceOpts...)

	opts = append(opts, getSidetreeURL(cmd)...)

	return opts, nil
}

func getServices(cmd *cobra.Command) ([]create.Option, error) {
	serviceFile := cmdutils.GetUserSetOptionalVarFromString(cmd, serviceFileFlagName,
		serviceFileEnvKey)

	var opts []create.Option

	if serviceFile != "" {
		services, err := common.GetServices(serviceFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get services from file %w", err)
		}

		for i := range services {
			opts = append(opts, create.WithService(&services[i]))
		}
	}

	return opts, nil
}

func getPublicKeys(cmd *cobra.Command) ([]create.Option, error) {
	publicKeyFile := cmdutils.GetUserSetOptionalVarFromString(cmd, publicKeyFileFlagName,
		publicKeyFileEnvKey)

	var opts []create.Option

	if publicKeyFile != "" {
		publicKeys, err := common.GetPublicKeysFromFile(publicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get public keys from file %w", err)
		}

		for i := range publicKeys {
			opts = append(opts, create.WithPublicKey(&publicKeys[i]))
		}
	}

	return opts, nil
}

func getRootCAs(cmd *cobra.Command) (*x509.CertPool, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey)

	return tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(domainFlagName, "", "", domainFileFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(publicKeyFileFlagName, "", "", publicKeyFileFlagUsage)
	startCmd.Flags().StringP(serviceFileFlagName, "", "", serviceFlagUsage)
	startCmd.Flags().StringP(recoveryKeyFlagName, "", "", recoveryKeyFlagUsage)
	startCmd.Flags().StringP(recoveryKeyFileFlagName, "", "", recoveryKeyFileFlagUsage)
	startCmd.Flags().StringP(updateKeyFlagName, "", "", updateKeyFlagUsage)
	startCmd.Flags().StringP(updateKeyFileFlagName, "", "", updateKeyFileFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLFlagName, "", []string{}, sidetreeURLFlagUsage)
}
