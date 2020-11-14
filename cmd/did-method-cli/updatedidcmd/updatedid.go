/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package updatedidcmd

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
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/update"
)

const (
	didURIFlagName  = "did-uri"
	didURIEnvKey    = "DID_METHOD_CLI_DID_URI"
	didURIFlagUsage = "DID URI. " +
		" Alternatively, this can be set with the following environment variable: " + didURIEnvKey

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

	addPublicKeyFileFlagName  = "add-publickey-file"
	addPublicKeyFileEnvKey    = "DID_METHOD_CLI_ADD_PUBLICKEY_FILE"
	addPublicKeyFileFlagUsage = "publickey file include public keys to be added for TrustBloc DID " +
		" Alternatively, this can be set with the following environment variable: " + addPublicKeyFileEnvKey

	addServiceFileFlagName = "add-service-file"
	addServiceFileEnvKey   = "DID_METHOD_CLI_ADD_SERVICE_FILE"
	addServiceFlagUsage    = "publickey file include services to be added for TrustBloc DID " +
		" Alternatively, this can be set with the following environment variable: " + addServiceFileEnvKey

	removePublicKeyIDFlagName  = "remove-publickey-id"
	removePublicKeyIDEnvKey    = "DID_METHOD_CLI_REMOVE_PUBLICKEY_ID"
	removePublicKeyIDFlagUsage = "Comma-Separated list of public key id's to be removed from TrustBloc DID. " +
		" Alternatively, this can be set with the following environment variable: " + removePublicKeyIDEnvKey

	removeServiceIDFlagName  = "remove-service-id"
	removeServiceIDEnvKey    = "DID_METHOD_CLI_REMOVE_SERVICE_ID"
	removeServiceIDFlagUsage = "Comma-Separated list of service id's to be removed from TrustBloc DID. " +
		" Alternatively, this can be set with the following environment variable: " + removeServiceIDEnvKey

	signingKeyFlagName  = "signingkey"
	signingKeyEnvKey    = "DID_METHOD_CLI_SIGNINGKEY"
	signingKeyFlagUsage = "The private key PEM used for signing the update of the index document." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyEnvKey

	signingKeyFileFlagName  = "signingkey-file"
	signingKeyFileEnvKey    = "DID_METHOD_CLI_SIGNINGKEY_FILE"
	signingKeyFileFlagUsage = "The file that contains the private key" +
		" PEM used for signing the update of the index document" +
		" Alternatively, this can be set with the following environment variable: " + signingKeyFileEnvKey

	signingKeyPasswordFlagName  = "signingkey-password"
	signingKeyPasswordEnvKey    = "DID_METHOD_CLI_SIGNINGKEY_PASSWORD" //nolint: gosec
	signingKeyPasswordFlagUsage = "signing key pem password. " +
		" Alternatively, this can be set with the following environment variable: " + signingKeyPasswordEnvKey

	nextUpdateKeyFlagName  = "nextupdatekey"
	nextUpdateKeyEnvKey    = "DID_METHOD_CLI_NEXTUPDATEKEY"
	nextUpdateKeyFlagUsage = "The public key PEM used for creating commitment for next update of the index document." +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyEnvKey

	nextUpdateKeyFileFlagName  = "nextupdatekey-file"
	nextUpdateKeyFileEnvKey    = "DID_METHOD_CLI_NEXTUPDATEKEY_FILE"
	nextUpdateKeyFileFlagUsage = "The file that contains the public key" +
		" PEM used for creating commitment for next update of the index document. " +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyFileEnvKey
)

// GetUpdateDIDCmd returns the Cobra update did command.
func GetUpdateDIDCmd() *cobra.Command {
	updateDIDCmd := updateDIDCmd()

	createFlags(updateDIDCmd)

	return updateDIDCmd
}

func updateDIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update-did",
		Short: "Update TrustBloc DID",
		Long:  "Update TrustBloc DID",
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCAs, err := getRootCAs(cmd)
			if err != nil {
				return err
			}

			didURI, err := cmdutils.GetUserSetVarFromString(cmd, didURIFlagName,
				didURIEnvKey, false)
			if err != nil {
				return err
			}

			sidetreeWriteToken := cmdutils.GetUserSetOptionalVarFromString(cmd, sidetreeWriteTokenFlagName,
				sidetreeWriteTokenEnvKey)

			domain := cmdutils.GetUserSetOptionalVarFromString(cmd, domainFlagName,
				domainFileEnvKey)

			client := did.New(did.WithAuthToken(sidetreeWriteToken),
				did.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}))

			opts, err := updateDIDOption(cmd)
			if err != nil {
				return err
			}

			err = client.UpdateDID(didURI, domain, opts...)
			if err != nil {
				return fmt.Errorf("failed to update did: %w", err)
			}

			fmt.Printf("successfully updated DID %s", didURI)

			return nil
		},
	}
}

func getSidetreeURL(cmd *cobra.Command) []update.Option {
	var opts []update.Option

	sidetreeURL := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLFlagName,
		sidetreeURLEnvKey)

	for _, v := range sidetreeURL {
		opts = append(opts, update.WithSidetreeEndpoint(v))
	}

	return opts
}

func updateDIDOption(cmd *cobra.Command) ([]update.Option, error) {
	opts, err := getPublicKeys(cmd)
	if err != nil {
		return nil, err
	}

	signingKey, err := common.GetKey(cmd, signingKeyFlagName, signingKeyEnvKey, signingKeyFileFlagName,
		signingKeyFileEnvKey, []byte(cmdutils.GetUserSetOptionalVarFromString(cmd, signingKeyPasswordFlagName,
			signingKeyPasswordEnvKey)), true)
	if err != nil {
		return nil, err
	}

	opts = append(opts, update.WithSigningKey(signingKey))

	nextUpdateKey, err := common.GetKey(cmd, nextUpdateKeyFlagName, nextUpdateKeyEnvKey, nextUpdateKeyFileFlagName,
		nextUpdateKeyFileEnvKey, nil, false)
	if err != nil {
		return nil, err
	}

	opts = append(opts, update.WithNextUpdatePublicKey(nextUpdateKey))

	serviceOpts, err := getServices(cmd)
	if err != nil {
		return nil, err
	}

	opts = append(opts, serviceOpts...)

	opts = append(opts, getSidetreeURL(cmd)...)

	opts = append(opts, getRemovePublicKeyID(cmd)...)

	opts = append(opts, getRemoveServiceID(cmd)...)

	return opts, nil
}

func getServices(cmd *cobra.Command) ([]update.Option, error) {
	serviceFile := cmdutils.GetUserSetOptionalVarFromString(cmd, addServiceFileFlagName,
		addServiceFileEnvKey)

	var opts []update.Option

	if serviceFile != "" {
		services, err := common.GetServices(serviceFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get services from file %w", err)
		}

		for i := range services {
			opts = append(opts, update.WithAddService(&services[i]))
		}
	}

	return opts, nil
}

func getPublicKeys(cmd *cobra.Command) ([]update.Option, error) {
	publicKeyFile := cmdutils.GetUserSetOptionalVarFromString(cmd, addPublicKeyFileFlagName,
		addPublicKeyFileEnvKey)

	var opts []update.Option

	if publicKeyFile != "" {
		publicKeys, err := common.GetPublicKeysFromFile(publicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get public keys from file %w", err)
		}

		for i := range publicKeys {
			opts = append(opts, update.WithAddPublicKey(&publicKeys[i]))
		}
	}

	return opts, nil
}

func getRemoveServiceID(cmd *cobra.Command) []update.Option {
	var opts []update.Option

	removeServices := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, removeServiceIDFlagName,
		removeServiceIDEnvKey)

	for _, v := range removeServices {
		opts = append(opts, update.WithRemoveService(v))
	}

	return opts
}

func getRemovePublicKeyID(cmd *cobra.Command) []update.Option {
	var opts []update.Option

	removePublicKeys := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, removePublicKeyIDFlagName,
		removePublicKeyIDEnvKey)

	for _, v := range removePublicKeys {
		opts = append(opts, update.WithRemovePublicKey(v))
	}

	return opts
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
	startCmd.Flags().StringP(didURIFlagName, "", "", didURIFlagUsage)
	startCmd.Flags().StringP(domainFlagName, "", "", domainFileFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(addPublicKeyFileFlagName, "", "", addPublicKeyFileFlagUsage)
	startCmd.Flags().StringP(addServiceFileFlagName, "", "", addServiceFlagUsage)
	startCmd.Flags().StringP(signingKeyFlagName, "", "", signingKeyFlagUsage)
	startCmd.Flags().StringP(signingKeyFileFlagName, "", "", signingKeyFileFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFlagName, "", "", nextUpdateKeyFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFileFlagName, "", "", nextUpdateKeyFileFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLFlagName, "", []string{}, sidetreeURLFlagUsage)
	startCmd.Flags().StringArrayP(removePublicKeyIDFlagName, "", []string{}, removePublicKeyIDFlagUsage)
	startCmd.Flags().StringArrayP(removeServiceIDFlagName, "", []string{}, removeServiceIDFlagUsage)
	startCmd.Flags().StringP(signingKeyPasswordFlagName, "", "", signingKeyPasswordFlagUsage)
}
