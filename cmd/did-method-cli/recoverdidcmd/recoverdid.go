/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package recoverdidcmd

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
	"github.com/trustbloc/trustbloc-did-method/pkg/did/option/recovery"
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

	publicKeyFileFlagName  = "publickey-file"
	publicKeyFileEnvKey    = "DID_METHOD_CLI_PUBLICKEY_FILE"
	publicKeyFileFlagUsage = "publickey file include public keys for Trustbloc DID " +
		" Alternatively, this can be set with the following environment variable: " + publicKeyFileEnvKey

	serviceFileFlagName = "service-file"
	serviceFileEnvKey   = "DID_METHOD_CLI_SERVICE_FILE"
	serviceFlagUsage    = "publickey file include services for Trustbloc DID " +
		" Alternatively, this can be set with the following environment variable: " + serviceFileEnvKey

	signingKeyFlagName  = "signingkey"
	signingKeyEnvKey    = "DID_METHOD_CLI_SIGNINGKEY"
	signingKeyFlagUsage = "The private key PEM used for signing the recovery request." +
		" Alternatively, this can be set with the following environment variable: " + signingKeyEnvKey

	signingKeyFileFlagName  = "signingkey-file"
	signingKeyFileEnvKey    = "DID_METHOD_CLI_SIGNINGKEY_FILE"
	signingKeyFileFlagUsage = "The file that contains the private key" +
		" PEM used for signing the recovery request" +
		" Alternatively, this can be set with the following environment variable: " + signingKeyFileEnvKey

	signingKeyPasswordFlagName  = "signingkey-password"
	signingKeyPasswordEnvKey    = "DID_METHOD_CLI_SIGNINGKEY_PASSWORD" //nolint: gosec
	signingKeyPasswordFlagUsage = "signing key pem password. " +
		" Alternatively, this can be set with the following environment variable: " + signingKeyPasswordEnvKey

	nextUpdateKeyFlagName  = "nextupdatekey"
	nextUpdateKeyEnvKey    = "DID_METHOD_CLI_NEXTUPDATEKEY"
	nextUpdateKeyFlagUsage = "The public key PEM used for creating commitment for next update of the did doc." +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyEnvKey

	nextUpdateKeyFileFlagName  = "nextupdatekey-file"
	nextUpdateKeyFileEnvKey    = "DID_METHOD_CLI_NEXTUPDATEKEY_FILE"
	nextUpdateKeyFileFlagUsage = "The file that contains the public key" +
		" PEM used for creating commitment for next update of the did doc. " +
		" Alternatively, this can be set with the following environment variable: " + nextUpdateKeyFileEnvKey

	nextRecoveryKeyFlagName  = "nextrecoverykey"
	nextRecoveryKeyEnvKey    = "DID_METHOD_CLI_NEXTRECOVERYKEY"
	nextRecoveryKeyFlagUsage = "The public key PEM used for creating commitment for next recover of the did doc." +
		" Alternatively, this can be set with the following environment variable: " + nextRecoveryKeyEnvKey

	nextRecoveryKeyFileFlagName  = "nextrecoverkey-file"
	nextRecoveryKeyFileEnvKey    = "DID_METHOD_CLI_NEXTRECOVERYKEY_FILE"
	nextRecoveryKeyFileFlagUsage = "The file that contains the public key" +
		" PEM used for creating commitment for next recover of the did doc. " +
		" Alternatively, this can be set with the following environment variable: " + nextRecoveryKeyFileEnvKey
)

// GetRecoverDIDCmd returns the Cobra recover did command.
func GetRecoverDIDCmd() *cobra.Command {
	recoverDIDCmd := recoverDIDCmd()

	createFlags(recoverDIDCmd)

	return recoverDIDCmd
}

func recoverDIDCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "recover-did",
		Short: "Recover TrustBloc DID",
		Long:  "Recover TrustBloc DID",
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

			opts, err := recoverDIDOption(cmd)
			if err != nil {
				return err
			}

			err = client.RecoverDID(didURI, domain, opts...)
			if err != nil {
				return fmt.Errorf("failed to recover did: %w", err)
			}

			fmt.Printf("successfully recoverd DID %s", didURI)

			return nil
		},
	}
}

func getSidetreeURL(cmd *cobra.Command) []recovery.Option {
	var opts []recovery.Option

	sidetreeURL := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, sidetreeURLFlagName,
		sidetreeURLEnvKey)

	for _, v := range sidetreeURL {
		opts = append(opts, recovery.WithSidetreeEndpoint(v))
	}

	return opts
}

func recoverDIDOption(cmd *cobra.Command) ([]recovery.Option, error) {
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

	opts = append(opts, recovery.WithSigningKey(signingKey))

	nextUpdateKey, err := common.GetKey(cmd, nextUpdateKeyFlagName, nextUpdateKeyEnvKey, nextUpdateKeyFileFlagName,
		nextUpdateKeyFileEnvKey, nil, false)
	if err != nil {
		return nil, err
	}

	opts = append(opts, recovery.WithNextUpdatePublicKey(nextUpdateKey))

	nextRecoveryKey, err := common.GetKey(cmd, nextRecoveryKeyFlagName, nextRecoveryKeyEnvKey,
		nextRecoveryKeyFileFlagName, nextUpdateKeyFileEnvKey, nil, false)
	if err != nil {
		return nil, err
	}

	opts = append(opts, recovery.WithNextRecoveryPublicKey(nextRecoveryKey))

	serviceOpts, err := getServices(cmd)
	if err != nil {
		return nil, err
	}

	opts = append(opts, serviceOpts...)

	opts = append(opts, getSidetreeURL(cmd)...)

	return opts, nil
}

func getServices(cmd *cobra.Command) ([]recovery.Option, error) {
	serviceFile := cmdutils.GetUserSetOptionalVarFromString(cmd, serviceFileFlagName,
		serviceFileEnvKey)

	var opts []recovery.Option

	if serviceFile != "" {
		services, err := common.GetServices(serviceFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get services from file %w", err)
		}

		for i := range services {
			opts = append(opts, recovery.WithService(&services[i]))
		}
	}

	return opts, nil
}

func getPublicKeys(cmd *cobra.Command) ([]recovery.Option, error) {
	publicKeyFile := cmdutils.GetUserSetOptionalVarFromString(cmd, publicKeyFileFlagName,
		publicKeyFileEnvKey)

	var opts []recovery.Option

	if publicKeyFile != "" {
		publicKeys, err := common.GetPublicKeysFromFile(publicKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to get public keys from file %w", err)
		}

		for i := range publicKeys {
			opts = append(opts, recovery.WithPublicKey(&publicKeys[i]))
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
	startCmd.Flags().StringP(didURIFlagName, "", "", didURIFlagUsage)
	startCmd.Flags().StringP(domainFlagName, "", "", domainFileFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(publicKeyFileFlagName, "", "", publicKeyFileFlagUsage)
	startCmd.Flags().StringP(serviceFileFlagName, "", "", serviceFlagUsage)
	startCmd.Flags().StringArrayP(sidetreeURLFlagName, "", []string{}, sidetreeURLFlagUsage)
	startCmd.Flags().StringP(signingKeyFlagName, "", "", signingKeyFlagUsage)
	startCmd.Flags().StringP(signingKeyFileFlagName, "", "", signingKeyFileFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFlagName, "", "", nextUpdateKeyFlagUsage)
	startCmd.Flags().StringP(nextUpdateKeyFileFlagName, "", "", nextUpdateKeyFileFlagUsage)
	startCmd.Flags().StringP(signingKeyPasswordFlagName, "", "", signingKeyPasswordFlagUsage)
	startCmd.Flags().StringP(nextRecoveryKeyFlagName, "", "", nextRecoveryKeyFlagUsage)
	startCmd.Flags().StringP(nextRecoveryKeyFileFlagName, "", "", nextRecoveryKeyFileFlagUsage)
}
