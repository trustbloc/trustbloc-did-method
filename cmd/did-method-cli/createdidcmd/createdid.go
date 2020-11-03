/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createdidcmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/spf13/cobra"
	gojose "github.com/square/go-jose/v3"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/trustbloc-did-method/pkg/did"
	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
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
	recoveryKeyFlagUsage = "The public key PEM used for recovery of the document. Example: --recoverykey 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEXlp4fWF5rgLthKr20tsJ0tBIE6UmrGuAC8iVG/DaedkSt7HihCx/t2BGjooduaKwEIOmPjx2zBsbkbFrYhhnVw' " +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyEnvKey

	recoveryKeyFileFlagName  = "recoverykey-file"
	recoveryKeyFileEnvKey    = "DID_METHOD_CLI_RECOVERYKEY_FILE"
	recoveryKeyFileFlagUsage = "The file that contains the public key PEM used for recovery of the document. Example: --recoverykeyfile ./recovery_public.key " +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyFileEnvKey

	updateKeyFlagName  = "updatekey"
	updateKeyEnvKey    = "DID_METHOD_CLI_UPDATEKEY"
	updateKeyFlagUsage = "The public key PEM used for validating the signature of the next update of the document. Example: --updatekey 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFMy2n9jYZChYSjdhK9vUWvPjz9tzBcEa13Ye33haxFsT//3kGxOQhI7yb3MJsDvwLtdfLL6txM3RdOrmLABBvw' " +
		" Alternatively, this can be set with the following environment variable: " + updateKeyEnvKey

	updateKeyFileFlagName  = "updatekey-file"
	updateKeyFileEnvKey    = "DID_METHOD_CLI_UPDATEKEY_FILE"
	updateKeyFileFlagUsage = "The file that contains the public key PEM used for validating the signature of the next update of the document. Example: --updatekeyfile ./update_public.key " +
		" Alternatively, this can be set with the following environment variable: " + updateKeyFileEnvKey
)

type publicKey struct {
	Type     string   `json:"type,omitempty"`
	Purposes []string `json:"purposes,omitempty"`
	JWKPath  string   `json:"jwkPath,omitempty"`
}

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

			sidetreeWriteToken, err := cmdutils.GetUserSetVarFromString(cmd, sidetreeWriteTokenFlagName,
				sidetreeWriteTokenEnvKey, true)
			if err != nil {
				return err
			}

			domain, err := cmdutils.GetUserSetVarFromString(cmd, domainFlagName,
				domainFileEnvKey, true)
			if err != nil {
				return err
			}

			client := did.New(did.WithAuthToken(sidetreeWriteToken),
				did.WithTLSConfig(&tls.Config{RootCAs: rootCAs}))

			opts, err := createDIDOption(cmd)
			if err != nil {
				return err
			}

			doc, err := client.CreateDID(domain, opts...)
			if err != nil {
				return err
			}

			bytes, err := doc.JSONBytes()
			if err != nil {
				return err
			}

			fmt.Println(string(bytes))

			return nil
		},
	}
}

func getSidetreeURL(cmd *cobra.Command) ([]did.CreateDIDOption, error) {
	var opts []did.CreateDIDOption

	sidetreeURL, err := cmdutils.GetUserSetVarFromArrayString(cmd, sidetreeURLFlagName,
		sidetreeURLEnvKey, true)
	if err != nil {
		return nil, err
	}

	for _, v := range sidetreeURL {
		opts = append(opts, did.WithSidetreeEndpoint(v))
	}

	return opts, nil
}

func createDIDOption(cmd *cobra.Command) ([]did.CreateDIDOption, error) {
	opts, err := getPublicKeys(cmd)
	if err != nil {
		return nil, err
	}

	recoveryKeyOpts, err := getKey(cmd, recoveryKeyFlagName, recoveryKeyEnvKey, recoveryKeyFileFlagName,
		recoveryKeyFileEnvKey, true, false)
	if err != nil {
		return nil, err
	}

	opts = append(opts, recoveryKeyOpts...)

	updateKeyOpts, err := getKey(cmd, updateKeyFlagName, updateKeyEnvKey, updateKeyFileFlagName,
		updateKeyFileEnvKey, false, true)
	if err != nil {
		return nil, err
	}

	opts = append(opts, updateKeyOpts...)

	serviceOpts, err := getServices(cmd)
	if err != nil {
		return nil, err
	}

	opts = append(opts, serviceOpts...)

	sidetreeURLOpts, err := getSidetreeURL(cmd)
	if err != nil {
		return nil, err
	}

	opts = append(opts, sidetreeURLOpts...)

	return opts, nil
}

func getServices(cmd *cobra.Command) ([]did.CreateDIDOption, error) {
	serviceFile, err := cmdutils.GetUserSetVarFromString(cmd, serviceFileFlagName,
		serviceFileEnvKey, false)
	if err != nil {
		return nil, err
	}

	svcData, err := ioutil.ReadFile(filepath.Clean(serviceFile))
	if err != nil {
		return nil, fmt.Errorf("failed to service file '%s' : %w", serviceFile, err)
	}

	var services []operation.Service
	if err := json.Unmarshal(svcData, &services); err != nil {
		return nil, err
	}

	var opts []did.CreateDIDOption

	for _, v := range services {
		opts = append(opts, did.WithService(&docdid.Service{ID: v.ID, Type: v.Type,
			Priority: v.Priority, RecipientKeys: v.RecipientKeys, RoutingKeys: v.RoutingKeys,
			ServiceEndpoint: v.Endpoint}))
	}

	return opts, nil
}

func getKey(cmd *cobra.Command, keyFlagName, keyEnvKey, keyFileFlagName, keyFileEnvKey string,
	recovery, update bool) ([]did.CreateDIDOption, error) {
	keyString, err := cmdutils.GetUserSetVarFromString(cmd, keyFlagName,
		keyEnvKey, true)
	if err != nil {
		return nil, err
	}

	keyFile, err := cmdutils.GetUserSetVarFromString(cmd, keyFileFlagName,
		keyFileEnvKey, true)
	if err != nil {
		return nil, err
	}

	if keyString == "" && keyFile == "" {
		return nil, fmt.Errorf("either key (--%s) or key file (--%s) is required", keyFlagName, keyFileFlagName)
	}

	if keyString != "" && keyFile != "" {
		return nil, fmt.Errorf("only one of key (--%s) or key file (--%s) may be specified", keyFlagName, keyFileFlagName)
	}

	var pubKey crypto.PublicKey
	if keyFile != "" {
		pubKey, err = publicKeyFromFile(keyFile)
		if err != nil {
			return nil, err
		}
	} else {
		pubKey, err = publicKeyFromPEM([]byte(keyString))
		if err != nil {
			return nil, err
		}
	}

	keyType := ""
	var value []byte

	switch key := pubKey.(type) {
	case ed25519.PublicKey:
		keyType = did.Ed25519KeyType
		value = []byte(fmt.Sprintf("%v", key))
	case *ecdsa.PublicKey:
		if key.Curve.Params().Name != elliptic.P256().Params().Name {
			return nil, fmt.Errorf("ec cruve %s key not supported", elliptic.P256().Params().Name)
		}

		keyType = did.P256KeyType
		value = elliptic.Marshal(key.Curve, key.X, key.Y)
	default:
		return nil, fmt.Errorf("key not supported")
	}

	var opts []did.CreateDIDOption

	opts = append(opts, did.WithPublicKey(&did.PublicKey{Value: value, Encoding: did.PublicKeyEncodingJwk,
		KeyType: keyType, Recovery: recovery, Update: update}))

	return opts, nil
}

func getPublicKeys(cmd *cobra.Command) ([]did.CreateDIDOption, error) {
	publicKeyFile, err := cmdutils.GetUserSetVarFromString(cmd, publicKeyFileFlagName,
		publicKeyFileEnvKey, true)
	if err != nil {
		return nil, err
	}

	if publicKeyFile == "" {
		return nil, nil
	}

	pkData, err := ioutil.ReadFile(filepath.Clean(publicKeyFile))
	if err != nil {
		return nil, fmt.Errorf("failed to public key file '%s' : %w", publicKeyFile, err)
	}

	var publicKeys []publicKey
	if err := json.Unmarshal(pkData, &publicKeys); err != nil {
		return nil, err
	}

	var opts []did.CreateDIDOption

	for _, v := range publicKeys {
		jwkData, err := ioutil.ReadFile(filepath.Clean(v.JWKPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read jwk file '%s' : %w", v.JWKPath, err)
		}

		var jsonWebKey gojose.JSONWebKey
		if err := jsonWebKey.UnmarshalJSON(jwkData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal to jwk: %w", err)
		}

		keyType := ""
		var value []byte

		switch key := jsonWebKey.Key.(type) {
		case ed25519.PublicKey:
			keyType = did.Ed25519KeyType
			value = []byte(fmt.Sprintf("%v", key))
		case *ecdsa.PublicKey:
			if key.Curve.Params().Name != elliptic.P256().Params().Name {
				return nil, fmt.Errorf("ec cruve %s key not supported", elliptic.P256().Params().Name)
			}
			keyType = did.P256KeyType
			value = elliptic.Marshal(key.Curve, key.X, key.Y)
		default:
			return nil, fmt.Errorf("key not supported")
		}

		opts = append(opts, did.WithPublicKey(&did.PublicKey{ID: jsonWebKey.KeyID, Type: v.Type,
			Value: value, Encoding: did.PublicKeyEncodingJwk, Purposes: v.Purposes, KeyType: keyType}))
	}

	return opts, nil
}

func getRootCAs(cmd *cobra.Command) (*x509.CertPool, error) {
	tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool := false
	if tlsSystemCertPoolString != "" {
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return nil, err
		}
	}

	tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey, true)
	if err != nil {
		return nil, err
	}

	return tlsutils.GetCertPool(tlsSystemCertPool, tlsCACerts)
}

func publicKeyFromFile(file string) (crypto.PublicKey, error) {
	keyBytes, err := ioutil.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}

	return publicKeyFromPEM(keyBytes)
}

func publicKeyFromPEM(pubKeyPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("public key not found in PEM")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := key.(crypto.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key")
	}

	return publicKey, nil
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
