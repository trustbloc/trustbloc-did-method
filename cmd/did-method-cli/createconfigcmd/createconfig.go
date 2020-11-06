/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createconfigcmd

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/spf13/cobra"
	gojose "github.com/square/go-jose/v3"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/trustbloc-did-method/pkg/did"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/didconfiguration"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

const (
	sidetreeURLFlagName  = "sidetree-url"
	sidetreeURLFlagUsage = "Sidetree url." +
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

	configFileFlagName  = "config-file"
	configFileEnvKey    = "DID_METHOD_CLI_CONFIG_FILE"
	configFileFlagUsage = "Config file include data required for creating well known config files " +
		" Alternatively, this can be set with the following environment variable: " + configFileEnvKey

	outputDirectoryFlagName  = "output-directory"
	outputDirectoryEnvKey    = "DID_METHOD_CLI_OUTPUT_DIRECTORY"
	outputDirectoryFlagUsage = "Output directory " +
		" Alternatively, this can be set with the following environment variable: " + outputDirectoryEnvKey

	recoveryKeyFlagName  = "recoverykey"
	recoveryKeyEnvKey    = "DID_METHOD_CLI_RECOVERYKEY"
	recoveryKeyFlagUsage = "The public key PEM used for recovery of the document. " +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyEnvKey

	recoveryKeyFileFlagName  = "recoverykey-file"
	recoveryKeyFileEnvKey    = "DID_METHOD_CLI_RECOVERYKEY_FILE"
	recoveryKeyFileFlagUsage = "The file that contains the public key PEM used for recovery of the document. " +
		" Alternatively, this can be set with the following environment variable: " + recoveryKeyFileEnvKey

	updateKeyFlagName  = "updatekey"
	updateKeyEnvKey    = "DID_METHOD_CLI_UPDATEKEY"
	updateKeyFlagUsage = "The public key PEM used for validating the signature of the next update of the document. " +
		" Alternatively, this can be set with the following environment variable: " + updateKeyEnvKey

	updateKeyFileFlagName  = "updatekey-file"
	updateKeyFileEnvKey    = "DID_METHOD_CLI_UPDATEKEY_FILE"
	updateKeyFileFlagUsage = "The file that contains the public key PEM used for" +
		" validating the signature of the next update of the document " +
		" Alternatively, this can be set with the following environment variable: " + updateKeyFileEnvKey
)

type config struct {
	ConsortiumData consortiumData `json:"consortium_data,omitempty"`
	MembersData    []*memberData  `json:"members_data,omitempty"`
}

type consortiumData struct {
	// Domain is the domain name of the consortium
	Domain string `json:"domain,omitempty"`
	// Policy contains the consortium policy configuration
	Policy models.ConsortiumPolicy `json:"policy"`
}

type memberData struct {
	// Domain is the domain name of the member
	Domain string `json:"domain,omitempty"`
	// Policy contains stakeholder-specific configuration settings
	Policy models.StakeholderSettings `json:"policy"`
	// Endpoints is a list of sidetree endpoints owned by this stakeholder organization
	Endpoints []string `json:"endpoints"`
	// PrivateKeyJwk is privatekey jwk file
	PrivateKeyJwkPath string `json:"privateKeyJwkPath,omitempty"`

	jsonWebKey gojose.JSONWebKey
	sigKey     gojose.SigningKey
}

type didClient interface {
	CreateDID(domain string, opts ...did.CreateDIDOption) (*docdid.Doc, error)
}

type parameters struct {
	sidetreeURL string
	didClient   didClient
	config      *config
	recoveryKey crypto.PublicKey
	updateKey   crypto.PublicKey
}

// GetCreateConfigCmd returns the Cobra create conifg command.
func GetCreateConfigCmd() *cobra.Command {
	createConfigCmd := createCreateConfigCmd()

	createFlags(createConfigCmd)

	return createConfigCmd
}

func createCreateConfigCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create-config",
		Short: "Create did method config file",
		Long:  "Create did method config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			sidetreeURL, err := cmdutils.GetUserSetVarFromString(cmd, sidetreeURLFlagName, sidetreeURLEnvKey,
				false)
			if err != nil {
				return err
			}

			rootCAs, err := getRootCAs(cmd)
			if err != nil {
				return err
			}

			sidetreeWriteToken := cmdutils.GetUserSetOptionalVarFromString(cmd, sidetreeWriteTokenFlagName,
				sidetreeWriteTokenEnvKey)

			outputDirectory := cmdutils.GetUserSetOptionalVarFromString(cmd, outputDirectoryFlagName,
				outputDirectoryEnvKey)

			config, err := getConfig(cmd)
			if err != nil {
				return err
			}

			recoveryKey, err := getKey(cmd, recoveryKeyFlagName, recoveryKeyEnvKey, recoveryKeyFileFlagName,
				recoveryKeyFileEnvKey)
			if err != nil {
				return err
			}

			updateKey, err := getKey(cmd, updateKeyFlagName, updateKeyEnvKey, updateKeyFileFlagName,
				updateKeyFileEnvKey)
			if err != nil {
				return err
			}

			parameters := &parameters{
				sidetreeURL: strings.TrimSpace(sidetreeURL),
				didClient: did.New(did.WithAuthToken(sidetreeWriteToken),
					did.WithTLSConfig(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12})),
				config:      config,
				recoveryKey: recoveryKey,
				updateKey:   updateKey,
			}

			filesData, didConfData, err := createConfig(parameters)
			if err != nil {
				return err
			}

			return writeFiles(outputDirectory, filesData, didConfData)
		},
	}
}

func writeFiles(outputDirectory string, filesData, didConfData map[string][]byte) error {
	err := os.RemoveAll(outputDirectory)
	if err != nil {
		return fmt.Errorf("remove outputDirectory: %w", err)
	}

	err = writeConfig(outputDirectory, filesData)
	if err != nil {
		return err
	}

	return writeDIDConfiguration(outputDirectory, didConfData)
}

func getKey(cmd *cobra.Command, keyFlagName, keyEnvKey, keyFileFlagName,
	keyFileEnvKey string) (crypto.PublicKey, error) {
	keyString := cmdutils.GetUserSetOptionalVarFromString(cmd, keyFlagName,
		keyEnvKey)

	keyFile := cmdutils.GetUserSetOptionalVarFromString(cmd, keyFileFlagName,
		keyFileEnvKey)

	if keyString == "" && keyFile == "" {
		return nil, fmt.Errorf("either key (--%s) or key file (--%s) is required", keyFlagName, keyFileFlagName)
	}

	if keyString != "" && keyFile != "" {
		return nil, fmt.Errorf("only one of key (--%s) or key file (--%s) may be specified", keyFlagName, keyFileFlagName)
	}

	if keyFile != "" {
		return publicKeyFromFile(keyFile)
	}

	return publicKeyFromPEM([]byte(keyString))
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

func writeConfig(outputDirectory string, filesData map[string][]byte) error {
	if outputDirectory != "" {
		if err := os.MkdirAll(outputDirectory, 0755); err != nil { //nolint: gosec
			return err
		}
	}

	if err := os.MkdirAll(path.Join(outputDirectory, "did-trustbloc"), 0755); err != nil { //nolint: gosec
		return err
	}

	for k, v := range filesData {
		err := ioutil.WriteFile(path.Join(outputDirectory, "did-trustbloc", k+".json"), v, 0644) //nolint: gosec
		if err != nil {
			return fmt.Errorf("failed to write file %w", err)
		}
	}

	return nil
}

func createDIDConfiguration(domain, didID string, expiryTime int64,
	signiningKeys ...*gojose.SigningKey) ([]byte, error) {
	conf, err := didconfiguration.CreateDIDConfiguration(domain, didID, expiryTime, signiningKeys...)
	if err != nil {
		return nil, err
	}

	return json.Marshal(conf)
}

func writeDIDConfiguration(outputDirectory string, filesData map[string][]byte) error {
	if outputDirectory != "" {
		if err := os.MkdirAll(outputDirectory, 0755); err != nil { //nolint: gosec
			return err
		}
	}

	for domain, data := range filesData {
		if err := os.MkdirAll(path.Join(outputDirectory, domain), 0755); err != nil { //nolint: gosec
			return err
		}

		err := ioutil.WriteFile(path.Join(outputDirectory, domain, "did-configuration.json"), data, 0644) //nolint: gosec
		if err != nil {
			return fmt.Errorf("failed to write file %w", err)
		}
	}

	return nil
}

func getConfig(cmd *cobra.Command) (*config, error) {
	configFile, err := cmdutils.GetUserSetVarFromString(cmd, configFileFlagName,
		configFileEnvKey, false)
	if err != nil {
		return nil, err
	}

	data, err := ioutil.ReadFile(configFile) //nolint: gosec
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s' : %w", configFile, err)
	}

	var conf config

	if err := json.Unmarshal(data, &conf); err != nil {
		return nil, fmt.Errorf("failed unmarshal to config %w", err)
	}

	for _, member := range conf.MembersData {
		jwkData, err := ioutil.ReadFile(filepath.Clean(member.PrivateKeyJwkPath))
		if err != nil {
			return nil, fmt.Errorf("failed to read jwk file '%s' : %w", member.PrivateKeyJwkPath, err)
		}

		if err := member.jsonWebKey.UnmarshalJSON(jwkData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal to jwk: %w", err)
		}
		// TODO add support for ECDSA using P-256 and SHA-256
		member.sigKey = gojose.SigningKey{Key: member.jsonWebKey.Key, Algorithm: gojose.EdDSA}
	}

	return &conf, nil
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
	startCmd.Flags().StringP(sidetreeURLFlagName, "", "", sidetreeURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(configFileFlagName, "", "", configFileFlagUsage)
	startCmd.Flags().StringP(outputDirectoryFlagName, "", "", outputDirectoryFlagUsage)
	startCmd.Flags().StringP(recoveryKeyFlagName, "", "", recoveryKeyFlagUsage)
	startCmd.Flags().StringP(recoveryKeyFileFlagName, "", "", recoveryKeyFileFlagUsage)
	startCmd.Flags().StringP(updateKeyFlagName, "", "", updateKeyFlagUsage)
	startCmd.Flags().StringP(updateKeyFileFlagName, "", "", updateKeyFileFlagUsage)
}

func createConfig(parameters *parameters) (map[string][]byte, map[string][]byte, error) { //nolint: funlen
	filesData := make(map[string][]byte)
	sigKeys := make([]gojose.SigningKey, 0)

	didConfData := make(map[string][]byte)

	consortium := models.Consortium{Domain: parameters.config.ConsortiumData.Domain,
		Policy: parameters.config.ConsortiumData.Policy}

	for _, member := range parameters.config.MembersData {
		didDoc, err := createDID(parameters.didClient, parameters.sidetreeURL, &member.jsonWebKey, parameters.recoveryKey,
			parameters.updateKey)
		if err != nil {
			return nil, nil, err
		}

		pubKey, err := member.jsonWebKey.Public().MarshalJSON()
		if err != nil {
			return nil, nil, err
		}

		consortium.Members = append(consortium.Members, &models.StakeholderListElement{Domain: member.Domain,
			DID: didDoc.ID, PublicKey: models.PublicKey{ID: didDoc.ID + "#" + member.jsonWebKey.KeyID,
				JWK: pubKey}})

		stakeholder := models.Stakeholder{Domain: member.Domain, DID: didDoc.ID,
			Policy: member.Policy, Endpoints: member.Endpoints}

		stakeholderBytes, err := json.Marshal(stakeholder)
		if err != nil {
			return nil, nil, err
		}

		jws, err :=
			signConfig(stakeholderBytes, []gojose.SigningKey{member.sigKey})
		if err != nil {
			return nil, nil, err
		}

		sigKeys = append(sigKeys, member.sigKey)

		filesData[member.Domain] = []byte(jws)

		didConf, err := createDIDConfiguration(member.Domain, didDoc.ID, 0, &member.sigKey)
		if err != nil {
			return nil, nil, fmt.Errorf("did configuration failed %w: ", err)
		}

		didConfData[member.Domain] = didConf
	}

	consortiumBytes, err := json.Marshal(consortium)
	if err != nil {
		return nil, nil, err
	}

	jws, err := signConfig(consortiumBytes, sigKeys)
	if err != nil {
		return nil, nil, err
	}

	filesData[consortium.Domain] = []byte(jws)

	return filesData, didConfData, nil
}

func signConfig(configBytes []byte, keys []gojose.SigningKey) (string, error) {
	signer, err := gojose.NewMultiSigner(keys, nil)
	if err != nil {
		return "", err
	}

	jws, err := signer.Sign(configBytes)
	if err != nil {
		return "", err
	}

	return jws.FullSerialize(), nil
}

func createDID(didClient didClient, sidetreeURL string, jwk *gojose.JSONWebKey, recoveryKey,
	updateKey crypto.PublicKey) (*docdid.Doc, error) {
	pkBytes, err := jwk.MarshalJSON()
	if err != nil {
		return nil, err
	}

	general := did.PublicKey{
		ID:       jwk.KeyID,
		Type:     did.JWSVerificationKey2020,
		Encoding: did.PublicKeyEncodingJwk,
		KeyType:  did.Ed25519KeyType,
		Value:    pkBytes,
		Purposes: []string{did.KeyPurposeVerificationMethod},
	}

	return didClient.CreateDID("", did.WithSidetreeEndpoint(sidetreeURL),
		did.WithRecoveryPublicKey(recoveryKey),
		did.WithUpdatePublicKey(updateKey),
		did.WithPublicKey(&general))
}
