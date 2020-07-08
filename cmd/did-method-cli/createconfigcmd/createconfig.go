/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package createconfigcmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"strings"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/spf13/cobra"
	gojose "github.com/square/go-jose/v3"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/trustbloc-did-method/pkg/did"
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
	outputDirectoryEnvKey    = "DID_METHOD_CLI_OUTPUT_DIRECTORY" //nolint: gosec
	outputDirectoryFlagUsage = "Output directory " +
		" Alternatively, this can be set with the following environment variable: " + outputDirectoryEnvKey
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

			sidetreeWriteToken, err := cmdutils.GetUserSetVarFromString(cmd, sidetreeWriteTokenFlagName,
				sidetreeWriteTokenEnvKey, true)
			if err != nil {
				return err
			}

			outputDirectory, err := cmdutils.GetUserSetVarFromString(cmd, outputDirectoryFlagName,
				outputDirectoryEnvKey, true)
			if err != nil {
				return err
			}

			config, err := getConfig(cmd)
			if err != nil {
				return err
			}

			parameters := &parameters{
				sidetreeURL: strings.TrimSpace(sidetreeURL),
				didClient: did.New(did.WithAuthToken(sidetreeWriteToken),
					did.WithTLSConfig(&tls.Config{RootCAs: rootCAs})),
				config: config,
			}

			filesData, err := createConfig(parameters)
			if err != nil {
				return err
			}

			return writeConfig(outputDirectory, filesData)
		},
	}
}

func writeConfig(outputDirectory string, filesData map[string][]byte) error {
	if outputDirectory != "" {
		if err := os.MkdirAll(outputDirectory, 0700); err != nil {
			return err
		}
	}

	for k, v := range filesData {
		err := ioutil.WriteFile(path.Join(outputDirectory, k+".json"), v, 0644)
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

	var config config

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed unmarshal to config %w", err)
	}

	for _, member := range config.MembersData {
		jwkData, err := ioutil.ReadFile(member.PrivateKeyJwkPath) //nolint: gosec
		if err != nil {
			return nil, fmt.Errorf("failed to read jwk file '%s' : %w", member.PrivateKeyJwkPath, err)
		}

		if err := member.jsonWebKey.UnmarshalJSON(jwkData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal to jwk: %w", err)
		}
		// TODO add support for ECDSA using P-256 and SHA-256
		member.sigKey = gojose.SigningKey{Key: member.jsonWebKey.Key, Algorithm: gojose.EdDSA}
	}

	return &config, nil
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

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(sidetreeURLFlagName, "", "", sidetreeURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, "", "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, "", []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(configFileFlagName, "", "", configFileFlagUsage)
	startCmd.Flags().StringP(outputDirectoryFlagName, "", "", outputDirectoryFlagUsage)
}

func createConfig(parameters *parameters) (map[string][]byte, error) {
	filesData := make(map[string][]byte)
	sigKeys := make([]gojose.SigningKey, 0)

	consortium := models.Consortium{Domain: parameters.config.ConsortiumData.Domain,
		Policy: parameters.config.ConsortiumData.Policy}

	for _, member := range parameters.config.MembersData {
		didDoc, err := createDID(parameters.didClient, parameters.sidetreeURL, &member.jsonWebKey)
		if err != nil {
			return nil, err
		}

		pubKey, err := member.jsonWebKey.Public().MarshalJSON()
		if err != nil {
			return nil, err
		}

		consortium.Members = append(consortium.Members, &models.StakeholderListElement{Domain: member.Domain,
			DID: didDoc.ID, PublicKey: models.PublicKey{ID: didDoc.ID + "#" + member.jsonWebKey.KeyID,
				JWK: pubKey}})

		stakeholder := models.Stakeholder{Domain: member.Domain, DID: didDoc.ID,
			Policy: member.Policy, Endpoints: member.Endpoints}

		stakeholderBytes, err := json.Marshal(stakeholder)
		if err != nil {
			return nil, err
		}

		jws, err := signConfig(stakeholderBytes, []gojose.SigningKey{member.sigKey})
		if err != nil {
			return nil, err
		}

		sigKeys = append(sigKeys, member.sigKey)

		filesData[member.Domain] = []byte(jws)
	}

	consortiumBytes, err := json.Marshal(consortium)
	if err != nil {
		return nil, err
	}

	jws, err := signConfig(consortiumBytes, sigKeys)
	if err != nil {
		return nil, err
	}

	filesData[consortium.Domain] = []byte(jws)

	return filesData, nil
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

func createDID(didClient didClient, sidetreeURL string, jwk *gojose.JSONWebKey) (*docdid.Doc, error) {
	pubKey, err := jwk.Public().MarshalJSON()
	if err != nil {
		return nil, err
	}


	// TODO: Verify usage of this code - recovery, update and general purpose key should NOT be the same
	return didClient.CreateDID("", did.WithSidetreeEndpoint(sidetreeURL), did.WithPublicKey(&did.PublicKey{
		Type: did.Ed25519VerificationKey2018, Encoding: did.PublicKeyEncodingJwk, Value: pubKey, Recovery: true}),
		did.WithPublicKey(&did.PublicKey{
			Type: did.Ed25519VerificationKey2018, Encoding: did.PublicKeyEncodingJwk, Value: pubKey, Update: true}),
		did.WithPublicKey(&did.PublicKey{ID: jwk.KeyID,
			Type: did.JWSVerificationKey2020, Encoding: did.PublicKeyEncodingJwk, KeyType: did.Ed25519KeyType,
			Value:   pubKey,
			Purpose: []string{did.KeyPurposeGeneral}}))
}
