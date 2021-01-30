/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/hyperledger/aries-framework-go-ext/component/vdr/trustbloc/models"
	"github.com/spf13/cobra"
	loglib "github.com/trustbloc/edge-core/pkg/log"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod"
	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/healthcheck"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the bloc did method instance on. Format: HostName:Port."
	hostURLEnvKey        = "DID_METHOD_HOST_URL"

	tlsSystemCertPoolFlagName      = "tls-systemcertpool"
	tlsSystemCertPoolFlagShorthand = "s"
	tlsSystemCertPoolFlagUsage     = "Use system certificate pool." +
		" Possible values [true] [false]. Defaults to false if not set." +
		" Alternatively, this can be set with the following environment variable: " + tlsSystemCertPoolEnvKey
	tlsSystemCertPoolEnvKey = "DID_METHOD_TLS_SYSTEMCERTPOOL"

	tlsCACertsFlagName      = "tls-cacerts"
	tlsCACertsFlagShorthand = "c"
	tlsCACertsFlagUsage     = "Comma-Separated list of ca certs path." +
		" Alternatively, this can be set with the following environment variable: " + tlsCACertsEnvKey
	tlsCACertsEnvKey = "DID_METHOD_TLS_CACERTS"

	domainFlagName      = "domain"
	domainFlagShorthand = "b"
	domainFlagUsage     = "domain"
	domainEnvKey        = "DID_METHOD_DOMAIN"

	modeFlagName      = "mode"
	modeFlagShorthand = "m"
	modeFlagUsage     = "Mode in which the did-method service will run. Possible values: " +
		"['registrar', 'resolver', 'combined'] (default: combined)."
	modeEnvKey = "DID_METHOD_MODE"

	sidetreeReadTokenFlagName  = "sidetree-read-token"
	sidetreeReadTokenEnvKey    = "SIDETREE_READ_TOKEN"
	sidetreeReadTokenFlagUsage = "The sidetree read token." +
		" Alternatively, this can be set with the following environment variable: " + sidetreeReadTokenEnvKey

	sidetreeWriteTokenFlagName  = "sidetree-write-token"
	sidetreeWriteTokenEnvKey    = "SIDETREE_WRITE_TOKEN" //nolint: gosec
	sidetreeWriteTokenFlagUsage = "The sidetree write token." +
		" Alternatively, this can be set with the following environment variable: " + sidetreeWriteTokenEnvKey

	enableSignaturesFlagName  = "enable-signatures"
	enableSignaturesEnvKey    = "ENABLE_SIGNATURES"
	enableSignaturesFlagUsage = "Enable signatures. Possible values [true] [false]. Defaults to true if not set." +
		" Alternatively, this can be set with the following environment variable: " + enableSignaturesEnvKey

	genesisFileFlagName  = "genesis-files"
	genesisFileEnvKey    = "GENESIS_FILES"
	genesisFileFlagUsage = "Comma-separated list of consortium config genesis file paths." +
		" Alternatively, this can be set with the following environment variable: " + genesisFileEnvKey
)

// nolint:gochecknoglobals
var log = loglib.New("did-method-rest/start")

// mode in which to run the did-method service
type mode string

const (
	registrar mode = "registrar"
	resolver  mode = "resolver"
	combined  mode = "combined"
)

type server interface {
	ListenAndServe(host string, router http.Handler) error
}

// HTTPServer represents an actual HTTP server implementation.
type HTTPServer struct{}

// ListenAndServe starts the server using the standard Go HTTP server implementation.
func (s *HTTPServer) ListenAndServe(host string, router http.Handler) error {
	return http.ListenAndServe(host, router)
}

type parameters struct {
	srv                server
	hostURL            string
	tlsSystemCertPool  bool
	tlsCACerts         []string
	blocDomain         string
	mode               string
	sidetreeReadToken  string
	sidetreeWriteToken string
	enableSignatures   bool
	genesisFiles       []string
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command {
	return &cobra.Command{
		Use:   "start",
		Short: "Start did-method",
		Long:  "Start did-method",
		RunE: func(cmd *cobra.Command, args []string) error {
			parameters, err := getParameters(cmd)
			if err != nil {
				return err
			}

			parameters.srv = srv

			return startDidMethod(parameters)
		},
	}
}

func getParameters(cmd *cobra.Command) (*parameters, error) {
	mode, err := getMode(cmd)
	if err != nil {
		return nil, err
	}

	hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
	if err != nil {
		return nil, err
	}

	tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
	if err != nil {
		return nil, err
	}

	genesisFiles := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, genesisFileFlagName,
		genesisFileEnvKey)

	blocDomain, err := cmdutils.GetUserSetVarFromString(cmd, domainFlagName, domainEnvKey,
		!isRegistrar(mode))
	if err != nil {
		return nil, err
	}

	sidetreeReadToken := cmdutils.GetUserSetOptionalVarFromString(cmd, sidetreeReadTokenFlagName,
		sidetreeReadTokenEnvKey)

	sidetreeWriteToken := cmdutils.GetUserSetOptionalVarFromString(cmd, sidetreeWriteTokenFlagName,
		sidetreeWriteTokenEnvKey)

	enableSignaturesString := cmdutils.GetUserSetOptionalVarFromString(cmd, enableSignaturesFlagName,
		enableSignaturesEnvKey)

	enableSignatures := true
	if enableSignaturesString != "" {
		enableSignatures, err = strconv.ParseBool(enableSignaturesString)
		if err != nil {
			return nil, err
		}
	}

	return &parameters{
		hostURL:            strings.TrimSpace(hostURL),
		tlsSystemCertPool:  tlsSystemCertPool,
		tlsCACerts:         tlsCACerts,
		blocDomain:         blocDomain,
		mode:               mode,
		sidetreeReadToken:  sidetreeReadToken,
		sidetreeWriteToken: sidetreeWriteToken,
		enableSignatures:   enableSignatures,
		genesisFiles:       genesisFiles,
	}, nil
}

func getTLS(cmd *cobra.Command) (bool, []string, error) {
	tlsSystemCertPoolString := cmdutils.GetUserSetOptionalVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey)

	tlsSystemCertPool := false

	if tlsSystemCertPoolString != "" {
		var err error
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)

		if err != nil {
			return false, nil, err
		}
	}

	tlsCACerts := cmdutils.GetUserSetOptionalVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey)

	return tlsSystemCertPool, tlsCACerts, nil
}

func getMode(cmd *cobra.Command) (string, error) {
	mode := cmdutils.GetUserSetOptionalVarFromString(cmd, modeFlagName, modeEnvKey)

	if !supportedMode(mode) {
		return "", fmt.Errorf("unsupported mode: %s", mode)
	}

	if mode == "" {
		mode = string(combined)
	}

	return mode, nil
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().StringP(tlsSystemCertPoolFlagName, tlsSystemCertPoolFlagShorthand, "",
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, tlsCACertsFlagShorthand, []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(domainFlagName, domainFlagShorthand, "", domainFlagUsage)
	startCmd.Flags().StringP(modeFlagName, modeFlagShorthand, "", modeFlagUsage)
	startCmd.Flags().StringP(sidetreeReadTokenFlagName, "", "", sidetreeReadTokenFlagUsage)
	startCmd.Flags().StringP(sidetreeWriteTokenFlagName, "", "", sidetreeWriteTokenFlagUsage)
	startCmd.Flags().StringP(enableSignaturesFlagName, "", "", enableSignaturesFlagUsage)
	startCmd.Flags().StringArray(genesisFileFlagName, nil, genesisFileFlagUsage)
}

func startDidMethod(parameters *parameters) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	genesisFiles, err := loadGenesisConfigs(parameters.genesisFiles)
	if err != nil {
		return err
	}

	didMethodService, err := didmethod.New(&operation.Config{TLSConfig: &tls.Config{RootCAs: rootCAs,
		MinVersion: tls.VersionTLS12}, BlocDomain: parameters.blocDomain, Mode: parameters.mode,
		SidetreeReadToken: parameters.sidetreeReadToken, SidetreeWriteToken: parameters.sidetreeWriteToken,
		EnableSignatures: parameters.enableSignatures, GenesisFiles: genesisFiles})
	if err != nil {
		return err
	}

	router := mux.NewRouter()

	// add health check endpoint
	healthCheckService := healthcheck.New()

	healthCheckHandlers := healthCheckService.GetOperations()
	for _, handler := range healthCheckHandlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	handlers := didMethodService.GetOperations()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return parameters.srv.ListenAndServe(parameters.hostURL, router)
}

func loadGenesisConfigs(genesisFilePaths []string) ([]operation.GenesisFileConfig, error) {
	if len(genesisFilePaths) == 0 {
		return nil, nil
	}

	var configs []operation.GenesisFileConfig

	for _, path := range genesisFilePaths {
		genesisFileBytes, err := ioutil.ReadFile(filepath.Clean(path))
		if err != nil {
			return nil, fmt.Errorf("reading genesis file: %w", err)
		}

		genesisFileData, err := models.ParseConsortium(genesisFileBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing genesis file: %w", err)
		}

		configs = append(configs, operation.GenesisFileConfig{
			URL:  genesisFileData.Config.Domain,
			Data: genesisFileBytes,
		})

		log.Warnf("loaded genesis file with url '%s'", genesisFileData.Config.Domain)
	}

	return configs, nil
}

func supportedMode(mode string) bool {
	if len(mode) > 0 && mode != string(registrar) && mode != string(resolver) {
		return false
	}

	return true
}

func isRegistrar(mode string) bool {
	return mode == string(registrar) || mode == string(combined)
}
