/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"
	cmdutils "github.com/trustbloc/edge-core/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/edge-core/pkg/utils/tls"

	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod"
	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
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
	sidetreeReadTokenFlagUsage = "The sidetree read token " +
		" Alternatively, this can be set with the following environment variable: " + sidetreeReadTokenEnvKey

	sidetreeWriteTokenFlagName  = "sidetree-write-token"
	sidetreeWriteTokenEnvKey    = "SIDETREE_WRITE_TOKEN" //nolint: gosec
	sidetreeWriteTokenFlagUsage = "The sidetree write token " +
		" Alternatively, this can be set with the following environment variable: " + sidetreeWriteTokenEnvKey
)

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
}

// GetStartCmd returns the Cobra start command.
func GetStartCmd(srv server) *cobra.Command {
	startCmd := createStartCmd(srv)

	createFlags(startCmd)

	return startCmd
}

func createStartCmd(srv server) *cobra.Command { //nolint: funlen
	return &cobra.Command{
		Use:   "start",
		Short: "Start did-method",
		Long:  "Start did-method",
		RunE: func(cmd *cobra.Command, args []string) error {
			mode, err := getMode(cmd)
			if err != nil {
				return err
			}

			hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}

			tlsSystemCertPool, tlsCACerts, err := getTLS(cmd)
			if err != nil {
				return err
			}

			blocDomain, err := cmdutils.GetUserSetVarFromString(cmd, domainFlagName, domainEnvKey,
				!isRegistrar(mode))
			if err != nil {
				return err
			}

			sidetreeReadToken, err := cmdutils.GetUserSetVarFromString(cmd, sidetreeReadTokenFlagName,
				sidetreeReadTokenEnvKey, true)
			if err != nil {
				return err
			}

			sidetreeWriteToken, err := cmdutils.GetUserSetVarFromString(cmd, sidetreeWriteTokenFlagName,
				sidetreeWriteTokenEnvKey, true)
			if err != nil {
				return err
			}

			parameters := &parameters{
				srv:                srv,
				hostURL:            strings.TrimSpace(hostURL),
				tlsSystemCertPool:  tlsSystemCertPool,
				tlsCACerts:         tlsCACerts,
				blocDomain:         blocDomain,
				mode:               mode,
				sidetreeReadToken:  sidetreeReadToken,
				sidetreeWriteToken: sidetreeWriteToken,
			}

			return startDidMethod(parameters)
		},
	}
}

func getTLS(cmd *cobra.Command) (bool, []string, error) {
	tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
		tlsSystemCertPoolEnvKey, true)
	if err != nil {
		return false, nil, err
	}

	tlsSystemCertPool := false
	if tlsSystemCertPoolString != "" {
		tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
		if err != nil {
			return false, nil, err
		}
	}

	tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName,
		tlsCACertsEnvKey, true)
	if err != nil {
		return false, nil, err
	}

	return tlsSystemCertPool, tlsCACerts, nil
}

func getMode(cmd *cobra.Command) (string, error) {
	mode, err := cmdutils.GetUserSetVarFromString(cmd, modeFlagName, modeEnvKey, true)
	if err != nil {
		return "", err
	}

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
}

func startDidMethod(parameters *parameters) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	didMethodService, err := didmethod.New(&operation.Config{TLSConfig: &tls.Config{RootCAs: rootCAs},
		BlocDomain: parameters.blocDomain, Mode: parameters.mode, SidetreeReadToken: parameters.sidetreeReadToken,
		SidetreeWriteToken: parameters.sidetreeWriteToken})
	if err != nil {
		return err
	}

	handlers := didMethodService.GetOperations()
	router := mux.NewRouter()

	for _, handler := range handlers {
		router.HandleFunc(handler.Path(), handler.Handle()).Methods(handler.Method())
	}

	return parameters.srv.ListenAndServe(parameters.hostURL, router)
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
