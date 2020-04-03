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
	ariesapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api"
	"github.com/hyperledger/aries-framework-go/pkg/framework/context"
	"github.com/hyperledger/aries-framework-go/pkg/kms/legacykms"
	ariesstorage "github.com/hyperledger/aries-framework-go/pkg/storage"
	ariesmemstore "github.com/hyperledger/aries-framework-go/pkg/storage/mem"
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

type rpParameters struct {
	srv               server
	hostURL           string
	tlsSystemCertPool bool
	tlsCACerts        []string
	blocDomain        string
	mode              string
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
			mode, err := getMode(cmd)
			if err != nil {
				return err
			}

			hostURL, err := cmdutils.GetUserSetVarFromString(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}

			tlsSystemCertPoolString, err := cmdutils.GetUserSetVarFromString(cmd, tlsSystemCertPoolFlagName,
				tlsSystemCertPoolEnvKey, true)
			if err != nil {
				return err
			}

			tlsSystemCertPool := false
			if tlsSystemCertPoolString != "" {
				tlsSystemCertPool, err = strconv.ParseBool(tlsSystemCertPoolString)
				if err != nil {
					return err
				}
			}

			tlsCACerts, err := cmdutils.GetUserSetVarFromArrayString(cmd, tlsCACertsFlagName,
				tlsCACertsEnvKey, true)
			if err != nil {
				return err
			}

			blocDomain, err := cmdutils.GetUserSetVarFromString(cmd, domainFlagName, domainEnvKey,
				!isRegistrar(mode))
			if err != nil {
				return err
			}

			parameters := &rpParameters{
				srv:               srv,
				hostURL:           strings.TrimSpace(hostURL),
				tlsSystemCertPool: tlsSystemCertPool,
				tlsCACerts:        tlsCACerts,
				blocDomain:        blocDomain,
				mode:              mode,
			}

			return startDidMethod(parameters)
		},
	}
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
	startCmd.Flags().BoolP(tlsSystemCertPoolFlagName, tlsSystemCertPoolFlagShorthand, false,
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, tlsCACertsFlagShorthand, []string{}, tlsCACertsFlagUsage)
	startCmd.Flags().StringP(domainFlagName, domainFlagShorthand, "", domainFlagUsage)
	startCmd.Flags().StringP(modeFlagName, modeFlagShorthand, "", modeFlagUsage)
}

func startDidMethod(parameters *rpParameters) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	// Create KMS
	kms, err := createKMS(ariesmemstore.NewProvider())
	if err != nil {
		return err
	}

	didMethodService, err := didmethod.New(&operation.Config{TLSConfig: &tls.Config{RootCAs: rootCAs}, KMS: kms,
		BlocDomain: parameters.blocDomain, Mode: parameters.mode})
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

func createKMS(s ariesstorage.Provider) (ariesapi.CloseableKMS, error) {
	kmsProvider, err := context.New(context.WithStorageProvider(s))
	if err != nil {
		return nil, fmt.Errorf("failed to create new kms provider: %w", err)
	}

	kms, err := legacykms.New(kmsProvider)
	if err != nil {
		return nil, fmt.Errorf("failed to create new kms: %w", err)
	}

	return kms, nil
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
