/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"crypto/tls"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"

	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod"
	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod/operation"
	cmdutils "github.com/trustbloc/trustbloc-did-method/pkg/utils/cmd"
	tlsutils "github.com/trustbloc/trustbloc-did-method/pkg/utils/tls"
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

			parameters := &rpParameters{
				srv:               srv,
				hostURL:           strings.TrimSpace(hostURL),
				tlsSystemCertPool: tlsSystemCertPool,
				tlsCACerts:        tlsCACerts,
			}

			return startDidMethod(parameters)
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
	startCmd.Flags().BoolP(tlsSystemCertPoolFlagName, tlsSystemCertPoolFlagShorthand, false,
		tlsSystemCertPoolFlagUsage)
	startCmd.Flags().StringArrayP(tlsCACertsFlagName, tlsCACertsFlagShorthand, []string{}, tlsCACertsFlagUsage)
}

func startDidMethod(parameters *rpParameters) error {
	rootCAs, err := tlsutils.GetCertPool(parameters.tlsSystemCertPool, parameters.tlsCACerts)
	if err != nil {
		return err
	}

	didMethodService, err := didmethod.New(&operation.Config{TLSConfig: &tls.Config{RootCAs: rootCAs}})
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
