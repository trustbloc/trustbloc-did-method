/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/spf13/cobra"

	"github.com/trustbloc/trustbloc-did-method/pkg/restapi/didmethod"
	cmdutils "github.com/trustbloc/trustbloc-did-method/pkg/utils/cmd"
)

const (
	hostURLFlagName      = "host-url"
	hostURLFlagShorthand = "u"
	hostURLFlagUsage     = "URL to run the bloc did method instance on. Format: HostName:Port."
	hostURLEnvKey        = "DID_METHOD_HOST_URL"
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
	srv     server
	hostURL string
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
			hostURL, err := cmdutils.GetUserSetVar(cmd, hostURLFlagName, hostURLEnvKey, false)
			if err != nil {
				return err
			}

			parameters := &rpParameters{
				srv:     srv,
				hostURL: strings.TrimSpace(hostURL),
			}

			return startDidMethod(parameters)
		},
	}
}

func createFlags(startCmd *cobra.Command) {
	startCmd.Flags().StringP(hostURLFlagName, hostURLFlagShorthand, "", hostURLFlagUsage)
}

func startDidMethod(parameters *rpParameters) error {
	didMethodService, err := didmethod.New()
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
