/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package trustbloc

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/trustbloc-did-method/pkg/internal/common/jsoncanonicalizer"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/httpconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/verifyingconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/discovery/staticdiscovery"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/endpoint"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/selection/staticselection"
)

type endpointService interface {
	GetEndpoints(domain string) ([]*models.Endpoint, error)
}

type vdri interface {
	Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*docdid.Doc, error)
	Read(did string, opts ...vdriapi.ResolveOpts) (*docdid.Doc, error)
}

// VDRI bloc
type VDRI struct {
	resolverURL     string
	endpointService endpointService
	getHTTPVDRI     func(url string) (vdri, error) // needed for unit test
	tlsConfig       *tls.Config
	authToken       string
}

// New creates new bloc vdri
func New(opts ...Option) *VDRI {
	v := &VDRI{}

	for _, opt := range opts {
		opt(v)
	}

	configService := httpconfig.NewService(httpconfig.WithTLSConfig(v.tlsConfig))
	verifyingService := verifyingconfig.NewService(configService)
	v.endpointService = endpoint.NewService(
		staticdiscovery.NewService(verifyingService),
		staticselection.NewService(verifyingService))

	v.getHTTPVDRI = func(url string) (vdri, error) {
		return httpbinding.New(url,
			httpbinding.WithTLSConfig(v.tlsConfig), httpbinding.WithResolveAuthToken(v.authToken))
	}

	return v
}

// Accept did method
func (v *VDRI) Accept(method string) bool {
	return method == "trustbloc"
}

// Close vdri
func (v *VDRI) Close() error {
	return nil
}

// Store did doc
func (v *VDRI) Store(doc *docdid.Doc, by *[]vdriapi.ModifiedBy) error {
	return nil
}

// Build did doc
func (v *VDRI) Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*docdid.Doc, error) {
	return nil, fmt.Errorf("build method not supported for did bloc")
}

func (v *VDRI) sidetreeResolve(url, did string, opts ...vdriapi.ResolveOpts) (*docdid.Doc, error) {
	resolver, err := v.getHTTPVDRI(url)
	if err != nil {
		return nil, fmt.Errorf("failed to create new sidetree vdri: %w", err)
	}

	doc, err := resolver.Read(did, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve did: %w", err)
	}

	return doc, nil
}

func (v *VDRI) Read(did string, opts ...vdriapi.ResolveOpts) (*docdid.Doc, error) { //nolint: gocyclo
	if v.resolverURL != "" {
		return v.sidetreeResolve(v.resolverURL, did, opts...)
	}

	// parse did
	didParts := strings.Split(did, ":")
	if len(didParts) != 4 {
		return nil, fmt.Errorf("wrong did %s", did)
	}

	endpoints, err := v.endpointService.GetEndpoints(didParts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints: %w", err)
	}

	if len(endpoints) == 0 {
		return nil, errors.New("list of endpoints is empty")
	}

	var doc *docdid.Doc

	var docBytes []byte

	for _, e := range endpoints {
		resp, err := v.sidetreeResolve(e.URL+"/identifiers", did, opts...)
		if err != nil {
			return nil, err
		}

		respBytesRaw, err := resp.JSONBytes()
		if err != nil {
			return nil, fmt.Errorf("cannot marshal resolved doc: %w", err)
		}

		respBytes, err := jsoncanonicalizer.Transform(respBytesRaw)
		if err != nil {
			return nil, fmt.Errorf("cannot canonicalize resolved doc: %w", err)
		}

		if doc != nil && !bytes.Equal(docBytes, respBytes) {
			log.Errorf("mismatch in document contents for did %s. Doc 1: %s, Doc 2: %s",
				did, string(docBytes), string(respBytes))

			return nil, errors.New("mismatch in document contents")
		}

		doc = resp
		docBytes = respBytes
	}

	return doc, nil
}

// Option configures the bloc vdri
type Option func(opts *VDRI)

// WithResolverURL option is setting resolver url
func WithResolverURL(resolverURL string) Option {
	return func(opts *VDRI) {
		opts.resolverURL = resolverURL
	}
}

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *VDRI) {
		opts.tlsConfig = tlsConfig
	}
}

// WithAuthToken add auth token
func WithAuthToken(authToken string) Option {
	return func(opts *VDRI) {
		opts.authToken = authToken
	}
}
