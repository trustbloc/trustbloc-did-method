/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package bloc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/httpbinding"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"

	"github.com/trustbloc/bloc-did-method/pkg/vdri/bloc/discovery/staticdiscovery"
	"github.com/trustbloc/bloc-did-method/pkg/vdri/bloc/endpoint"
	"github.com/trustbloc/bloc-did-method/pkg/vdri/bloc/selection/staticselection"
)

type discovery interface {
	GetEndpoints(domain string) ([]*endpoint.Endpoint, error)
}

type selection interface {
	SelectEndpoints(endpoints []*endpoint.Endpoint) ([]*endpoint.Endpoint, error)
}

type vdri interface {
	Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*docdid.Doc, error)
	Read(did string, opts ...vdriapi.ResolveOpts) (*docdid.Doc, error)
}

// VDRI bloc
type VDRI struct {
	domain      string
	resolverURL string
	discovery   discovery
	selection   selection
	getHTTPVDRI func(url string) (vdri, error) // needed for unit test
}

// createPayloadSchema is the struct for create payload
type createPayloadSchema struct {

	// operation
	Operation model.OperationType `json:"type"`

	// Encoded original DID document
	DidDocument string `json:"didDocument"`

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOtpHash"`

	// Hash of the one-time password for this recovery/checkpoint/revoke operation.
	NextRecoveryOTPHash string `json:"nextRecoveryOtpHash"`
}

// New creates new bloc vdri
func New(opts ...Option) (*VDRI, error) {
	vdri := &VDRI{discovery: staticdiscovery.NewService(), selection: staticselection.NewService(),
		getHTTPVDRI: func(url string) (vdri, error) {
			return httpbinding.New(url)
		}}

	for _, opt := range opts {
		opt(vdri)
	}

	return vdri, nil
}

// Accept did method
func (v *VDRI) Accept(method string) bool {
	return method == "bloc"
}

// Store did doc
func (v *VDRI) Store(doc *docdid.Doc, by *[]vdriapi.ModifiedBy) error {
	return errors.New("store not supported in bloc vdri")
}
func (v *VDRI) getEndpoints(domain string) ([]*endpoint.Endpoint, error) {
	endpoints, err := v.discovery.GetEndpoints(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to discover endpoints: %w", err)
	}

	selectedEndpoints, err := v.selection.SelectEndpoints(endpoints)
	if err != nil {
		return nil, fmt.Errorf("failed to select endpoints: %w", err)
	}

	if len(selectedEndpoints) == 0 {
		return nil, errors.New("list of endpoints is empty")
	}

	return selectedEndpoints, nil
}

// Build did doc
func (v *VDRI) Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*docdid.Doc, error) {
	if v.domain == "" {
		return nil, errors.New("domain is empty")
	}

	endpoints, err := v.getEndpoints(v.domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints: %w", err)
	}

	sideTreeVDRI, err := v.getHTTPVDRI(endpoints[0].URL)
	if err != nil {
		return nil, fmt.Errorf("failed to create new sidetree vdri: %w", err)
	}

	opts = append(opts, vdriapi.WithRequestBuilder(buildSideTreeRequest))

	resDoc, err := sideTreeVDRI.Build(pubKey, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create did: %w", err)
	}

	return resDoc, nil
}

func (v *VDRI) Read(did string, opts ...vdriapi.ResolveOpts) (*docdid.Doc, error) {
	if v.resolverURL != "" {
		resolver, err := v.getHTTPVDRI(v.resolverURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create new sidetree vdri: %w", err)
		}

		doc, err := resolver.Read(did, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve did: %w", err)
		}

		return doc, nil
	}

	// parse did
	didParts := strings.Split(did, ":")
	if len(didParts) != 4 {
		return nil, fmt.Errorf("wrong did %s", did)
	}

	endpoints, err := v.getEndpoints(v.domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints: %w", err)
	}

	var doc *docdid.Doc

	for _, e := range endpoints {
		sideTreeVDRI, err := v.getHTTPVDRI(e.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to create new sidetree vdri: %w", err)
		}

		resp, err := sideTreeVDRI.Read(did, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve did: %w", err)
		}

		// TODO add logic to compare response from each endpoint
		doc = resp
	}

	return doc, nil
}

// buildSideTreeRequest request builder for sidetree public DID creation
func buildSideTreeRequest(docBytes []byte) (io.Reader, error) {
	encodeDidDocument := base64.URLEncoding.EncodeToString(docBytes)

	schema := createPayloadSchema{
		Operation:           model.OperationTypeCreate,
		DidDocument:         encodeDidDocument,
		NextUpdateOTPHash:   "",
		NextRecoveryOTPHash: "",
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}

	request := &model.Request{
		Protected: &model.Header{Alg: "", Kid: ""},
		Payload:   base64.URLEncoding.EncodeToString(payload),
		Signature: ""}

	b, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(b), nil
}

// Option configures the bloc vdri
type Option func(opts *VDRI)

// WithResolverURL option is setting resolver url
func WithResolverURL(resolverURL string) Option {
	return func(opts *VDRI) {
		opts.resolverURL = resolverURL
	}
}

// WithDomain option is setting domain url to discover endpoints
func WithDomain(domain string) Option {
	return func(opts *VDRI) {
		opts.domain = domain
	}
}
