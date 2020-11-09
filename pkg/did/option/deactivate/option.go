/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package deactivate

import (
	"crypto"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// Opts deactivate did opts
type Opts struct {
	SidetreeEndpoints []*models.Endpoint
	SigningKey        crypto.PrivateKey
	SigningKeyID      string
}

// Option is a deactivate DID option
type Option func(opts *Opts)

// WithSidetreeEndpoint go directly to sidetree
func WithSidetreeEndpoint(sidetreeEndpoint string) Option {
	return func(opts *Opts) {
		opts.SidetreeEndpoints = append(opts.SidetreeEndpoints,
			&models.Endpoint{URL: sidetreeEndpoint})
	}
}

// WithSigningKey set signing key
func WithSigningKey(signingKey crypto.PrivateKey) Option {
	return func(opts *Opts) {
		opts.SigningKey = signingKey
	}
}

// WithSigningKeyID set signing key id
func WithSigningKeyID(id string) Option {
	return func(opts *Opts) {
		opts.SigningKeyID = id
	}
}
