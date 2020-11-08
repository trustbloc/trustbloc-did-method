/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package update

import (
	"crypto"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/trustbloc/trustbloc-did-method/pkg/did/doc"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// Option is a update DID option
type Option func(opts *Opts)

// Opts update did opts
type Opts struct {
	AddPublicKeys       []doc.PublicKey
	AddServices         []docdid.Service
	RemovePublicKeys    []string
	RemoveServices      []string
	SidetreeEndpoints   []*models.Endpoint
	NextUpdatePublicKey crypto.PublicKey
	SigningKey          crypto.PrivateKey
	SigningKeyID        string
}

// WithAddPublicKey set public key to be added
func WithAddPublicKey(publicKey *doc.PublicKey) Option {
	return func(opts *Opts) {
		opts.AddPublicKeys = append(opts.AddPublicKeys, *publicKey)
	}
}

// WithAddService set services to be added
func WithAddService(service *docdid.Service) Option {
	return func(opts *Opts) {
		opts.AddServices = append(opts.AddServices, *service)
	}
}

// WithRemovePublicKey set remove public key  id
func WithRemovePublicKey(publicKeyID string) Option {
	return func(opts *Opts) {
		opts.RemovePublicKeys = append(opts.RemovePublicKeys, publicKeyID)
	}
}

// WithRemoveService set remove service id
func WithRemoveService(serviceID string) Option {
	return func(opts *Opts) {
		opts.RemoveServices = append(opts.RemoveServices, serviceID)
	}
}

// WithNextUpdatePublicKey set next update public key
func WithNextUpdatePublicKey(nextUpdatePublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.NextUpdatePublicKey = nextUpdatePublicKey
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

// WithSidetreeEndpoint go directly to sidetree
func WithSidetreeEndpoint(sidetreeEndpoint string) Option {
	return func(opts *Opts) {
		opts.SidetreeEndpoints = append(opts.SidetreeEndpoints,
			&models.Endpoint{URL: sidetreeEndpoint})
	}
}
