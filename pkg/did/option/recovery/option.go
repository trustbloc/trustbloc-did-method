/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package recovery

import (
	"crypto"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/trustbloc/trustbloc-did-method/pkg/did/doc"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// Opts recover did opts
type Opts struct {
	PublicKeys            []doc.PublicKey
	Services              []docdid.Service
	SidetreeEndpoints     []*models.Endpoint
	NextRecoveryPublicKey crypto.PublicKey
	NextUpdatePublicKey   crypto.PublicKey
	SigningKey            crypto.PrivateKey
	SigningKeyID          string
	RevealValue           string
}

// Option is a recover DID option
type Option func(opts *Opts)

// WithPublicKey add DID public key
func WithPublicKey(publicKey *doc.PublicKey) Option {
	return func(opts *Opts) {
		opts.PublicKeys = append(opts.PublicKeys, *publicKey)
	}
}

// WithService add service
func WithService(service *docdid.Service) Option {
	return func(opts *Opts) {
		opts.Services = append(opts.Services, *service)
	}
}

// WithSidetreeEndpoint go directly to sidetree
func WithSidetreeEndpoint(sidetreeEndpoint string) Option {
	return func(opts *Opts) {
		opts.SidetreeEndpoints = append(opts.SidetreeEndpoints,
			&models.Endpoint{URL: sidetreeEndpoint})
	}
}

// WithNextRecoveryPublicKey set next recovery public key
func WithNextRecoveryPublicKey(nextRecoveryPublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.NextRecoveryPublicKey = nextRecoveryPublicKey
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

// WithRevealValue sets reveal value
func WithRevealValue(rv string) Option {
	return func(opts *Opts) {
		opts.RevealValue = rv
	}
}
