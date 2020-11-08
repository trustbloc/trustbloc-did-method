/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package create

import (
	"crypto"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/trustbloc/trustbloc-did-method/pkg/did/doc"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// Opts create did opts
type Opts struct {
	PublicKeys        []doc.PublicKey
	Services          []docdid.Service
	SidetreeEndpoints []*models.Endpoint
	RecoveryPublicKey crypto.PublicKey
	UpdatePublicKey   crypto.PublicKey
}

// Option is a create DID option
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

// WithRecoveryPublicKey set recovery public key
func WithRecoveryPublicKey(recoveryPublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.RecoveryPublicKey = recoveryPublicKey
	}
}

// WithUpdatePublicKey set update public key
func WithUpdatePublicKey(updatePublicKey crypto.PublicKey) Option {
	return func(opts *Opts) {
		opts.UpdatePublicKey = updatePublicKey
	}
}
