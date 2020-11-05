/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"crypto"
	"crypto/tls"

	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
)

// Option is a DID client instance option
type Option func(opts *Client)

// WithTLSConfig option is for definition of secured HTTP transport using a tls.Config instance
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(opts *Client) {
		opts.tlsConfig = tlsConfig
	}
}

// WithAuthToken add auth token
func WithAuthToken(authToken string) Option {
	return func(opts *Client) {
		opts.authToken = "Bearer " + authToken
	}
}

// CreateDIDOpts create did opts
type CreateDIDOpts struct {
	publicKeys        []PublicKey
	services          []docdid.Service
	sidetreeEndpoints []*models.Endpoint
	recoveryPublicKey crypto.PublicKey
	updatePublicKey   crypto.PublicKey
}

// CreateDIDOption is a create DID option
type CreateDIDOption func(opts *CreateDIDOpts)

// WithPublicKey add DID public key
func WithPublicKey(publicKey *PublicKey) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.publicKeys = append(opts.publicKeys, *publicKey)
	}
}

// WithService add service
func WithService(service *docdid.Service) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.services = append(opts.services, *service)
	}
}

// WithSidetreeEndpoint go directly to sidetree
func WithSidetreeEndpoint(sidetreeEndpoint string) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.sidetreeEndpoints = append(opts.sidetreeEndpoints,
			&models.Endpoint{URL: sidetreeEndpoint})
	}
}

// WithRecoveryPublicKey set recovery public key
func WithRecoveryPublicKey(recoveryPublicKey crypto.PublicKey) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.recoveryPublicKey = recoveryPublicKey
	}
}

// WithUpdatePublicKey set update public key
func WithUpdatePublicKey(updatePublicKey crypto.PublicKey) CreateDIDOption {
	return func(opts *CreateDIDOpts) {
		opts.updatePublicKey = updatePublicKey
	}
}

// UpdateDIDOption is a update DID option
type UpdateDIDOption func(opts *UpdateDIDOpts)

// UpdateDIDOpts update did opts
type UpdateDIDOpts struct {
	addPublicKeys       []PublicKey
	addServices         []docdid.Service
	removePublicKeys    []string
	removeServices      []string
	sidetreeEndpoints   []*models.Endpoint
	nextUpdatePublicKey crypto.PublicKey
	signingKey          crypto.PrivateKey
	signingKeyID        string
}

// WithAddPublicKey set public key to be added
func WithAddPublicKey(publicKey *PublicKey) UpdateDIDOption {
	return func(opts *UpdateDIDOpts) {
		opts.addPublicKeys = append(opts.addPublicKeys, *publicKey)
	}
}

// WithAddService set services to be added
func WithAddService(service *docdid.Service) UpdateDIDOption {
	return func(opts *UpdateDIDOpts) {
		opts.addServices = append(opts.addServices, *service)
	}
}

// WithRemovePublicKey set remove public key  id
func WithRemovePublicKey(publicKeyID string) UpdateDIDOption {
	return func(opts *UpdateDIDOpts) {
		opts.removePublicKeys = append(opts.removePublicKeys, publicKeyID)
	}
}

// WithRemoveService set remove service id
func WithRemoveService(serviceID string) UpdateDIDOption {
	return func(opts *UpdateDIDOpts) {
		opts.removeServices = append(opts.removeServices, serviceID)
	}
}

// WithNextUpdatePublicKey set next update public key
func WithNextUpdatePublicKey(nextUpdatePublicKey crypto.PublicKey) UpdateDIDOption {
	return func(opts *UpdateDIDOpts) {
		opts.nextUpdatePublicKey = nextUpdatePublicKey
	}
}

// WithSigningKey set signing key
func WithSigningKey(signingKey crypto.PrivateKey) UpdateDIDOption {
	return func(opts *UpdateDIDOpts) {
		opts.signingKey = signingKey
	}
}

// WithSigningKeyID set signing key id
func WithSigningKeyID(id string) UpdateDIDOption {
	return func(opts *UpdateDIDOpts) {
		opts.signingKeyID = id
	}
}

// WithUpdateSidetreeEndpoint go directly to sidetree
func WithUpdateSidetreeEndpoint(sidetreeEndpoint string) UpdateDIDOption {
	return func(opts *UpdateDIDOpts) {
		opts.sidetreeEndpoints = append(opts.sidetreeEndpoints,
			&models.Endpoint{URL: sidetreeEndpoint})
	}
}
