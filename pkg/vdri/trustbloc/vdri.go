/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package trustbloc

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go-ext/component/vdr/sidetree"
	docdid "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	vdrdoc "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/resolve"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/httpbinding"
	log "github.com/sirupsen/logrus"

	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/httpconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/memorycacheconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/signatureconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/updatevalidationconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/config/verifyingconfig"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/didconfiguration"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/discovery/staticdiscovery"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/endpoint"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/models"
	"github.com/trustbloc/trustbloc-did-method/pkg/vdri/trustbloc/selection/staticselection"
)

type configService interface {
	GetConsortium(string, string) (*models.ConsortiumFileData, error)
	GetStakeholder(string, string) (*models.StakeholderFileData, error)
	GetSidetreeConfig(url string) (*models.SidetreeConfig, error)
}

type sidetreeClient interface {
	CreateDID(opts ...create.Option) (*docdid.DocResolution, error)
}

type endpointService interface {
	GetEndpoints(domain string) ([]*models.Endpoint, error)
}

type didConfigService interface {
	VerifyStakeholder(domain string, doc *docdid.Doc) error
}

type vdri interface {
	Build(keyManager kms.KeyManager, opts ...create.Option) (*docdid.DocResolution, error)
	Read(id string, opts ...resolve.Option) (*docdid.DocResolution, error)
}

// VDRI bloc
type VDRI struct {
	resolverURL      string
	domain           string
	configService    configService
	endpointService  endpointService
	didConfigService didConfigService
	getHTTPVDRI      func(url string) (vdri, error) // needed for unit test
	tlsConfig        *tls.Config
	authToken        string

	validatedConsortium map[string]bool

	enableSignatureVerification bool

	useUpdateValidation     bool
	updateValidationService *updatevalidationconfig.ConfigService
	genesisFiles            []genesisFileData
	sidetreeClient          sidetreeClient
}

type genesisFileData struct {
	url      string
	domain   string
	fileData []byte
}

// New creates new bloc vdri
func New(opts ...Option) *VDRI {
	v := &VDRI{}

	for _, opt := range opts {
		opt(v)
	}

	v.sidetreeClient = sidetree.New(sidetree.WithAuthToken(v.authToken), sidetree.WithTLSConfig(v.tlsConfig))

	v.getHTTPVDRI = func(url string) (vdri, error) {
		return httpbinding.New(url,
			httpbinding.WithTLSConfig(v.tlsConfig), httpbinding.WithResolveAuthToken(v.authToken))
	}

	configService := httpconfig.NewService(httpconfig.WithTLSConfig(v.tlsConfig))

	switch {
	case v.useUpdateValidation:
		verifyingService := signatureconfig.NewService(verifyingconfig.NewService(configService))
		v.updateValidationService = updatevalidationconfig.NewService(verifyingService)
		v.configService = memorycacheconfig.NewService(v.updateValidationService)
	case v.enableSignatureVerification:
		verifyingService := signatureconfig.NewService(verifyingconfig.NewService(configService))
		v.configService = memorycacheconfig.NewService(verifyingService)
	default:
		v.configService = memorycacheconfig.NewService(verifyingconfig.NewService(configService))
	}

	v.endpointService = endpoint.NewService(
		staticdiscovery.NewService(v.configService),
		staticselection.NewService(v.configService))

	v.didConfigService = didconfiguration.NewService(didconfiguration.WithTLSConfig(v.tlsConfig))

	v.validatedConsortium = map[string]bool{}

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
func (v *VDRI) Store(doc *docdid.Doc, by *[]vdrdoc.ModifiedBy) error {
	return nil
}

// Build did doc
func (v *VDRI) Build(keyManager kms.KeyManager, opts ...create.Option) (*docdid.DocResolution, error) {
	createDIDOpts := &create.Opts{}

	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	if createDIDOpts.GetEndpoints == nil {
		createDIDOpts.GetEndpoints = func() ([]string, error) {
			var result []string

			endpoints, err := v.endpointService.GetEndpoints(v.domain)
			if err != nil {
				return nil, fmt.Errorf("failed to get endpoints: %w", err)
			}

			for _, v := range endpoints {
				result = append(result, v.URL)
			}

			return result, err
		}

		opts = append(opts, create.WithEndpoints(createDIDOpts.GetEndpoints))
	}

	if createDIDOpts.MultiHashAlgorithm == 0 {
		endpoints, err := createDIDOpts.GetEndpoints()
		if err != nil {
			return nil, err
		}

		sidetreeConfig, err := v.configService.GetSidetreeConfig(endpoints[0])
		if err != nil {
			return nil, err
		}

		opts = append(opts, create.WithMultiHashAlgorithm(sidetreeConfig.MultiHashAlgorithm))
	}

	return v.sidetreeClient.CreateDID(opts...)
}

func (v *VDRI) loadGenesisFiles() error {
	for _, genesisFile := range v.genesisFiles {
		err := v.updateValidationService.AddGenesisFile(genesisFile.url, genesisFile.domain, genesisFile.fileData)
		if err != nil {
			return fmt.Errorf("error loading consortium genesis config: %w", err)
		}
	}

	v.genesisFiles = nil

	return nil
}

func (v *VDRI) sidetreeResolve(url, did string, opts ...resolve.Option) (*docdid.DocResolution, error) {
	resolver, err := v.getHTTPVDRI(url)
	if err != nil {
		return nil, fmt.Errorf("failed to create new sidetree vdri: %w", err)
	}

	docResolution, err := resolver.Read(did, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve did: %w", err)
	}

	return docResolution, nil
}

const (
	expectedTrustblocDIDParts = 4
	domainDIDPart             = 2
)

func (v *VDRI) Read(did string, opts ...resolve.Option) (*docdid.DocResolution, error) { //nolint: gocyclo,funlen
	err := v.loadGenesisFiles()
	if err != nil {
		return nil, fmt.Errorf("invalid genesis file: %w", err)
	}

	if v.resolverURL != "" {
		return v.sidetreeResolve(v.resolverURL, did, opts...)
	}

	// parse did
	didParts := strings.Split(did, ":")
	if len(didParts) != expectedTrustblocDIDParts {
		return nil, fmt.Errorf("wrong did %s", did)
	}

	domain := didParts[domainDIDPart]
	if v.domain != "" {
		domain = v.domain
	}

	if v.enableSignatureVerification {
		if _, ok := v.validatedConsortium[domain]; !ok {
			_, err = v.ValidateConsortium(domain)
			if err != nil {
				return nil, fmt.Errorf("invalid consortium: %w", err)
			}

			v.validatedConsortium[domain] = true
		}
	}

	endpoints, err := v.endpointService.GetEndpoints(domain)
	if err != nil {
		return nil, fmt.Errorf("failed to get endpoints: %w", err)
	}

	if len(endpoints) == 0 {
		return nil, errors.New("list of endpoints is empty")
	}

	var docResolution *docdid.DocResolution

	var docBytes []byte

	for _, e := range endpoints {
		resp, err := v.sidetreeResolve(e.URL+"/identifiers", did, opts...)
		if err != nil {
			return nil, err
		}

		respBytes, err := canonicalizeDoc(resp.DIDDocument)
		if err != nil {
			return nil, fmt.Errorf("cannot canonicalize resolved doc: %w", err)
		}

		if docResolution != nil && !bytes.Equal(docBytes, respBytes) {
			log.Debugf("mismatch in document contents for did %s. Doc 1: %s, Doc 2: %s",
				did, string(docBytes), string(respBytes))
		}

		docResolution = resp
		docBytes = respBytes
	}

	return docResolution, nil
}

// ValidateConsortium validate the config and endorsement of a consortium and its stakeholders
// returns the duration after which the consortium config expires and needs re-validation
func (v *VDRI) ValidateConsortium(consortiumDomain string) (*time.Duration, error) {
	consortiumConfig, err := v.configService.GetConsortium(consortiumDomain, consortiumDomain)
	if err != nil {
		return nil, fmt.Errorf("consortium invalid: %w", err)
	}

	stakeholders, err := v.selectStakeholders(consortiumConfig.Config)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch stakeholders: %w", err)
	}

	n := consortiumConfig.Config.Policy.NumQueries
	if n == 0 || n > len(consortiumConfig.Config.Members) {
		n = len(consortiumConfig.Config.Members)
	}

	numVerifications := 0

	verificationErrors := ""

	for _, sfd := range stakeholders {
		e := v.verifyStakeholder(consortiumConfig, sfd)
		if e != nil {
			verificationErrors += e.Error() + ", "
			continue
		}

		numVerifications++
	}

	if numVerifications < n {
		return nil, fmt.Errorf("insufficient stakeholders verified, all errors: [%s]", verificationErrors)
	}

	lifetime, err := consortiumConfig.CacheLifetime()
	if err != nil {
		return nil, fmt.Errorf("consortium lifetime error: %w", err)
	}

	return &lifetime, nil
}

func (v *VDRI) verifyStakeholder(cfd *models.ConsortiumFileData, sfd *models.StakeholderFileData) error {
	s := sfd.Config
	if s == nil {
		return fmt.Errorf("stakeholder has nil config")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s.Endpoints))))
	if err != nil {
		return err
	}

	ep := s.Endpoints[n.Uint64()]

	docResolution, e := v.sidetreeResolve(ep+"/identifiers", s.DID)
	if e != nil {
		return fmt.Errorf("can't resolve stakeholder DID: %w", e)
	}

	// verify did configuration
	e = v.didConfigService.VerifyStakeholder(s.Domain, docResolution.DIDDocument)
	if e != nil {
		return fmt.Errorf("stakeholder did configuration failed to verify: %w", e)
	}

	_, e = didconfiguration.VerifyDIDSignature(cfd.JWS, docResolution.DIDDocument)
	if e != nil {
		return fmt.Errorf("stakeholder does not sign consortium: %w", e)
	}

	_, e = didconfiguration.VerifyDIDSignature(sfd.JWS, docResolution.DIDDocument)
	if e != nil {
		return fmt.Errorf("stakeholder does not sign itself: %w", e)
	}

	return nil
}

// select n random stakeholders from the consortium (where n is the consortium's numQueries policy parameter)
func (v *VDRI) selectStakeholders(consortium *models.Consortium) ([]*models.StakeholderFileData, error) {
	n := consortium.Policy.NumQueries
	if n == 0 || n > len(consortium.Members) {
		n = len(consortium.Members)
	}

	perm := mathrand.Perm(len(consortium.Members))

	successCount := 0

	var out []*models.StakeholderFileData

	for i := 0; i < len(consortium.Members) && successCount < n; i++ {
		sle := consortium.Members[perm[i]]

		s, err := v.configService.GetStakeholder(sle.Domain, sle.Domain)
		if err != nil {
			continue
		}

		out = append(out, s)

		successCount++
	}

	if successCount < n {
		return nil, fmt.Errorf("insufficient valid stakeholders")
	}

	return out, nil
}

// canonicalizeDoc canonicalizes a DID doc using json-ld canonicalization
func canonicalizeDoc(doc *docdid.Doc) ([]byte, error) {
	marshaled, err := doc.JSONBytes()
	if err != nil {
		return nil, err
	}

	docMap := map[string]interface{}{}

	err = json.Unmarshal(marshaled, &docMap)
	if err != nil {
		return nil, err
	}

	proc := jsonld.Default()

	return proc.GetCanonicalDocument(docMap)
}

// Option configures the bloc vdri
type Option func(opts *VDRI)

// WithResolverURL option is setting resolver url
func WithResolverURL(resolverURL string) Option {
	return func(opts *VDRI) {
		opts.resolverURL = resolverURL
	}
}

// WithDomain option is setting domain
func WithDomain(domain string) Option {
	return func(opts *VDRI) {
		opts.domain = domain
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

// EnableSignatureVerification enables signature verification
func EnableSignatureVerification(enable bool) Option {
	return func(opts *VDRI) {
		opts.enableSignatureVerification = enable
	}
}

// UseGenesisFile adds a consortium genesis file to the VDRI and enables consortium config update validation
func UseGenesisFile(url, domain string, genesisFile []byte) Option {
	return func(opts *VDRI) {
		opts.genesisFiles = append(opts.genesisFiles, genesisFileData{
			url:      url,
			domain:   domain,
			fileData: genesisFile,
		})
		opts.useUpdateValidation = true
	}
}
