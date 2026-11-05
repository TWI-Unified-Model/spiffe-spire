package credentialacquisition

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Acquirer is the Credential Acquisition System Server: the three calls of
// TACRA for the Workloads the Agents attested. The refusals it returns are
// gRPC statuses that name the reason, as TACRA enumerates them: an invalid
// or unsupported Target, an unsupported Credential Type, a rejected
// Credential Hint, a Remote Attestation failure, a permission failure, a
// Server unreachable.
type Acquirer struct {
	log       logrus.FieldLogger
	policies  map[string]*Policy
	evidence  []string
	sessions  *sessions
	appraiser *appraiser
	ear       *earVerifier
	vault     *vaultClient
	platform  *PlatformRule
}

// New builds the Acquirer from the configuration: it loads the keys of the
// Verifiers and the TLS material, and refuses a configuration it cannot serve.
func New(c *Config, log logrus.FieldLogger) (*Acquirer, error) {
	policies, err := c.Validate()
	if err != nil {
		return nil, err
	}
	maxAge, _ := parseDuration(c.EARMaxAge, 2*time.Minute)
	skew, _ := parseDuration(c.EARSkew, 5*time.Second)
	ear := &earVerifier{maxAge: maxAge, skew: skew, now: time.Now}
	for name, v := range c.Verifier {
		key, err := loadEARKey(v.EARKeyPath)
		if err != nil {
			return nil, fmt.Errorf("credential_acquisition: Verifier %q: ear_key_path: %w", name, err)
		}
		ear.keys = append(ear.keys, earKey{name: name, key: key, submods: v.Submods})
	}
	appraiser, err := newAppraiser(c)
	if err != nil {
		return nil, fmt.Errorf("credential_acquisition: %w", err)
	}
	vault, err := newVaultClient(c)
	if err != nil {
		return nil, fmt.Errorf("credential_acquisition: %w", err)
	}
	var rule *PlatformRule
	if c.PlatformRulePath != "" {
		if rule, err = loadPlatformRule(c.PlatformRulePath); err != nil {
			return nil, fmt.Errorf("credential_acquisition: platform_rule_path: %w", err)
		}
	}
	a := newAcquirer(log, policies, c.AcceptableEvidence, appraiser, ear, vault, time.Now)
	a.platform = rule
	for name, p := range policies {
		log.WithFields(logrus.Fields{
			"target":    name,
			"mode":      p.Mode,
			"verifiers": strings.Join(p.Verifiers, ","),
		}).Info("Attested credential acquisition configured for Target")
	}
	return a, nil
}

func newAcquirer(log logrus.FieldLogger, policies map[string]*Policy, evidence []string, appraiser *appraiser, ear *earVerifier, vault *vaultClient, now func() time.Time) *Acquirer {
	return &Acquirer{
		log:       log,
		policies:  policies,
		evidence:  evidence,
		sessions:  newSessions(now),
		appraiser: appraiser,
		ear:       ear,
		vault:     vault,
	}
}

// Initiation is Initiate-Credential-Acquisition as the Agent forwards it,
// with the registration entry of the Workload it attested and its own ID.
type Initiation struct {
	EntryID        string
	AgentID        string
	Target         string
	CredentialType string
	CredentialHint string
}

// InitiationResult is what the Workload needs to produce its key and its
// Evidence.
type InitiationResult struct {
	Mode               string
	FreshnessKind      string
	Handle             []byte
	ExpiresIn          uint32
	MaxAge             uint32
	AcceptableCSK      []string
	AcceptableCEK      []string
	AcceptableEvidence []string
}

// Initiate validates the Target, the Credential Type and the Credential
// Hint, and returns the Freshness Handle: minted here for a Target in enroll
// mode, by the Secret Vault for one in retrieve mode.
func (a *Acquirer) Initiate(ctx context.Context, in Initiation) (*InitiationResult, error) {
	p, err := a.policy(in.Target, "")
	if err != nil {
		return nil, err
	}
	if err := p.servesCredentialType(in.CredentialType); err != nil {
		return nil, err
	}
	ss := session{
		kind:           FreshnessPresentNonce,
		target:         in.Target,
		credentialType: in.CredentialType,
		hint:           in.CredentialHint,
		mode:           p.Mode,
		entryID:        in.EntryID,
		agentID:        in.AgentID,
	}
	switch p.Mode {
	case ModeEnroll:
		ss.expires = a.sessions.now().Add(p.ExpiresIn)
		handle, err := a.sessions.mint(ss)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		return &InitiationResult{
			Mode:               ModeEnroll,
			FreshnessKind:      FreshnessPresentNonce,
			Handle:             handle,
			ExpiresIn:          uint32(p.ExpiresIn / time.Second), //nolint:gosec // bounded by the configuration
			AcceptableCSK:      slices.Clone(p.AcceptableCSK),
			AcceptableEvidence: slices.Clone(a.evidence),
		}, nil
	default:
		if a.vault == nil {
			return nil, status.Error(codes.Unavailable, "no Secret Vault is configured")
		}
		vi, handle, err := a.vault.initiate(ctx, in.Target, in.CredentialType, in.CredentialHint)
		if err != nil {
			return nil, vaultError(err)
		}
		switch {
		case vi.Mode != ModeRetrieve:
			return nil, status.Errorf(codes.Unavailable, "Secret Vault answered mode %q for a Target in retrieve mode", vi.Mode)
		case vi.FreshnessKind != FreshnessPresentNonce:
			return nil, status.Errorf(codes.Unavailable, "Secret Vault answered Freshness Kind %q; this Server supports present-nonce", vi.FreshnessKind)
		case len(handle) < 16 || len(handle) > 64:
			return nil, status.Errorf(codes.Unavailable, "Secret Vault answered a Handle of %d octets", len(handle))
		case len(vi.AcceptableCEK) == 0:
			return nil, status.Error(codes.Unavailable, "Secret Vault answered no acceptable_cek")
		}
		expiresIn := p.ExpiresIn
		if vi.ExpiresIn > 0 {
			expiresIn = time.Duration(vi.ExpiresIn) * time.Second
		}
		ss.expires = a.sessions.now().Add(expiresIn)
		a.sessions.remember(handle, ss)
		return &InitiationResult{
			Mode:               ModeRetrieve,
			FreshnessKind:      FreshnessPresentNonce,
			Handle:             handle,
			ExpiresIn:          uint32(expiresIn / time.Second), //nolint:gosec // bounded by the vault's answer
			AcceptableCEK:      vi.AcceptableCEK,
			AcceptableEvidence: slices.Clone(a.evidence),
		}, nil
	}
}

// Enrollment is Enroll-Credential as the Agent forwards it.
type Enrollment struct {
	EntryID          string
	AgentID          string
	Target           string
	CredentialType   string
	CredentialHint   string
	FreshnessKind    string
	FreshnessElement []byte
	CSR              []byte
	Evidence         []byte
	EvidenceProfile  string
	BindingMethod    string
	BindingHash      string
}

// EnrollmentResult is what the Credential Authority mints from: the CSR,
// whose key the Evidence is bound to, and the Attestation Results.
type EnrollmentResult struct {
	CSR         *x509.CertificateRequest
	Verifier    string
	Submod      string
	Measurement []byte
	IssuedAt    time.Time
	// Waived is what the platform rule admitted the Attestation Results
	// without, one line per named waiver it applied, for the record.
	Waived []string
}

// Enroll checks the exchange, the binding and the Attestation Results, and
// returns the CSR the Credential Authority mints for.
func (a *Acquirer) Enroll(ctx context.Context, in Enrollment) (*EnrollmentResult, error) {
	p, err := a.policy(in.Target, ModeEnroll)
	if err != nil {
		return nil, err
	}
	if err := checkBinding(in.BindingMethod, in.BindingHash); err != nil {
		return nil, err
	}
	profile, err := a.profile(in.EvidenceProfile)
	if err != nil {
		return nil, err
	}
	csr, err := parseCSR(in.CSR, p.AcceptableCSK)
	if err != nil {
		return nil, err
	}
	// The request is well formed: the single-use Handle is consumed only now.
	if err := a.consumeSession(in.FreshnessKind, in.FreshnessElement, in.Target, in.CredentialType, in.CredentialHint, in.EntryID, in.AgentID); err != nil {
		return nil, err
	}
	bv := BindingValue(in.FreshnessElement, in.Target, in.CSR)
	res, err := a.appraise(ctx, p, in.Evidence, profile, bv)
	if err != nil {
		return nil, err
	}
	// The Credential Type after the attestation: a request that failed attestation is refused for that, whatever it
	// asked for; one that passed and asks for a type the policy does not support is refused for the type.
	if err := p.servesCredentialType(in.CredentialType); err != nil {
		return nil, err
	}
	return &EnrollmentResult{
		CSR:         csr,
		Verifier:    res.Verifier,
		Submod:      res.Submod,
		Measurement: res.Measurement,
		IssuedAt:    res.IssuedAt,
		Waived:      res.waived,
	}, nil
}

// Retrieval is Retrieve-Credential as the Agent forwards it.
type Retrieval struct {
	EntryID          string
	AgentID          string
	Target           string
	CredentialType   string
	CredentialHint   string
	FreshnessKind    string
	FreshnessElement []byte
	CEKPub           []byte
	Evidence         []byte
	EvidenceProfile  string
	BindingMethod    string
	BindingHash      string
}

// Retrieve checks the exchange and forwards the request to the Secret
// Vault, which appraises the Evidence, checks the binding of CEKpub and
// releases the credential sealed to it. The container comes back opaque.
func (a *Acquirer) Retrieve(ctx context.Context, in Retrieval) ([]byte, error) {
	p, err := a.policy(in.Target, ModeRetrieve)
	if err != nil {
		return nil, err
	}
	if err := checkBinding(in.BindingMethod, in.BindingHash); err != nil {
		return nil, err
	}
	profile, err := a.profile(in.EvidenceProfile)
	if err != nil {
		return nil, err
	}
	if len(in.CEKPub) == 0 {
		return nil, status.Error(codes.InvalidArgument, "cek_pub must be specified")
	}
	if a.vault == nil {
		return nil, status.Error(codes.Unavailable, "no Secret Vault is configured")
	}
	// The request is well formed: the single-use Handle is consumed only now.
	if err := a.consumeSession(in.FreshnessKind, in.FreshnessElement, in.Target, in.CredentialType, in.CredentialHint, in.EntryID, in.AgentID); err != nil {
		return nil, err
	}
	leg := &vaultRetrieval{
		FreshnessKind:  in.FreshnessKind,
		Target:         in.Target,
		CredentialType: in.CredentialType,
		Handle:         base64.RawURLEncoding.EncodeToString(in.FreshnessElement),
		CredentialHint: in.CredentialHint,
		CEKPub:         base64.RawURLEncoding.EncodeToString(in.CEKPub),
	}
	switch p.RATSModel {
	case ModelPassport:
		// The Server asks the Verifier that the policy names and forwards the
		// Attestation Results; the Secret Vault verifies them under the keys it holds.
		bv := BindingValue(in.FreshnessElement, in.Target, in.CEKPub)
		ear, _, err := a.appraiser.appraise(ctx, in.Evidence, profile, bv, p.Verifiers)
		switch {
		case errors.Is(err, ErrNoVerifier):
			return nil, status.Errorf(codes.PermissionDenied, "%v", err)
		case errors.Is(err, ErrVerifierUnavailable):
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		case err != nil:
			return nil, status.Errorf(codes.PermissionDenied, "remote attestation failed: %v", err)
		}
		// the Credential Type after the Attestation Results, as at enrollment; in Background Check the Secret Vault
		// appraises and applies its own policy to the type, which this Server relays
		if err := p.servesCredentialType(in.CredentialType); err != nil {
			return nil, err
		}
		leg.EAR = ear
	default:
		leg.Evidence = base64.RawURLEncoding.EncodeToString(in.Evidence)
		leg.Profile = profile
	}
	container, err := a.vault.retrieve(ctx, leg)
	if err != nil {
		return nil, vaultError(err)
	}
	return container, nil
}

func (a *Acquirer) policy(target, mode string) (*Policy, error) {
	if target == "" {
		return nil, status.Error(codes.InvalidArgument, "Target must be specified")
	}
	p, ok := a.policies[target]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "unsupported Target %q", target)
	}
	if mode != "" && p.Mode != mode {
		// Enroll for a Target in retrieve mode, or Retrieve for one in enroll mode,
		// is a malformed request, not a permission failure
		return nil, status.Errorf(codes.InvalidArgument, "Target %q is served in %s mode", target, p.Mode)
	}
	return p, nil
}

// servesCredentialType checks a Credential Type against the policy: one that
// is not a Credential Type of TACRA is invalid; one the policy does not support for
// the Target is refused with Unimplemented, the gRPC code of a feature not
// supported in this service, and the response
// names the ones supported.
func (p *Policy) servesCredentialType(credentialType string) error {
	if credentialType == "" {
		return nil
	}
	if !slices.Contains(credentialTypes, credentialType) {
		return status.Errorf(codes.InvalidArgument, "Credential Type %q is not one of TACRA", credentialType)
	}
	if len(p.CredentialTypes) > 0 && !slices.Contains(p.CredentialTypes, credentialType) {
		return status.Errorf(codes.Unimplemented, "Credential Type %q is not supported for Target %q; supported: %s",
			credentialType, p.Name, strings.Join(p.CredentialTypes, ", "))
	}
	return nil
}

func checkBinding(method, hash string) error {
	if method != BindingMethod || hash != BindingHash {
		return status.Errorf(codes.InvalidArgument, "binding %q with %q is not recognized; this Server accepts %s with %s",
			method, hash, BindingMethod, BindingHash)
	}
	return nil
}

func (a *Acquirer) consumeSession(kind string, element []byte, target, credentialType, hint, entryID, agentID string) error {
	if kind != FreshnessPresentNonce {
		return status.Errorf(codes.InvalidArgument, "Freshness Kind %q differs from %s, the kind named at initiation", kind, FreshnessPresentNonce)
	}
	if len(element) < 16 || len(element) > 64 {
		return status.Errorf(codes.InvalidArgument, "a present-nonce Handle is 16 to 64 octets, not %d", len(element))
	}
	if _, err := a.sessions.consume(element, kind, target, credentialType, hint, entryID, agentID); err != nil {
		return status.Errorf(codes.InvalidArgument, "freshness: %v", err)
	}
	return nil
}

func (a *Acquirer) profile(profile string) (string, error) {
	if profile == "" {
		return a.evidence[0], nil
	}
	if !slices.Contains(a.evidence, profile) {
		return "", status.Errorf(codes.InvalidArgument, "Evidence format %q is not accepted; accepted: %s", profile, strings.Join(a.evidence, ", "))
	}
	return profile, nil
}

// parseCSR parses the CSR, checks its proof of possession, and that its key
// and signature are of one of the acceptable CSK algorithms.
func parseCSR(der []byte, acceptable []string) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "malformed CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid CSR signature: %v", err)
	}
	for _, alg := range acceptable {
		if alg == "ecdsa-p256-sha256" {
			if pub, ok := csr.PublicKey.(*ecdsa.PublicKey); ok && pub.Curve == elliptic.P256() && csr.SignatureAlgorithm == x509.ECDSAWithSHA256 {
				return csr, nil
			}
		}
	}
	return nil, status.Errorf(codes.InvalidArgument, "the CSR key or signature is not one of the acceptable CSK algorithms: %s", strings.Join(acceptable, ", "))
}

// appraise sends the Evidence to the Verifier that the policy names for its
// provider, verifies the Attestation Results against the binding value, and
// applies the platform rules per the policy.
func (a *Acquirer) appraise(ctx context.Context, p *Policy, evidence []byte, profile string, bindingValue []byte) (*earResult, error) {
	ear, name, err := a.appraiser.appraise(ctx, evidence, profile, bindingValue, p.Verifiers)
	switch {
	case errors.Is(err, ErrNoVerifier):
		return nil, status.Errorf(codes.PermissionDenied, "%v", err)
	case errors.Is(err, ErrVerifierUnavailable):
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	case err != nil:
		return nil, status.Errorf(codes.PermissionDenied, "remote attestation failed: %v", err)
	}
	res, err := a.ear.verify(ear, p.Verifiers, bindingValue)
	if err != nil {
		a.log.WithError(err).WithField("verifier", name).Warn("Attestation Results refused")
		return nil, status.Errorf(codes.PermissionDenied, "remote attestation failed: %v", err)
	}
	if !p.AllowAnyMeasurement && !slices.ContainsFunc(p.Measurements, func(m []byte) bool { return bytes.Equal(m, res.Measurement) }) {
		return nil, status.Errorf(codes.PermissionDenied, "remote attestation failed: the launch measurement is not admitted for Target %q: %x", p.Name, res.Measurement)
	}
	if a.platform != nil {
		waived, err := a.platform.Check(res)
		if err != nil {
			a.log.WithError(err).WithField("verifier", name).Warn("Attestation Results refused by the platform rule")
			return nil, status.Errorf(codes.PermissionDenied, "remote attestation failed: %v", err)
		}
		res.waived = waived
		for _, w := range waived {
			a.log.WithField("verifier", name).WithField("waiver", w).Warn("Attestation Results admitted under a waiver of the platform rule")
		}
	} else if res.SNP != nil {
		// Without a platform rule, the guest policy alone: no debug, no migration.
		if res.SNP.policy>>19&1 == 1 {
			return nil, status.Error(codes.PermissionDenied, "remote attestation failed: the guest policy has DEBUG set")
		}
		if res.SNP.policy>>18&1 == 1 {
			return nil, status.Error(codes.PermissionDenied, "remote attestation failed: the guest policy has MIGRATE_MA set")
		}
	}
	return res, nil
}

// vaultError turns a refusal of the Secret Vault into the status the Workload
// sees: the gRPC code of the HTTP status of the refusal, with the reason the
// Secret Vault gives.
func vaultError(err error) error {
	if refusal, ok := errors.AsType[*vaultRefusal](err); ok {
		code := codes.Unavailable
		switch refusal.Status {
		case http.StatusBadRequest, http.StatusUnsupportedMediaType:
			code = codes.InvalidArgument
		case http.StatusForbidden:
			code = codes.PermissionDenied
		case http.StatusUnprocessableEntity:
			code = codes.Unimplemented // a Credential Type the vault does not serve for the Target
		case http.StatusNotFound:
			code = codes.NotFound
		case http.StatusTooManyRequests:
			code = codes.ResourceExhausted
		}
		return status.Errorf(code, "%v", refusal)
	}
	return status.Errorf(codes.Unavailable, "%v", err)
}
