// Package credentialacquisition is the Credential Acquisition System Server of
// draft-novak-rats-tacra (TACRA) inside SPIRE Server, behind the
// CredentialAcquisition Server API. The Client is the Agent (pkg/agent); the
// Attester is the Workload. For a Workload the Agent attested, this Server
// issues the Freshness Handle, sends the Evidence to a RATS Verifier, and
// verifies the Attestation Results and the binding of the Attester-held key to
// the Evidence. In Enrollment, SPIRE Server is the Identity Provider as well:
// its CA mints the X509-SVID, so the Credential Authority of TACRA and this
// Server are one process. In Retrieval, the Identity Provider is the Secret
// Vault, and this Server is the conduit that returns the credential the Secret
// Vault released, sealed to the key of the Workload.
package credentialacquisition

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// CredentialAcquisitionMode is a Credential Acquisition Mode of TACRA. The
// configuration spells it as one of two names, which Validate checks.
type CredentialAcquisitionMode string

// The Credential Acquisition Modes of TACRA.
const (
	ModeEnroll   CredentialAcquisitionMode = "enroll"
	ModeRetrieve CredentialAcquisitionMode = "retrieve"
)

// The RATS models a Target in retrieve mode is served in. In the Passport RATS
// model, the Server, as the conduit, obtains the Attestation Results from the
// Verifier for the Target and forwards them to the Secret Vault. In the
// Background Check RATS model, the Server forwards the Evidence, and the Secret
// Vault asks the Verifier itself.
type RATSModel string

// The two RATS models.
const (
	ModelPassport        RATSModel = "passport"
	ModelBackgroundCheck RATSModel = "background-check"
)

// FreshnessKind is a Freshness Kind of TACRA: how the Freshness Element of an
// exchange is produced, and by whom. The configuration and the API spell it
// as one of five names.
type FreshnessKind string

// The Freshness Kinds of TACRA. This Server issues present-nonce Handles.
const (
	FreshnessPresentNonce    FreshnessKind = "present-nonce"
	FreshnessPresentEpoch    FreshnessKind = "present-epoch"
	FreshnessAbsentTimestamp FreshnessKind = "absent-timestamp"
	FreshnessAbsentEpoch     FreshnessKind = "absent-epoch"
	FreshnessAbsentNone      FreshnessKind = "absent-none"
)

// CredentialType is a Credential Type of TACRA. The configuration and the
// API spell it as one of the names below.
type CredentialType string

// The Credential Types of TACRA.
const (
	CredentialTypeX509       CredentialType = "x509"
	CredentialTypeWIC        CredentialType = "wic"
	CredentialTypeWIT        CredentialType = "wit"
	CredentialTypeJWT        CredentialType = "jwt"
	CredentialTypeAPIKey     CredentialType = "api-key"
	CredentialTypePSK        CredentialType = "psk"
	CredentialTypePrivateKey CredentialType = "private-key"
)

// credentialTypes lists the Credential Types of TACRA.
var credentialTypes = []CredentialType{CredentialTypeX509, CredentialTypeWIC, CredentialTypeWIT, CredentialTypeJWT,
	CredentialTypeAPIKey, CredentialTypePSK, CredentialTypePrivateKey}

// The Credential Types Enrollment mints.
var enrollableCredentialTypes = []CredentialType{CredentialTypeX509, CredentialTypeWIC}

// The CSK algorithms this Server accepts, by the names acceptable_csk carries.
var supportedCSKAlgorithms = []string{"ecdsa-p256-sha256"}

// Config is the credential_acquisition block of the experimental
// configuration of the Server.
type Config struct {
	// Target holds the policy for each Target this Server serves, keyed by the
	// Target name: the octet string the Workload names in its calls.
	Target map[string]*TargetConfig `hcl:"target"`

	// Verifier, by name, is a RATS Verifier this Server sends Evidence to
	// and whose Attestation Results it accepts. The policy for a Target names the
	// Verifiers it accepts.
	Verifier map[string]*VerifierConfig `hcl:"verifier"`

	// AcceptableEvidence is the list of Evidence formats this Server
	// forwards, each named by its media type, for example
	// application/vnd.veraison.tsm-report+cbor.
	AcceptableEvidence []string `hcl:"acceptable_evidence"`

	// EARMaxAge is how old Attestation Results may be: a duration with its unit,
	// as Go writes it, for example 2m or 90s; the default is 2m.
	EARMaxAge string `hcl:"ear_max_age"`

	// EARSkew is how far in the future Attestation Results may be dated: a
	// duration with its unit, for example 5s; the default is 5s.
	EARSkew string `hcl:"ear_skew"`

	// ClientCertPath and ClientKeyPath hold the certificate and key this
	// Server presents to the Verifiers and the Secret Vault over mutual TLS.
	ClientCertPath string `hcl:"client_cert_path"`
	ClientKeyPath  string `hcl:"client_key_path"`

	// SecretVault is the Secret Vault behind the Targets in retrieve mode.
	SecretVault *SecretVaultConfig `hcl:"secret_vault"`

	// PlatformRulePath is the file holding the platform rule applied to
	// affirming Attestation Results of every Target: the machine, the product
	// line, the TCB floors, the mitigations and the guest policy for SEV-SNP,
	// the TD attributes for TDX. The guest policy is the POLICY field of the
	// SEV-SNP report: the launch settings of the guest, among them whether
	// debugging and migration are allowed (AMD 56860, Table 12). Without a rule,
	// only the debug and migration bits of the guest policy are refused.
	PlatformRulePath string `hcl:"platform_rule_path"`

	// SEVSNPProductsPath is the file holding the product data of AMD the
	// platform module for SEV-SNP reads reports with: the product lines, the
	// CPUID family and extended model that report each, and the byte of each
	// component in TCB_VERSION. Without it, the Server uses the copy it ships.
	// The file is JSON, in the format of that copy.
	SEVSNPProductsPath string `hcl:"sevsnp_products_path"`
}

// TargetConfig is the policy for one Target.
type TargetConfig struct {
	// Mode is enroll or retrieve.
	Mode CredentialAcquisitionMode `hcl:"mode"`

	// CredentialTypes are the Credential Types served for the Target.
	// Enrollment serves x509 and wic.
	CredentialTypes []CredentialType `hcl:"credential_types"`

	// FreshnessKind is the Freshness Kind of the exchanges of the Target. This
	// Server issues present-nonce Handles; a Target in retrieve mode uses
	// the kind its Secret Vault answers.
	FreshnessKind FreshnessKind `hcl:"freshness_kind"`

	// ExpiresIn is the lifetime of a Freshness Handle: a duration with its unit,
	// for example 5m or 300s; the default is 5m, and TACRA recommends at least
	// 1m.
	ExpiresIn string `hcl:"expires_in"`

	// Verifiers names the Verifiers whose Attestation Results the policy
	// accepts for this Target, among those configured. In retrieve mode, the
	// Verifiers the Server asks when the RATS model is passport.
	Verifiers []string `hcl:"verifiers"`

	// RATSModel is, for a Target in retrieve mode, passport or
	// background-check (the default): who asks the Verifier, this Server or
	// the Secret Vault.
	RATSModel RATSModel `hcl:"rats_model"`

	// AcceptableCSK lists the CSK algorithms the Credential Authority
	// accepts for enrollment (default ecdsa-p256-sha256).
	AcceptableCSK []string `hcl:"acceptable_csk"`

	// Measurements lists the launch measurements admitted, in hex. A
	// measurement not listed is refused unless AllowAnyMeasurement is set.
	Measurements []string `hcl:"measurements"`

	// AllowAnyMeasurement admits any affirming Attestation Results whatever
	// the launch measurement. For bring-up only.
	AllowAnyMeasurement bool `hcl:"allow_any_measurement"`
}

// VerifierConfig is one RATS Verifier.
type VerifierConfig struct {
	// VerifierKind is the kind of Verifier: how the Server sends it Evidence
	// and reads its Attestation Results. The Veraison kind, veraison, is the
	// default and the one kind for now.
	VerifierKind string `hcl:"kind"`

	// URL is the base URL of the API of the Verifier: for the Veraison kind,
	// its challenge-response API.
	URL string `hcl:"url"`

	// CAPath is the file holding the certificate of the CA that signed the TLS
	// certificate of the Verifier: the Server trusts that CA, so the Verifier
	// rotates its own certificate under it without a change here.
	CAPath string `hcl:"ca_path"`

	// EARKeyPath, for the Veraison kind, is the file holding the public key the
	// Verifier signs its Attestation Results with: an EC P-256 public JWK, or
	// a PEM public key. It is provisioned, never fetched.
	EARKeyPath string `hcl:"ear_key_path"`

	// Provider is the TSM report provider of the Evidence this Verifier
	// appraises: sev_guest or tdx_guest.
	Provider string `hcl:"provider"`

	// Submods, for the Veraison kind, names the EAR submodules the Verifier speaks
	// for, each of a platform family: SEVSNP, TDX.
	Submods []string `hcl:"submods"`
}

// SecretVaultConfig is the Secret Vault of the Targets in retrieve mode.
type SecretVaultConfig struct {
	// SecretVaultKind is the kind of Secret Vault: how the Server forwards the
	// initiate and the retrieve parts of the flow to it. json, the TACRA calls
	// as JSON over HTTPS, is the default and the one kind for now.
	SecretVaultKind string `hcl:"kind"`

	// URL is the base URL of the API of the Secret Vault.
	URL string `hcl:"url"`

	// CAPath is the file holding the certificate of the CA that signed the TLS
	// certificate of the Secret Vault: the Server trusts that CA, so the Secret
	// Vault rotates its own certificate under it without a change here.
	CAPath string `hcl:"ca_path"`

	// ClientCertPath and ClientKeyPath, when set, are the certificate and key
	// this Server presents to the Secret Vault instead of the ones it presents to
	// the verifiers.
	ClientCertPath string `hcl:"client_cert_path"`
	ClientKeyPath  string `hcl:"client_key_path"`
}

// Policy is the parsed policy of one Target.
type Policy struct {
	Name                string
	Mode                CredentialAcquisitionMode
	CredentialTypes     []CredentialType
	FreshnessKind       FreshnessKind
	ExpiresIn           time.Duration
	Verifiers           []string
	AcceptableCSK       []string
	Measurements        [][]byte
	AllowAnyMeasurement bool
	RATSModel           RATSModel
}

// Validate returns the parsed policies of a correct configuration, and the
// first error it finds otherwise.
func (c *Config) Validate() (map[string]*Policy, error) {
	if len(c.Target) == 0 {
		return nil, errors.New("credential_acquisition: at least one Target is required")
	}
	if len(c.AcceptableEvidence) == 0 {
		return nil, errors.New("credential_acquisition: acceptable_evidence is required")
	}
	for name, v := range c.Verifier {
		if v == nil {
			return nil, fmt.Errorf("credential_acquisition: Verifier %q is empty", name)
		}
		kind, ok := verifierKindNamed(v.VerifierKind)
		if !ok {
			return nil, fmt.Errorf("credential_acquisition: Verifier %q: kind %q is not one of %s", name, v.VerifierKind, verifierKindNames())
		}
		if v.Provider == "" {
			return nil, fmt.Errorf("credential_acquisition: Verifier %q: provider is required", name)
		}
		if err := kind.Validate(v); err != nil {
			return nil, fmt.Errorf("credential_acquisition: Verifier %q: %w", name, err)
		}
	}
	if _, err := parseDuration(c.EARMaxAge, 2*time.Minute); err != nil {
		return nil, fmt.Errorf("credential_acquisition: ear_max_age: %w", err)
	}
	if _, err := parseDuration(c.EARSkew, 5*time.Second); err != nil {
		return nil, fmt.Errorf("credential_acquisition: ear_skew: %w", err)
	}
	if c.SecretVault != nil {
		kind, ok := secretVaultKindNamed(c.SecretVault.SecretVaultKind)
		if !ok {
			return nil, fmt.Errorf("credential_acquisition: secret_vault: kind %q is not one of %s", c.SecretVault.SecretVaultKind, secretVaultKindNames())
		}
		if err := kind.Validate(c.SecretVault); err != nil {
			return nil, fmt.Errorf("credential_acquisition: secret_vault: %w", err)
		}
	}

	policies := make(map[string]*Policy, len(c.Target))
	for name, t := range c.Target {
		p, err := t.policy(name, c)
		if err != nil {
			return nil, err
		}
		policies[name] = p
	}
	return policies, nil
}

func (t *TargetConfig) policy(name string, c *Config) (*Policy, error) {
	fail := func(format string, args ...any) (*Policy, error) {
		return nil, fmt.Errorf("credential_acquisition: Target %q: "+format, append([]any{name}, args...)...)
	}
	if t == nil {
		return fail("is empty")
	}
	if name == "" {
		return fail("the Target name is required")
	}
	p := &Policy{
		Name:                name,
		Mode:                t.Mode,
		CredentialTypes:     t.CredentialTypes,
		FreshnessKind:       t.FreshnessKind,
		Verifiers:           t.Verifiers,
		AcceptableCSK:       t.AcceptableCSK,
		AllowAnyMeasurement: t.AllowAnyMeasurement,
	}
	switch p.Mode {
	case ModeEnroll:
		if len(p.CredentialTypes) == 0 {
			p.CredentialTypes = []CredentialType{CredentialTypeX509}
		}
		for _, ct := range p.CredentialTypes {
			if !slices.Contains(enrollableCredentialTypes, ct) {
				return fail("Credential Type %q cannot be enrolled; enrollment mints %v", ct, enrollableCredentialTypes)
			}
		}
		if p.FreshnessKind == "" {
			p.FreshnessKind = FreshnessPresentNonce
		}
		if p.FreshnessKind != FreshnessPresentNonce {
			return fail("freshness_kind %q is not supported; this Server issues present-nonce Handles", p.FreshnessKind)
		}
		if len(p.AcceptableCSK) == 0 {
			p.AcceptableCSK = slices.Clone(supportedCSKAlgorithms)
		}
		for _, alg := range p.AcceptableCSK {
			if !slices.Contains(supportedCSKAlgorithms, alg) {
				return fail("acceptable_csk %q is not supported; supported: %v", alg, supportedCSKAlgorithms)
			}
		}
		if len(p.Verifiers) == 0 {
			return fail("at least one Verifier must be configured")
		}
		for _, v := range p.Verifiers {
			if _, ok := c.Verifier[v]; !ok {
				return fail("Verifier %q is not configured", v)
			}
		}
		for _, m := range t.Measurements {
			b, err := decodeHex(m)
			if err != nil {
				return fail("measurement %q is not hex", m)
			}
			p.Measurements = append(p.Measurements, b)
		}
		if len(p.Measurements) == 0 && !p.AllowAnyMeasurement {
			return fail("measurements is required, or allow_any_measurement for bring-up")
		}
	case ModeRetrieve:
		if c.SecretVault == nil {
			return fail("retrieve mode needs a secret_vault")
		}
		switch t.RATSModel {
		case "", ModelBackgroundCheck:
			p.RATSModel = ModelBackgroundCheck
		case ModelPassport:
			p.RATSModel = ModelPassport
			if len(p.Verifiers) == 0 {
				return fail("the Passport RATS model requires one or more Verifiers: the Server obtains the Attestation Results")
			}
			for _, v := range p.Verifiers {
				if _, ok := c.Verifier[v]; !ok {
					return fail("Verifier %q is not configured", v)
				}
			}
		default:
			return fail("rats_model %q is not %s or %s", t.RATSModel, ModelPassport, ModelBackgroundCheck)
		}
		for _, ct := range p.CredentialTypes {
			if !slices.Contains(credentialTypes, ct) {
				return fail("Credential Type %q is not one of TACRA", ct)
			}
		}
		if p.FreshnessKind != "" && p.FreshnessKind != FreshnessPresentNonce {
			return fail("freshness_kind %q is not supported; the Secret Vault issues present-nonce Handles", p.FreshnessKind)
		}
		p.FreshnessKind = FreshnessPresentNonce
	case "":
		return fail("mode is required: enroll or retrieve")
	default:
		return fail("mode %q is not %s or %s", p.Mode, ModeEnroll, ModeRetrieve)
	}
	expiresIn, err := parseDuration(t.ExpiresIn, 5*time.Minute)
	if err != nil {
		return fail("expires_in: %v", err)
	}
	if expiresIn < time.Minute {
		return fail("expires_in %s is below the minimum of %s that TACRA recommends for a Freshness Handle", expiresIn, time.Minute)
	}
	p.ExpiresIn = expiresIn
	return p, nil
}

func parseDuration(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s is not positive", s)
	}
	return d, nil
}
