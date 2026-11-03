// Package credentialacquisition implements the Credential Acquisition System
// Server of draft-novak-rats-tacra (TACRA) in SPIRE Server, behind the
// CredentialAcquisition server API: for a workload an agent attested, it
// issues the Freshness Handle, sends the workload's Evidence to a RATS
// Verifier, verifies the Attestation Results and the binding of the
// credential key to the Evidence, and, as the Credential Authority, lets the
// server's CA mint an X509-SVID for the key, or, as the conduit to a Secret
// Vault, returns the credential the vault released sealed to the key.
package credentialacquisition

import (
	"errors"
	"fmt"
	"slices"
	"time"
)

// The Credential Acquisition Modes of TACRA.
const (
	ModeEnroll   = "enroll"
	ModeRetrieve = "retrieve"
)

// The RATS models a Target in retrieve mode is served in: in Passport the
// server, as the conduit, obtains the Attestation Results from the Target's
// verifier and forwards them to the Secret Vault; in Background Check it
// forwards the Evidence, and the vault asks the verifier itself.
const (
	ModelPassport        = "passport"
	ModelBackgroundCheck = "background-check"
)

// The Freshness Kinds of TACRA, as the TACRA EST profile names them.
const (
	FreshnessPresentNonce    = "present-nonce"
	FreshnessPresentEpoch    = "present-epoch"
	FreshnessAbsentTimestamp = "absent-timestamp"
	FreshnessAbsentEpoch     = "absent-epoch"
	FreshnessAbsentNone      = "absent-none"
)

// The Credential Type tokens of TACRA.
var credentialTypeTokens = []string{"x509", "wic", "wit", "jwt", "api-key", "psk", "private-key"}

// The Credential Types Enrollment mints.
var enrollableCredentialTypes = []string{"x509", "wic"}

// The CSK algorithm tokens of the TACRA EST profile this server accepts.
var supportedCSKAlgorithms = []string{"ecdsa-p256-sha256"}

// Config is the credential_acquisition block of the server's experimental
// configuration.
type Config struct {
	// Target, by Target name, is the policy for each Target this server
	// serves: the octet string the workload names in its calls.
	Target map[string]*TargetConfig `hcl:"target"`

	// Verifier, by name, is a RATS Verifier this server sends Evidence to
	// and whose Attestation Results it accepts. A Target's policy names the
	// verifiers it takes.
	Verifier map[string]*VerifierConfig `hcl:"verifier"`

	// AcceptableEvidence is the list of Evidence formats this server
	// forwards, each named by its media type, for example
	// application/vnd.veraison.tsm-report+cbor.
	AcceptableEvidence []string `hcl:"acceptable_evidence"`

	// EARMaxAge is how old Attestation Results may be (default 2m).
	EARMaxAge string `hcl:"ear_max_age"`

	// EARSkew is how far in the future Attestation Results may be dated
	// (default 5s).
	EARSkew string `hcl:"ear_skew"`

	// ClientCertPath and ClientKeyPath hold the certificate and key this
	// server presents to the verifiers and the Secret Vault over mutual TLS.
	ClientCertPath string `hcl:"client_cert_path"`
	ClientKeyPath  string `hcl:"client_key_path"`

	// SecretVault is the Secret Vault behind the Targets in retrieve mode.
	SecretVault *SecretVaultConfig `hcl:"secret_vault"`

	// PlatformRulePath is the file holding the platform rule applied to
	// affirming Attestation Results of every Target: the machine, the product
	// line, the TCB floors, the mitigations and the guest policy for SEV-SNP,
	// the TD attributes for TDX. Without it, only the guest policy's debug and
	// migration bits are refused.
	PlatformRulePath string `hcl:"platform_rule_path"`
}

// TargetConfig is the policy for one Target.
type TargetConfig struct {
	// Mode is enroll or retrieve.
	Mode string `hcl:"mode"`

	// CredentialTypes are the Credential Type tokens served for the Target.
	// Enrollment serves x509 and wic.
	CredentialTypes []string `hcl:"credential_types"`

	// FreshnessKind is the Freshness Kind of the Target's exchanges. This
	// server issues present-nonce Handles; a Target in retrieve mode takes
	// the kind its Secret Vault answers.
	FreshnessKind string `hcl:"freshness_kind"`

	// ExpiresIn is the lifetime of a Freshness Handle (default 5m, at least
	// 1m as TACRA recommends).
	ExpiresIn string `hcl:"expires_in"`

	// Verifiers names the verifiers whose Attestation Results the policy
	// takes for this Target, among those configured. In retrieve mode, the
	// verifiers the server asks when the RATS model is passport.
	Verifiers []string `hcl:"verifiers"`

	// RATSModel is, for a Target in retrieve mode, passport or
	// background-check (the default): who asks the verifier, this server or
	// the Secret Vault.
	RATSModel string `hcl:"rats_model"`

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
	// URL is the base URL of the verifier's challenge-response API.
	URL string `hcl:"url"`

	// CAPath is the file holding the CA certificate of the verifier's TLS
	// certificate.
	CAPath string `hcl:"ca_path"`

	// EARKeyPath is the file holding the public key the verifier signs its
	// Attestation Results with: an EC P-256 public JWK, or a PEM public key.
	// It is provisioned, never fetched.
	EARKeyPath string `hcl:"ear_key_path"`

	// Provider is the TSM report provider of the Evidence this verifier
	// appraises: sev_guest or tdx_guest.
	Provider string `hcl:"provider"`

	// Submods names the EAR submodules the verifier's key speaks for, for
	// example SEVSNP.
	Submods []string `hcl:"submods"`
}

// SecretVaultConfig is the Secret Vault of the Targets in retrieve mode.
type SecretVaultConfig struct {
	// URL is the base URL of the vault's TACRA API.
	URL string `hcl:"url"`

	// CAPath is the file holding the CA certificate of the vault's TLS
	// certificate.
	CAPath string `hcl:"ca_path"`

	// ClientCertPath and ClientKeyPath, when set, are the certificate and key
	// this server presents to the vault instead of the ones it presents to
	// the verifiers.
	ClientCertPath string `hcl:"client_cert_path"`
	ClientKeyPath  string `hcl:"client_key_path"`
}

// Policy is the parsed policy of one Target.
type Policy struct {
	Name                string
	Mode                string
	CredentialTypes     []string
	FreshnessKind       string
	ExpiresIn           time.Duration
	Verifiers           []string
	AcceptableCSK       []string
	Measurements        [][]byte
	AllowAnyMeasurement bool
	RATSModel           string
}

// Validate checks the configuration and returns the parsed policies.
func (c *Config) Validate() (map[string]*Policy, error) {
	if len(c.Target) == 0 {
		return nil, errors.New("credential_acquisition: at least one target is required")
	}
	if len(c.AcceptableEvidence) == 0 {
		return nil, errors.New("credential_acquisition: acceptable_evidence is required")
	}
	for name, v := range c.Verifier {
		switch {
		case v == nil:
			return nil, fmt.Errorf("credential_acquisition: verifier %q is empty", name)
		case v.URL == "":
			return nil, fmt.Errorf("credential_acquisition: verifier %q: url is required", name)
		case v.EARKeyPath == "":
			return nil, fmt.Errorf("credential_acquisition: verifier %q: ear_key_path is required", name)
		case v.Provider == "":
			return nil, fmt.Errorf("credential_acquisition: verifier %q: provider is required", name)
		case len(v.Submods) == 0:
			return nil, fmt.Errorf("credential_acquisition: verifier %q: submods is required", name)
		}
	}
	if _, err := parseDuration(c.EARMaxAge, 2*time.Minute); err != nil {
		return nil, fmt.Errorf("credential_acquisition: ear_max_age: %w", err)
	}
	if _, err := parseDuration(c.EARSkew, 5*time.Second); err != nil {
		return nil, fmt.Errorf("credential_acquisition: ear_skew: %w", err)
	}
	if c.SecretVault != nil && c.SecretVault.URL == "" {
		return nil, errors.New("credential_acquisition: secret_vault: url is required")
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
		return nil, fmt.Errorf("credential_acquisition: target %q: "+format, append([]any{name}, args...)...)
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
			p.CredentialTypes = []string{"x509"}
		}
		for _, ct := range p.CredentialTypes {
			if !slices.Contains(enrollableCredentialTypes, ct) {
				return fail("credential type %q cannot be enrolled; enrollment mints %v", ct, enrollableCredentialTypes)
			}
		}
		if p.FreshnessKind == "" {
			p.FreshnessKind = FreshnessPresentNonce
		}
		if p.FreshnessKind != FreshnessPresentNonce {
			return fail("freshness_kind %q is not supported; this server issues present-nonce Handles", p.FreshnessKind)
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
			return fail("verifiers is required: the Attestation Results of no verifier are taken otherwise")
		}
		for _, v := range p.Verifiers {
			if _, ok := c.Verifier[v]; !ok {
				return fail("verifier %q is not configured", v)
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
				return fail("rats_model passport needs verifiers: the server obtains the Attestation Results")
			}
			for _, v := range p.Verifiers {
				if _, ok := c.Verifier[v]; !ok {
					return fail("verifier %q is not configured", v)
				}
			}
		default:
			return fail("rats_model %q is not passport or background-check", t.RATSModel)
		}
		for _, ct := range p.CredentialTypes {
			if !slices.Contains(credentialTypeTokens, ct) {
				return fail("credential type %q is not a TACRA token", ct)
			}
		}
		if p.FreshnessKind != "" && p.FreshnessKind != FreshnessPresentNonce {
			return fail("freshness_kind %q is not supported; the Secret Vault issues present-nonce Handles", p.FreshnessKind)
		}
		p.FreshnessKind = FreshnessPresentNonce
	case "":
		return fail("mode is required: enroll or retrieve")
	default:
		return fail("mode %q is not enroll or retrieve", p.Mode)
	}
	expiresIn, err := parseDuration(t.ExpiresIn, 5*time.Minute)
	if err != nil {
		return fail("expires_in: %v", err)
	}
	if expiresIn < time.Minute {
		return fail("expires_in %s is below the minute TACRA recommends for a Freshness Handle", expiresIn)
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
