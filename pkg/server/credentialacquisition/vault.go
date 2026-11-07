package credentialacquisition

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// ErrVaultUnavailable is the Secret Vault not answering.
var ErrVaultUnavailable = errors.New("the Secret Vault is unavailable")

// secretVaultKind is the kind of Secret Vault this Server is the conduit to:
// how it forwards the initiate and the retrieve parts of the flow. The
// configuration names the kind; the kinds are listed in secretVaultKinds, and
// another kind is a new type there. The rest of the Server sees a secretVault.
type secretVaultKind interface {
	// Name is the kind as the configuration spells it.
	Name() string
	// Validate checks the configuration of a Secret Vault of the kind.
	Validate(c *SecretVaultConfig) error
	// New builds the Secret Vault of the kind, with the TLS configuration the
	// Server calls it with.
	New(c *SecretVaultConfig, tc *tls.Config) (secretVault, error)
}

// A secretVault is the configured Secret Vault of the Targets in retrieve
// mode: the RATS Relying Party that originates the Freshness Handle, appraises
// the Evidence and releases the credential, sealed to the Credential
// Encryption Key of the Workload. The Server forwards both the initiate and
// the retrieve parts of the flow.
type secretVault interface {
	Initiate(ctx context.Context, target string, credentialType CredentialType, hint string) (*vaultInitiation, []byte, error)
	Retrieve(ctx context.Context, req *vaultRetrieval) ([]byte, error)
}

// secretVaultKinds lists the kinds: json, the one kind for now.
var secretVaultKinds = []secretVaultKind{jsonVaultKind{}}

// defaultSecretVaultKind is used in the absence of configuration.
const defaultSecretVaultKind = "json"

func secretVaultKindNamed(name string) (secretVaultKind, bool) {
	if name == "" {
		name = defaultSecretVaultKind
	}
	i := slices.IndexFunc(secretVaultKinds, func(k secretVaultKind) bool { return k.Name() == name })
	if i < 0 {
		return nil, false
	}
	return secretVaultKinds[i], true
}

func secretVaultKindNames() string {
	names := make([]string, 0, len(secretVaultKinds))
	for _, k := range secretVaultKinds {
		names = append(names, k.Name())
	}
	return strings.Join(names, ", ")
}

// newSecretVault builds the configured Secret Vault by its kind, or none.
func newSecretVault(c *Config) (secretVault, error) {
	if c.SecretVault == nil {
		return nil, nil
	}
	kind, ok := secretVaultKindNamed(c.SecretVault.SecretVaultKind)
	if !ok {
		return nil, fmt.Errorf("secret_vault: kind %q is not one of %s", c.SecretVault.SecretVaultKind, secretVaultKindNames())
	}
	certPath, keyPath := c.ClientCertPath, c.ClientKeyPath
	if c.SecretVault.ClientCertPath != "" || c.SecretVault.ClientKeyPath != "" {
		certPath, keyPath = c.SecretVault.ClientCertPath, c.SecretVault.ClientKeyPath
	}
	tc, err := clientTLS(c.SecretVault.CAPath, certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("secret_vault: %w", err)
	}
	return kind.New(c.SecretVault, tc)
}

// vaultRefusal is a refusal of the Secret Vault: its HTTP status, the error
// code and detail it responds with.
type vaultRefusal struct {
	Status int
	Code   string
	Detail string
}

func (e *vaultRefusal) Error() string { return fmt.Sprintf("Secret Vault: %s: %s", e.Code, e.Detail) }

// vaultInitiation is what the Secret Vault answers at initiation, a byte
// string as unpadded base64url.
type vaultInitiation struct {
	FreshnessKind    FreshnessKind             `json:"freshness_kind"`
	Handle           string                    `json:"handle,omitempty"`
	ExpiresInSeconds int                       `json:"expires_in,omitempty"` // the lifetime of the Handle, in seconds
	MaxAgeSeconds    int                       `json:"max_age,omitempty"`    // how old the Evidence may be, in seconds
	Mode             CredentialAcquisitionMode `json:"mode"`
	AcceptableCSK    []string                  `json:"acceptable_csk,omitempty"`
	AcceptableCEK    []string                  `json:"acceptable_cek,omitempty"`
}

// vaultRetrieval is the attest-retrieve request as the conduit forwards it
// to the Secret Vault: the retrieve part of the flow, with the Evidence and
// CEKpub.
type vaultRetrieval struct {
	FreshnessKind  FreshnessKind  `json:"freshness_kind"`
	Target         string         `json:"target"`
	CredentialType CredentialType `json:"credential_type,omitempty"`
	Handle         string         `json:"handle,omitempty"`
	CredentialHint string         `json:"credential_hint,omitempty"`
	Evidence       string         `json:"evidence,omitempty"` // Background Check: the Evidence of the Attester, as it sent it
	Profile        string         `json:"profile,omitempty"`  // Background Check: the media type of the Evidence
	EAR            string         `json:"ear,omitempty"`      // Passport: the Attestation Results the Server obtained
	CEKPub         string         `json:"cek_pub"`
}

// jsonVaultKind is the kind of Secret Vault of the proof of concept: the TACRA
// calls as JSON over HTTPS, initiate and retrieve posted to /tacra/v1/initiate
// and /tacra/v1/retrieve under the URL of the Secret Vault, a refusal answered
// as an HTTP status with an error code and a detail.
type jsonVaultKind struct{}

func (jsonVaultKind) Name() string { return "json" }

func (jsonVaultKind) Validate(c *SecretVaultConfig) error {
	if c.URL == "" {
		return errors.New("url is required")
	}
	return nil
}

func (jsonVaultKind) New(c *SecretVaultConfig, tc *tls.Config) (secretVault, error) {
	return &jsonVault{
		url:    strings.TrimRight(c.URL, "/"),
		client: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}},
	}, nil
}

// jsonVault is a Secret Vault of kind json.
type jsonVault struct {
	url    string
	client *http.Client
}

func (v *jsonVault) Initiate(ctx context.Context, target string, credentialType CredentialType, hint string) (*vaultInitiation, []byte, error) {
	body := map[string]string{"target": target}
	if credentialType != "" {
		body["credential_type"] = string(credentialType)
	}
	if hint != "" {
		body["credential_hint"] = hint
	}
	var out vaultInitiation
	if err := v.post(ctx, "/tacra/v1/initiate", body, &out); err != nil {
		return nil, nil, err
	}
	var handle []byte
	if out.Handle != "" {
		var err error
		if handle, err = base64.RawURLEncoding.DecodeString(out.Handle); err != nil {
			return nil, nil, fmt.Errorf("%w: the Handle is not base64url", ErrVaultUnavailable)
		}
	}
	return &out, handle, nil
}

func (v *jsonVault) Retrieve(ctx context.Context, req *vaultRetrieval) ([]byte, error) {
	var container json.RawMessage
	if err := v.post(ctx, "/tacra/v1/retrieve", req, &container); err != nil {
		return nil, err
	}
	return container, nil
}

func (v *jsonVault) post(ctx context.Context, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVaultUnavailable, err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVaultUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVaultUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		refusal := &vaultRefusal{Status: resp.StatusCode}
		var e struct {
			Error  string `json:"error"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(raw, &e) == nil && e.Error != "" {
			refusal.Code, refusal.Detail = e.Error, e.Detail
		} else {
			refusal.Code, refusal.Detail = "http-"+fmt.Sprint(resp.StatusCode), strings.TrimSpace(string(raw))
		}
		return refusal
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("%w: malformed answer: %w", ErrVaultUnavailable, err)
	}
	return nil
}
