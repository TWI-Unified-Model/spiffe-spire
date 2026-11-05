package credentialacquisition

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrVaultUnavailable is the Secret Vault not answering.
var ErrVaultUnavailable = errors.New("secret vault unavailable")

// vaultRefusal is a refusal of the Secret Vault: its HTTP status and its
// error code and detail, as the TACRA EST profile's RATS Relying Party
// answers them.
type vaultRefusal struct {
	Status int
	Code   string
	Detail string
}

func (e *vaultRefusal) Error() string { return fmt.Sprintf("secret vault: %s: %s", e.Code, e.Detail) }

// vaultClient is the conduit to the Secret Vault of the Targets in retrieve
// mode: the vault is the RATS Relying Party that originates the Freshness
// Handle, appraises the Evidence and releases the credential, sealed to the
// Workload's Credential Encryption Key. The Server forwards the two legs.
type vaultClient struct {
	url    string
	client *http.Client
}

func newVaultClient(c *Config) (*vaultClient, error) {
	if c.SecretVault == nil {
		return nil, nil
	}
	certPath, keyPath := c.ClientCertPath, c.ClientKeyPath
	if c.SecretVault.ClientCertPath != "" || c.SecretVault.ClientKeyPath != "" {
		certPath, keyPath = c.SecretVault.ClientCertPath, c.SecretVault.ClientKeyPath
	}
	tc, err := clientTLS(c.SecretVault.CAPath, certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("secret_vault: %w", err)
	}
	return &vaultClient{
		url:    strings.TrimRight(c.SecretVault.URL, "/"),
		client: &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}},
	}, nil
}

// vaultInitiation is what the vault answers at initiation: the fields of
// the AttestationInitiationResponse of the TACRA EST profile, a byte string
// as unpadded base64url.
type vaultInitiation struct {
	FreshnessKind string   `json:"freshness_kind"`
	Handle        string   `json:"handle,omitempty"`
	ExpiresIn     int      `json:"expires_in,omitempty"`
	MaxAge        int      `json:"max_age,omitempty"`
	Mode          string   `json:"mode"`
	AcceptableCSK []string `json:"acceptable_csk,omitempty"`
	AcceptableCEK []string `json:"acceptable_cek,omitempty"`
}

// vaultRetrieval is the attest-retrieve request as the conduit forwards it
// to the vault: the second leg, the Evidence and CEKpub.
type vaultRetrieval struct {
	FreshnessKind  string `json:"freshness_kind"`
	Target         string `json:"target"`
	CredentialType string `json:"credential_type,omitempty"`
	Handle         string `json:"handle,omitempty"`
	CredentialHint string `json:"credential_hint,omitempty"`
	Evidence       string `json:"evidence,omitempty"` // Background Check: the Attester's Evidence, as it sent it
	Profile        string `json:"profile,omitempty"`  // Background Check: the Evidence's media type
	EAR            string `json:"ear,omitempty"`      // Passport: the Attestation Results the Server obtained
	CEKPub         string `json:"cek_pub"`
}

func (v *vaultClient) initiate(ctx context.Context, target, credentialType, hint string) (*vaultInitiation, []byte, error) {
	body := map[string]string{"target": target}
	if credentialType != "" {
		body["credential_type"] = credentialType
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

func (v *vaultClient) retrieve(ctx context.Context, req *vaultRetrieval) ([]byte, error) {
	var container json.RawMessage
	if err := v.post(ctx, "/tacra/v1/retrieve", req, &container); err != nil {
		return nil, err
	}
	return container, nil
}

func (v *vaultClient) post(ctx context.Context, path string, in, out any) error {
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
