package credentialacquisition

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Refusals of the appraisal.
var (
	ErrNoVerifier          = errors.New("none of the verifiers the Target's policy takes appraises Evidence of this provider")
	ErrVerifierUnavailable = errors.New("verifier unavailable")
	ErrNoResults           = errors.New("the verifier produced no Attestation Results")
)

// verifier is one RATS Verifier the Server sends Evidence to, over mutual
// TLS with the Server's own client certificate, through Veraison's
// challenge-response API: a session opened with a nonce, here the binding
// value the Server recomputed, and the Evidence posted to it.
type verifier struct {
	name     string
	provider string
	url      string
	client   *http.Client
}

// appraiser holds the verifiers; a Target's policy names the ones it takes.
type appraiser struct {
	verifiers []verifier
}

func newAppraiser(c *Config) (*appraiser, error) {
	a := &appraiser{}
	for name, v := range c.Verifier {
		tc, err := clientTLS(v.CAPath, c.ClientCertPath, c.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("verifier %q: %w", name, err)
		}
		a.verifiers = append(a.verifiers, verifier{
			name:     name,
			provider: v.Provider,
			url:      strings.TrimRight(v.URL, "/"),
			client:   &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}},
		})
	}
	slices.SortFunc(a.verifiers, func(x, y verifier) int { return strings.Compare(x.name, y.name) })
	return a, nil
}

// route picks, among the verifiers the Target's policy takes, the one for
// the Evidence's TSM report provider. The policy chooses the verifier; the
// Evidence only picks among those, and there is no default for the rest.
func (a *appraiser) route(evidence []byte, accept []string) (*verifier, error) {
	var t struct {
		Provider string `cbor:"provider"`
	}
	provider := ""
	if cbor.Unmarshal(evidence, &t) == nil {
		provider = strings.TrimSpace(t.Provider)
	}
	for i := range a.verifiers {
		v := &a.verifiers[i]
		if slices.Contains(accept, v.name) && v.provider != "" && v.provider == provider {
			return v, nil
		}
	}
	return nil, fmt.Errorf("%w: provider %q, verifiers %v", ErrNoVerifier, provider, accept)
}

// appraise runs one challenge-response session with the verifier the
// policy takes for the Evidence and returns its Attestation Results, not
// yet verified, and the verifier's name.
func (a *appraiser) appraise(ctx context.Context, evidence []byte, mediaType string, nonce []byte, accept []string) (string, string, error) {
	v, err := a.route(evidence, accept)
	if err != nil {
		return "", "", err
	}
	q := url.Values{"nonce": {base64.URLEncoding.EncodeToString(nonce)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url+"/challenge-response/v1/newSession?"+q.Encode(), nil)
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrVerifierUnavailable, err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s: %w", ErrVerifierUnavailable, v.name, err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusCreated || loc == "" {
		return "", "", fmt.Errorf("%w: %s refused a session: HTTP %d", ErrVerifierUnavailable, v.name, resp.StatusCode)
	}
	if !strings.HasPrefix(loc, "http") {
		loc = v.url + "/challenge-response/v1/" + strings.TrimPrefix(loc, "/")
	}
	defer func() {
		if del, err := http.NewRequestWithContext(context.WithoutCancel(ctx), http.MethodDelete, loc, nil); err == nil {
			if r, err := v.client.Do(del); err == nil {
				r.Body.Close()
			}
		}
	}()
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, loc, bytes.NewReader(evidence))
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrVerifierUnavailable, err)
	}
	req.Header.Set("Content-Type", mediaType)
	req.Header.Set("Accept", "application/vnd.veraison.challenge-response-session+json")
	resp, err = v.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s: %w", ErrVerifierUnavailable, v.name, err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	var s struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Status != "complete" || s.Result == "" {
		return "", "", fmt.Errorf("%w: %s answered HTTP %d", ErrNoResults, v.name, resp.StatusCode)
	}
	return s.Result, v.name, nil
}

// clientTLS is the TLS configuration for a verifier or the Secret Vault: its
// CA, and this Server's client certificate when configured.
func clientTLS(caPath, certPath, keyPath string) (*tls.Config, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no certificate", caPath)
		}
		tc.RootCAs = pool
	}
	if certPath != "" || keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}
