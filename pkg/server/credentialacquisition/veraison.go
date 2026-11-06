package credentialacquisition

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// veraisonKind is the kind of Verifier of the proof of concept: Veraison. The
// Server opens a session of its challenge-response API with the binding value
// as the nonce and posts the Evidence to it. The Attestation Results are an
// EAR (RFC 9711 EAT in a JWT signed ES256) under a key provisioned here, never
// fetched, with the claims of one platform family under an EAR submodule.
type veraisonKind struct{}

// earProfile is how an EAR names its own format, in eat_profile. Attestation
// Results that name another are not what a Verifier of this kind issues, and
// are refused with both names.
const earProfile = "tag:github.com,2023:veraison/ear"

// veraisonFamilies is the platform family of each EAR submodule a Verifier of
// this kind annotates.
var veraisonFamilies = map[string]string{"SEVSNP": familySEVSNP, "TDX": familyTDX}

func (veraisonKind) Name() string { return "veraison" }

// Validate checks the configuration of a Veraison Verifier: its URL, the key
// its Attestation Results are verified with, and the EAR submodules it speaks
// for, each of a platform family this Server knows.
func (veraisonKind) Validate(c *VerifierConfig) error {
	switch {
	case c.URL == "":
		return errors.New("url is required")
	case c.EARKeyPath == "":
		return errors.New("ear_key_path is required")
	case len(c.Submods) == 0:
		return errors.New("submods is required")
	}
	for _, s := range c.Submods {
		if _, ok := veraisonFamilies[s]; !ok {
			return fmt.Errorf("submods: %q is not an EAR submodule of a platform family this Server knows (%s)",
				s, strings.Join(slices.Sorted(maps.Keys(veraisonFamilies)), ", "))
		}
	}
	return nil
}

func (veraisonKind) New(name string, c *VerifierConfig, tc *tls.Config, window resultsWindow) (verifierClient, error) {
	key, err := loadEARKey(c.EARKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ear_key_path: %w", err)
	}
	return &veraisonVerifier{
		name:     name,
		provider: c.Provider,
		url:      strings.TrimRight(c.URL, "/"),
		client:   &http.Client{Timeout: 60 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}},
		key:      key,
		submods:  c.Submods,
		window:   window,
	}, nil
}

// veraisonVerifier is one Veraison Verifier: the Server calls it over mutual
// TLS with the client certificate of the Server, and verifies its Attestation
// Results with the key provisioned for it.
type veraisonVerifier struct {
	name     string
	provider string
	url      string
	client   *http.Client
	key      *ecdsa.PublicKey // the key its Attestation Results are signed with
	submods  []string         // the EAR submodules it speaks for
	window   resultsWindow
}

func (v *veraisonVerifier) Name() string     { return v.name }
func (v *veraisonVerifier) Kind() string     { return veraisonKind{}.Name() }
func (v *veraisonVerifier) Provider() string { return v.provider }

// Appraise runs one challenge-response session with the Verifier and returns
// its Attestation Results, not yet verified: a session opened with the nonce,
// the Evidence posted to it, the session deleted after use.
func (v *veraisonVerifier) Appraise(ctx context.Context, evidence []byte, mediaType string, nonce []byte) (string, error) {
	q := url.Values{"nonce": {base64.URLEncoding.EncodeToString(nonce)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url+"/challenge-response/v1/newSession?"+q.Encode(), nil)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrVerifierUnavailable, err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrVerifierUnavailable, v.name, err)
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusCreated || loc == "" {
		return "", fmt.Errorf("%w: %s refused a session: HTTP %d", ErrVerifierUnavailable, v.name, resp.StatusCode)
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
		return "", fmt.Errorf("%w: %w", ErrVerifierUnavailable, err)
	}
	req.Header.Set("Content-Type", mediaType)
	req.Header.Set("Accept", "application/vnd.veraison.challenge-response-session+json")
	resp, err = v.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrVerifierUnavailable, v.name, err)
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	var s struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if json.Unmarshal(raw, &s) != nil || s.Status != "complete" || s.Result == "" {
		return "", fmt.Errorf("%w: %s answered HTTP %d", ErrNoResults, v.name, resp.StatusCode)
	}
	return s.Result, nil
}

// Verify checks the EAR: signed by the key provisioned for this Verifier,
// naming the EAR profile, issued within the accepted window, carrying the
// expected nonce as eat_nonce, and affirming for a submodule this Verifier
// speaks for. It reads the claims of the platform family of that submodule.
func (v *veraisonVerifier) Verify(jws string, expectedNonce []byte) (*attestationResults, error) {
	sig, err := jose.ParseSigned(jws, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEARMalformed, err)
	}
	payload, err := sig.Verify(v.key)
	if err != nil {
		return nil, ErrEARSignature
	}
	var claims struct {
		Profile string `json:"eat_profile"`
		Nonce   string `json:"eat_nonce"`
		IAT     int64  `json:"iat"`
		Submods map[string]struct {
			Status   string          `json:"ear.status"`
			Evidence json.RawMessage `json:"ear.veraison.annotated-evidence"`
		} `json:"submods"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %w", ErrEARMalformed, err)
	}
	if claims.Profile != earProfile {
		return nil, fmt.Errorf("%w: eat_profile %q; a Verifier of kind %s issues %q", ErrEARProfile, claims.Profile, v.Kind(), earProfile)
	}
	now := v.window.now()
	iat := time.Unix(claims.IAT, 0)
	if claims.IAT == 0 || iat.Before(now.Add(-v.window.maxAge)) || iat.After(now.Add(v.window.skew)) {
		return nil, fmt.Errorf("%w: iat %s", ErrEAROutsideWindow, iat.UTC().Format(time.RFC3339))
	}
	nonce, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(claims.Nonce, "="))
	if err != nil || !bytes.Equal(nonce, expectedNonce) {
		return nil, ErrEARNonce
	}
	for _, name := range v.submods {
		sub, ok := claims.Submods[name]
		if !ok {
			continue
		}
		if sub.Status != "affirming" {
			return nil, fmt.Errorf("%w: %s is %q", ErrEARNotAffirming, name, sub.Status)
		}
		res := &attestationResults{Verifier: v.name, Family: veraisonFamilies[name], IssuedAt: iat, Raw: jws}
		switch res.Family {
		case familySEVSNP:
			res.SNP, res.SNPErr = parseSNPClaims(sub.Evidence)
			if res.SNP != nil {
				res.Measurement = res.SNP.measurement
			}
		case familyTDX:
			_ = json.Unmarshal(sub.Evidence, &res.TDX)
			if m, err := hex.DecodeString(res.TDX["mrtd"]); err == nil && len(m) == 48 {
				res.Measurement = m
			}
		}
		return res, nil
	}
	return nil, fmt.Errorf("%w: no submodule the Verifier speaks for (%v)", ErrEARNotAffirming, v.submods)
}
