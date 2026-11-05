package credentialacquisition

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// Refusals of Attestation Results.
var (
	ErrEARSignature    = errors.New("the Attestation Results are not signed by a Verifier that the policy of the Target names")
	ErrEARStale        = errors.New("the Attestation Results were issued too long ago or in the future")
	ErrEARNonce        = errors.New("the Attestation Results report a nonce that is not the binding value")
	ErrEARNotAffirming = errors.New("the Attestation Results are not affirming")
	ErrEARMalformed    = errors.New("the Attestation Results are malformed")
)

// earKey is the EAR signing key of a Verifier, provisioned, and the submodules
// the Verifier speaks for.
type earKey struct {
	name    string
	key     *ecdsa.PublicKey
	submods []string
}

// earVerifier verifies the Attestation Results a Veraison Verifier returns:
// an EAR (RFC 9711 EAT in a JWT signed ES256) that must be signed by the key
// provisioned for a Verifier that the policy of the Target names, be recent, report the
// binding value as its eat_nonce, and be affirming for the submodule of the
// scheme of the Verifier.
type earVerifier struct {
	keys   []earKey
	maxAge time.Duration
	skew   time.Duration
	now    func() time.Time
}

// earResult is what the Server takes from verified Attestation Results.
type earResult struct {
	Verifier    string
	Submod      string
	IssuedAt    time.Time
	Measurement []byte // the launch measurement the Verifier annotated: MEASUREMENT for SEV-SNP, MRTD for TDX
	Raw         string // the EAR as received, for the record
	// SNP holds the SEV-SNP report fields the Verifier annotated (submodule
	// SEVSNP), or nil with SNPErr saying why; TDX holds the annotations of the
	// TDX Verifier (submodule TDX).
	SNP    *snpClaims
	SNPErr error
	TDX    map[string]string
	waived []string // what the platform rule admitted the results without
}

// loadEARKey reads the EAR verification key of a Verifier: an EC P-256 public JWK,
// or a PEM public key. The key is provisioned by the operator, never fetched
// from the verifier.
func loadEARKey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseEARKey(raw)
}

func parseEARKey(raw []byte) (*ecdsa.PublicKey, error) {
	if b, _ := pem.Decode(raw); b != nil {
		k, err := x509.ParsePKIXPublicKey(b.Bytes)
		if err != nil {
			return nil, err
		}
		pub, ok := k.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return nil, errors.New("not an EC P-256 public key")
		}
		return pub, nil
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(raw); err != nil {
		return nil, fmt.Errorf("not a PEM public key or a JWK: %w", err)
	}
	if !jwk.IsPublic() {
		return nil, errors.New("holds a private key; the Server is given the public key alone")
	}
	pub, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("not an EC P-256 public JWK")
	}
	return pub, nil
}

// verify checks the EAR against the keys of the named Verifiers and that it
// reports wantNonce.
func (v *earVerifier) verify(jws string, verifiers []string, wantNonce []byte) (*earResult, error) {
	sig, err := jose.ParseSigned(jws, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEARMalformed, err)
	}
	var payload []byte
	var signer *earKey
	for i := range v.keys {
		k := &v.keys[i]
		if !slices.Contains(verifiers, k.name) {
			continue
		}
		if payload, err = sig.Verify(k.key); err == nil {
			signer = k
			break
		}
	}
	if signer == nil {
		return nil, ErrEARSignature
	}

	var claims struct {
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
	now := v.now()
	iat := time.Unix(claims.IAT, 0)
	if claims.IAT == 0 || iat.Before(now.Add(-v.maxAge)) || iat.After(now.Add(v.skew)) {
		return nil, fmt.Errorf("%w: iat %s", ErrEARStale, iat.UTC().Format(time.RFC3339))
	}
	nonce, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(claims.Nonce, "="))
	if err != nil || !bytes.Equal(nonce, wantNonce) {
		return nil, ErrEARNonce
	}
	for _, name := range signer.submods {
		sub, ok := claims.Submods[name]
		if !ok {
			continue
		}
		if sub.Status != "affirming" {
			return nil, fmt.Errorf("%w: %s is %q", ErrEARNotAffirming, name, sub.Status)
		}
		res := &earResult{Verifier: signer.name, Submod: name, IssuedAt: iat, Raw: jws}
		switch name {
		case "SEVSNP":
			res.SNP, res.SNPErr = parseSNPClaims(sub.Evidence)
			if res.SNP != nil {
				res.Measurement = res.SNP.measurement
			}
		case "TDX":
			_ = json.Unmarshal(sub.Evidence, &res.TDX)
			if m, err := hex.DecodeString(res.TDX["mrtd"]); err == nil && len(m) == 48 {
				res.Measurement = m
			}
		}
		return res, nil
	}
	return nil, fmt.Errorf("%w: no submodule the signing Verifier speaks for (%v)", ErrEARNotAffirming, signer.submods)
}
