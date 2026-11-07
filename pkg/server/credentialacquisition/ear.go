package credentialacquisition

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	"github.com/go-jose/go-jose/v4"
)

// Refusals of Attestation Results.
var (
	ErrEARSignature     = errors.New("the Attestation Results are not signed by the key provisioned for the Verifier that returned them")
	ErrEARProfile       = errors.New("the Attestation Results name a profile that is not the one the kind of the Verifier issues")
	ErrEAROutsideWindow = errors.New("the Attestation Results were issued outside the accepted time window, too long ago or in the future")
	ErrEARNonce         = errors.New("the Attestation Results report a nonce that is not the binding value")
	ErrEARNotAffirming  = errors.New("the Verifier did not affirm the Evidence")
	ErrEARMalformed     = errors.New("the Attestation Results are malformed")
)

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
