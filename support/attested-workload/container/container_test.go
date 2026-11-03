package container

import (
	"crypto/ecdsa"
	"crypto/hpke"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

// vector is a test vector of the TWI-Unified-Model attestation bench: a
// container its test Vault sealed, with the CEK that opens it and the Vault's
// signature key.
type vector struct {
	Description    string          `json:"description"`
	Suite          Suite           `json:"suite"`
	CEKSeed        string          `json:"cek_seed"`  // MLKEM768-P256: the seed of the CEK
	CEKPKCS8       string          `json:"cek_pkcs8"` // P-256: the CEK as PKCS#8
	CEKPub         string          `json:"cek_pub"`
	VaultSPKI      string          `json:"vault_signing_spki"`
	Target         string          `json:"target"`
	Freshness      string          `json:"freshness"`
	CredentialHint string          `json:"credential_hint"`
	Info           string          `json:"info"`
	AAD            string          `json:"aad"`
	ToBeSigned     string          `json:"to_be_signed"`
	Bundle         json.RawMessage `json:"bundle"`
	Plaintext      string          `json:"plaintext"`
}

func unhex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func loadVector(t *testing.T, path string) (vector, Bundle, hpke.PrivateKey, *ecdsa.PublicKey) {
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var v vector
	require.NoError(t, json.Unmarshal(raw, &v))
	var b Bundle
	require.NoError(t, json.Unmarshal(v.Bundle, &b))
	var cek hpke.PrivateKey
	switch v.Suite {
	case SuiteMLKEM768P256:
		cek, err = hpke.MLKEM768P256().NewPrivateKey(unhex(t, v.CEKSeed))
		require.NoError(t, err)
	case SuiteDHKEMP256:
		key, perr := x509.ParsePKCS8PrivateKey(unhex(t, v.CEKPKCS8))
		require.NoError(t, perr)
		cek, err = DHKEMPrivateKey(key)
		require.NoError(t, err)
	default:
		t.Fatalf("unknown suite %v", v.Suite)
	}
	pub, err := x509.ParsePKIXPublicKey(unhex(t, v.VaultSPKI))
	require.NoError(t, err)
	return v, b, cek, pub.(*ecdsa.PublicKey)
}

func TestOpenVectors(t *testing.T) {
	for _, path := range []string{"testdata/go-hpke-base.json", "testdata/go-hpke-base-p256.json"} {
		t.Run(path, func(t *testing.T) {
			v, b, cek, vaultKey := loadVector(t, path)
			fresh := unhex(t, v.Freshness)
			cekPub := unhex(t, v.CEKPub)
			if v.Suite == SuiteMLKEM768P256 {
				require.Equal(t, cekPub, cek.PublicKey().Bytes(), "CEKpub from the seed differs from the vector's")
			}
			require.Equal(t, v.Info, hex.EncodeToString(InfoBase(v.Target, fresh)))
			aad, err := Canonical(b.AAD)
			require.NoError(t, err)
			require.Equal(t, v.AAD, string(aad))
			require.Equal(t, v.ToBeSigned, hex.EncodeToString(ToBeSigned(v.Suite, cekPub, InfoBase(v.Target, fresh), aad, b.Enc, b.Ciphertext)))

			exp := Expect{Target: v.Target, Handle: fresh, CredentialHint: v.CredentialHint, CEK: cek, CEKPub: cekPub, VaultKey: vaultKey, RequireOrigin: true}
			c, err := Open(&b, exp)
			require.NoError(t, err)
			pt, err := Canonical(c)
			require.NoError(t, err)
			require.Equal(t, v.Plaintext, string(pt))
			require.NoError(t, CheckItems(c, false, 3600))
			require.NotEmpty(t, c.CredentialItems)
			octets, err := ItemOctets(c.CredentialItems[0])
			require.NoError(t, err)
			require.NotEmpty(t, octets)

			t.Run("without the Vault key, the container opens as it is", func(t *testing.T) {
				e := exp
				e.VaultKey, e.RequireOrigin = nil, false
				_, err := Open(&b, e)
				require.NoError(t, err)
			})
			t.Run("origin required without a key to verify under", func(t *testing.T) {
				e := exp
				e.VaultKey = nil
				_, err := Open(&b, e)
				require.ErrorIs(t, err, ErrSignature)
			})
			t.Run("another Target in the associated data", func(t *testing.T) {
				e := exp
				e.Target = "https://other.example"
				_, err := Open(&b, e)
				require.ErrorIs(t, err, ErrAAD)
			})
			t.Run("another freshness element", func(t *testing.T) {
				e := exp
				e.Handle = append([]byte(nil), fresh...)
				e.Handle[0] ^= 1
				_, err := Open(&b, e)
				require.ErrorIs(t, err, ErrAAD)
			})
			t.Run("another Credential Hint", func(t *testing.T) {
				e := exp
				e.CredentialHint = "other"
				_, err := Open(&b, e)
				require.ErrorIs(t, err, ErrAAD)
			})
			t.Run("a signature under another key", func(t *testing.T) {
				e := exp
				otherKey := newKey(t)
				e.VaultKey = &otherKey.PublicKey
				_, err := Open(&b, e)
				require.ErrorIs(t, err, ErrSignature)
			})
			t.Run("a container without the origin member where it is required", func(t *testing.T) {
				bb := b
				bb.Origin = nil
				_, err := Open(&bb, exp)
				require.ErrorIs(t, err, ErrOriginRequired)
			})
			t.Run("a tampered ciphertext", func(t *testing.T) {
				bb := b
				bb.Ciphertext = append([]byte(nil), b.Ciphertext...)
				bb.Ciphertext[len(bb.Ciphertext)-1] ^= 1
				e := exp
				e.VaultKey, e.RequireOrigin = nil, false
				_, err := Open(&bb, e)
				require.Error(t, err)
			})
			t.Run("another container type", func(t *testing.T) {
				bb := b
				bb.Container = "hpke-auth"
				_, err := Open(&bb, exp)
				require.ErrorIs(t, err, ErrContainer)
			})
		})
	}
}

func TestCheckItems(t *testing.T) {
	f, tr := false, true
	ok := &Content{CredentialItems: []Item{{Type: "api-key", Value: "dG9rZW4", Kid: "k", Purpose: []string{"authenticate"}, Algorithm: "opaque-bearer", Exportable: &f}},
		Metadata: map[string]any{"validity_seconds": float64(3600)}}
	require.NoError(t, CheckItems(ok, false, 3600))

	noAttrs := &Content{CredentialItems: []Item{{Type: "api-key", Value: "x"}}}
	require.ErrorIs(t, CheckItems(noAttrs, false, 0), ErrAttributes)
	exportable := &Content{CredentialItems: []Item{{Purpose: []string{"p"}, Algorithm: "a", Exportable: &tr}}}
	require.ErrorIs(t, CheckItems(exportable, false, 0), ErrExportable)
	shared := &Content{CredentialItems: []Item{{Purpose: []string{"p"}, Algorithm: "a", Exportable: &f, Shared: true}}}
	require.ErrorIs(t, CheckItems(shared, false, 0), ErrShared)
	require.NoError(t, CheckItems(shared, true, 0))
	long := &Content{CredentialItems: ok.CredentialItems, Metadata: map[string]any{"validity_seconds": float64(7200)}}
	require.ErrorIs(t, CheckItems(long, false, 3600), ErrValidity)
}

func TestSuiteOf(t *testing.T) {
	s, ok := SuiteOf(AcceptableMLKEM768P256)
	require.True(t, ok)
	require.Equal(t, SuiteMLKEM768P256, s)
	s, ok = SuiteOf(AcceptableDHKEMP256)
	require.True(t, ok)
	require.Equal(t, SuiteDHKEMP256, s)
	_, ok = SuiteOf("X25519+HKDF-SHA256+ChaCha20Poly1305")
	require.False(t, ok)
}

func TestGenerateCEK(t *testing.T) {
	sk, pub, err := GenerateCEK()
	require.NoError(t, err)
	require.Equal(t, sk.PublicKey().Bytes(), pub)
	_, err = baseSuites[0].kem.NewPublicKey(pub)
	require.NoError(t, err)

	k, spki, err := GenerateCEKP256()
	require.NoError(t, err)
	parsed, err := x509.ParsePKIXPublicKey(spki)
	require.NoError(t, err)
	require.NotNil(t, parsed)
	_, err = DHKEMPrivateKey(k)
	require.NoError(t, err)
	ecdsaKey := newKey(t)
	_, err = DHKEMPrivateKey(ecdsaKey)
	require.NoError(t, err)
	_, err = DHKEMPrivateKey("not a key")
	require.Error(t, err)
}
