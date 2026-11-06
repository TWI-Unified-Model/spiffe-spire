// Package container opens the encrypted credential bundle of
// draft-novak-rats-tacra (Sealing the Released Credential): the hpke-base
// container a Secret Vault seals to the Credential Encryption Key of the Workload
// in HPKE base mode, with the associated data that names the credential
// group, the Target, the freshness element and the Credential Hint, and,
// when the Secret Vault authenticates itself as the origin, its signature over the
// container. Only the holder of the Credential Encryption Key opens it.
//
// The test vectors in testdata come from the sealing side as it ran on
// Google Cloud and AWS SEV-SNP guests and on Google Cloud TDX guests.
package container

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// The container this package opens, and the algorithm of its origin member.
const (
	ContainerBase = "hpke-base"
	OriginAlg     = "ECDSA-P256-SHA256"
)

// The HPKE suites of the container, each named by its KEM, its KDF and its
// AEAD as the HPKE registries name them.
var (
	SuiteMLKEM768P256 = Suite{KEM: "MLKEM768-P256", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM"}
	SuiteDHKEMP256    = Suite{KEM: "DHKEM(P-256, HKDF-SHA256)", KDF: "HKDF-SHA256", AEAD: "AES-256-GCM"}
)

// The suites by the names acceptable_cek carries, the parts joined with +.
const (
	AcceptableMLKEM768P256 = "MLKEM768-P256+HKDF-SHA256+AES-256-GCM"
	AcceptableDHKEMP256    = "DHKEM(P-256, HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"
)

const (
	infoLabel = "tacra hpke-base v1"
	sigLabel  = "tacra-est bundle signature v1"
)

// Refusals.
var (
	ErrContainer      = errors.New("container: not an hpke-base container of a known suite")
	ErrAAD            = errors.New("container: the associated data does not name the Target, freshness element and Credential Hint of this request")
	ErrSignature      = errors.New("container: not signed by the trusted Secret Vault key over the bundle of this request")
	ErrOriginRequired = errors.New("container: origin authentication required, and the container carries none")
	ErrAttributes     = errors.New("container: an item has no key-block attributes (purpose, algorithm, exportable)")
	ErrExportable     = errors.New("container: an item may leave the TEE")
	ErrShared         = errors.New("container: an item is a private key shared among instances, which this Workload accepts none of")
	ErrValidity       = errors.New("container: validity_seconds is missing or longer than this Workload accepts")
)

// B64 is a byte string carried as its unpadded base64url encoding.
type B64 []byte

// MarshalJSON implements json.Marshaler.
func (b B64) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON implements json.Unmarshaler.
func (b *B64) UnmarshalJSON(d []byte) error {
	var s string
	if err := json.Unmarshal(d, &s); err != nil {
		return err
	}
	v, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return err
	}
	*b = v
	return nil
}

// AAD is the associated data of the bundle.
type AAD struct {
	GroupID        string `json:"group_id"`
	Target         B64    `json:"target"` // the Target octets, base64url on the wire
	Handle         B64    `json:"handle,omitempty"`
	CredentialHint string `json:"credential_hint,omitempty"`
}

// Bundle is the EncryptedCredentialBundle.
type Bundle struct {
	Container  string  `json:"container"`
	Suite      Suite   `json:"suite"`
	Enc        B64     `json:"enc"`
	Ciphertext B64     `json:"ciphertext"`
	AAD        AAD     `json:"aad"`
	Origin     *Origin `json:"origin,omitempty"` // the origin authentication of the Secret Vault
}

// Suite names the HPKE algorithms.
type Suite struct {
	KEM  string `json:"kem"`
	KDF  string `json:"kdf"`
	AEAD string `json:"aead"`
}

// Origin is the authentication of the Secret Vault as the origin of
// the container: the name of the signature algorithm and the signature.
type Origin struct {
	Alg       string `json:"alg"`
	Signature B64    `json:"signature"`
}

// Item is one credential inside the bundle, with its key-block attributes:
// what it may be used for, with which algorithm, whether it may leave the
// TEE, and whether it is a private key shared by the instances of a
// replicated service.
type Item struct {
	Type       string   `json:"type"`
	Format     string   `json:"format,omitempty"`
	Value      string   `json:"value"`
	Kid        string   `json:"kid,omitempty"`
	Purpose    []string `json:"purpose,omitempty"`
	Algorithm  string   `json:"algorithm,omitempty"`
	Exportable *bool    `json:"exportable,omitempty"`
	Shared     bool     `json:"shared,omitempty"`
}

// Content is the plaintext of the bundle.
type Content struct {
	CredentialItems []Item         `json:"credential_items"`
	Metadata        map[string]any `json:"metadata,omitempty"`
}

type baseSuite struct {
	suite Suite
	kem   hpke.KEM
	id    []byte
}

func suiteID(kemID uint16) []byte {
	return []byte{'H', 'P', 'K', 'E', byte(kemID >> 8), byte(kemID), 0x00, 0x01, 0x00, 0x02} //nolint:gosec // the two octets of the KEM id
}

var baseSuites = []baseSuite{
	{suite: SuiteMLKEM768P256, kem: hpke.MLKEM768P256(), id: suiteID(0x0050)},
	{suite: SuiteDHKEMP256, kem: hpke.DHKEM(ecdh.P256()), id: suiteID(0x0010)},
}

func kdfAEAD() (hpke.KDF, hpke.AEAD) {
	return hpke.HKDFSHA256(), hpke.AES256GCM()
}

// SuiteID returns the HPKE suite_id of a suite of the container, and false
// for any other suite.
func SuiteID(s Suite) ([]byte, bool) {
	for _, c := range baseSuites {
		if c.suite == s {
			return c.id, true
		}
	}
	return nil, false
}

// SuiteOf returns the suite an acceptable_cek token names.
func SuiteOf(token string) (Suite, bool) {
	switch token {
	case AcceptableMLKEM768P256:
		return SuiteMLKEM768P256, true
	case AcceptableDHKEMP256:
		return SuiteDHKEMP256, true
	}
	return Suite{}, false
}

func lp(b []byte, parts ...[]byte) []byte {
	for _, p := range parts {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p))) //nolint:gosec // the length of an octet string
		b = append(b, p...)
	}
	return b
}

// InfoBase is the HPKE info of the container: the label, the Target and the
// freshness element, each length-prefixed.
func InfoBase(target string, freshness []byte) []byte {
	return lp(nil, []byte(infoLabel), []byte(target), freshness)
}

// ToBeSigned is what the Secret Vault signs for the origin member: the suite
// in use names the HPKE suite_id among the signed octets, and the name of the
// algorithm is OriginAlg, which the member carries.
func ToBeSigned(s Suite, cekPub, info, aad, enc, ct []byte) []byte {
	id, _ := SuiteID(s)
	return lp(nil, []byte(sigLabel), id, []byte(OriginAlg), cekPub, info, aad, enc, ct)
}

// Canonical returns the JSON Canonicalization Scheme serialization (RFC
// 8785) of v: object keys sorted, no insignificant space, strings escaped as
// Section 3.2.2.2 says, integers as they are.
func Canonical(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var tree any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&tree); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := writeCanonical(&buf, tree); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeString(buf, k)
			buf.WriteByte(':')
			if err := writeCanonical(buf, t[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	case []any:
		buf.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, e); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case string:
		writeString(buf, t)
	case json.Number:
		buf.WriteString(t.String())
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case nil:
		buf.WriteString("null")
	default:
		return fmt.Errorf("container: cannot encode %T", v)
	}
	return nil
}

// writeString writes s as the JSON Canonicalization Scheme does (RFC 8785,
// Section 3.2.2.2): only the quotation mark, the backslash and the
// control characters are escaped, and everything else is written as it is.
func writeString(buf *bytes.Buffer, s string) {
	buf.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			buf.WriteString(`\"`)
		case r == '\\':
			buf.WriteString(`\\`)
		case r == '\n':
			buf.WriteString(`\n`)
		case r == '\r':
			buf.WriteString(`\r`)
		case r == '\t':
			buf.WriteString(`\t`)
		case r == '\b':
			buf.WriteString(`\b`)
		case r == '\f':
			buf.WriteString(`\f`)
		case r < 0x20:
			fmt.Fprintf(buf, `\u%04x`, r)
		default:
			buf.WriteRune(r)
		}
	}
	buf.WriteByte('"')
}

// GenerateCEK makes a fresh MLKEM768-P256 key pair for one request: the
// private key, and CEKpub as it is bound, the encapsulation key itself.
func GenerateCEK() (hpke.PrivateKey, []byte, error) {
	sk, err := baseSuites[0].kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return sk, sk.PublicKey().Bytes(), nil
}

// GenerateCEKP256 makes a fresh P-256 key pair for one request: the private
// key, and CEKpub as it is bound, the DER SubjectPublicKeyInfo.
func GenerateCEKP256() (*ecdh.PrivateKey, []byte, error) {
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(k.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	return k, spki, nil
}

// DHKEMPrivateKey is a P-256 CEK as the HPKE recipient uses it: from the
// ECDSA or ECDH private key the platform plug-in generated.
func DHKEMPrivateKey(k crypto.PrivateKey) (hpke.PrivateKey, error) {
	switch p := k.(type) {
	case hpke.PrivateKey:
		return p, nil
	case *ecdh.PrivateKey:
		if p.Curve() != ecdh.P256() {
			return nil, errors.New("container: the CEK is not a P-256 key")
		}
		return hpke.NewDHKEMPrivateKey(p)
	case *ecdsa.PrivateKey:
		if p.Curve != elliptic.P256() {
			return nil, errors.New("container: the CEK is not a P-256 key")
		}
		e, err := p.ECDH()
		if err != nil {
			return nil, err
		}
		return hpke.NewDHKEMPrivateKey(e)
	}
	return nil, fmt.Errorf("container: a CEK of type %T opens no hpke-base container", k)
}

// Expect is what the Workload bound into its Evidence, its CEK, and its
// policy for the Target on origin authentication: the Vault key it holds,
// and whether the container must carry a signature under it.
type Expect struct {
	Target         string
	Handle         []byte // the freshness element
	CredentialHint string
	CEK            hpke.PrivateKey
	// CEKPub is CEKpub as the request carried it, the octets the signature
	// covers. When nil, the encoding of the public key of CEK that the KEM defines.
	CEKPub []byte
	// VaultKey is the signature key of the Secret Vault that the Workload holds
	// for the Target; an origin member the container carries is verified under it.
	// RequireOrigin refuses a container without one.
	VaultKey      *ecdsa.PublicKey
	RequireOrigin bool
}

// Open checks the container, the suite, the associated data and, as the
// policy of the Workload says, the origin member, then decrypts.
func Open(b *Bundle, exp Expect) (*Content, error) {
	if b.Container != ContainerBase {
		return nil, ErrContainer
	}
	if _, ok := SuiteID(b.Suite); !ok {
		return nil, ErrContainer
	}
	if !bytes.Equal(b.AAD.Target, []byte(exp.Target)) || !bytes.Equal(b.AAD.Handle, exp.Handle) || b.AAD.CredentialHint != exp.CredentialHint {
		return nil, ErrAAD
	}
	info := InfoBase(exp.Target, exp.Handle)
	aadBytes, err := Canonical(b.AAD)
	if err != nil {
		return nil, err
	}
	switch {
	case b.Origin != nil && exp.VaultKey != nil:
		cekPub := exp.CEKPub
		if cekPub == nil {
			cekPub = exp.CEK.PublicKey().Bytes()
		}
		digest := sha256.Sum256(ToBeSigned(b.Suite, cekPub, info, aadBytes, b.Enc, b.Ciphertext))
		if b.Origin.Alg != OriginAlg || !ecdsa.VerifyASN1(exp.VaultKey, digest[:], b.Origin.Signature) {
			return nil, ErrSignature
		}
	case b.Origin != nil && exp.RequireOrigin:
		return nil, ErrSignature // required, and no key to verify it under
	case b.Origin == nil && exp.RequireOrigin:
		return nil, ErrOriginRequired
	}
	kdf, aead := kdfAEAD()
	r, err := hpke.NewRecipient(b.Enc, exp.CEK, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("container: %w", err)
	}
	pt, err := r.Open(aadBytes, b.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("container: %w", err)
	}
	var c Content
	if err := json.Unmarshal(pt, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// CheckItems is the policy of the Workload on what it accepts: every item with its
// key-block attributes, nothing exportable, a shared private key only if
// acceptShared, and a validity of at most maxValiditySeconds (0: not
// checked).
func CheckItems(c *Content, acceptShared bool, maxValiditySeconds int) error {
	for _, it := range c.CredentialItems {
		if len(it.Purpose) == 0 || it.Algorithm == "" || it.Exportable == nil {
			return fmt.Errorf("%w: %s", ErrAttributes, it.Kid)
		}
		if *it.Exportable {
			return fmt.Errorf("%w: %s", ErrExportable, it.Kid)
		}
		if it.Shared && !acceptShared {
			return fmt.Errorf("%w: %s", ErrShared, it.Kid)
		}
	}
	if maxValiditySeconds > 0 {
		v, ok := c.Metadata["validity_seconds"].(float64)
		if !ok || v > float64(maxValiditySeconds) || v != float64(int(v)) {
			return fmt.Errorf("%w: %v", ErrValidity, c.Metadata["validity_seconds"])
		}
	}
	return nil
}

// ItemOctets is the credential that an item carries: its value is the unpadded
// base64url of the octets of the credential, a DER certificate, a DER
// PrivateKeyInfo, the key octets or the UTF-8 of a token.
func ItemOctets(it Item) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(it.Value)
}
