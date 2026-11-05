package credentialacquisition

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func hexKey(handle []byte) []byte { return []byte(hex.EncodeToString(handle)) }

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// testMeasurement is the launch measurement the test verifier annotates.
var testMeasurement = func() []byte {
	m := make([]byte, 48)
	for i := range m {
		m[i] = byte(0xA0 + i)
	}
	return m
}()

// snpHost describes the SEV-SNP report a test verifier annotates. The
// defaults are those of the Google Cloud EPYC Milan hosts of the bench's
// records: a VCEK-signed report of version 5, REPORTED_TCB and COMMITTED_TCB
// bootloader 4, SNP 29, microcode 222, PLATFORM_INFO 0x25 (SMT on, alias check
// complete), mitigation vectors 0xb, and the guest policy 0x30000.
type snpHost struct {
	measurement   []byte
	policy        uint64
	platformInfo  uint64
	reportedTCB   uint64
	committedTCB  uint64
	family, model byte
	noCPUID       bool
	chipID        []byte
	byCSP         bool
	launchMit     uint64
	currentMit    uint64
	noMitVectors  bool
	noMeasurement bool
}

func gcpMilan() snpHost {
	chip := make([]byte, 64)
	for i := range chip {
		chip[i] = byte(0xC0 + i)
	}
	return snpHost{measurement: testMeasurement, policy: 0x30000, platformInfo: 0x25,
		reportedTCB: 0xDE1D000000000004, committedTCB: 0xDE1D000000000004, family: 0x19, model: 0x01, chipID: chip,
		launchMit: 0xb, currentMit: 0xb}
}

func rawBE(v uint64) []byte {
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

// snpCoMID builds the CoMID a Veraison verifier annotates for an SEV-SNP
// report: tag 506 around the CoMID map as a byte string, one reference-value
// triple whose environment names the class (the chip, or the cloud provider)
// and whose measurements carry the report's fields under the keys of the AMD
// SEV-SNP CoRIM profile.
func snpCoMID(t *testing.T, h snpHost) string {
	raw := func(key uint64, b []byte) map[any]any {
		return map[any]any{uint64(0): key, uint64(1): map[any]any{uint64(4): cbor.Tag{Number: tagRawValue, Content: b}}}
	}
	svn := func(key uint64, v uint64) map[any]any {
		return map[any]any{uint64(0): key, uint64(1): map[any]any{uint64(1): cbor.Tag{Number: tagSVN, Content: v}}}
	}
	measurements := []any{
		raw(mKeyPolicy, rawBE(h.policy)),
		raw(mKeyPlatformInfo, rawBE(h.platformInfo)),
		svn(mKeyReportedTCB, h.reportedTCB),
		svn(mKeyCommittedTCB, h.committedTCB),
	}
	if !h.noCPUID {
		measurements = append(measurements, raw(mKeyFamily, []byte{h.family}), raw(mKeyModel, []byte{h.model}), raw(mKeyStepping, []byte{1}))
	}
	if len(h.chipID) > 0 {
		measurements = append(measurements, raw(mKeyChipID, h.chipID))
	}
	if !h.noMitVectors {
		measurements = append(measurements, raw(mKeyLaunchMit, rawBE(h.launchMit)), raw(mKeyCurrentMit, rawBE(h.currentMit)))
	}
	if !h.noMeasurement {
		measurements = append(measurements, map[any]any{uint64(0): uint64(mKeyMeasurement), uint64(1): map[any]any{uint64(2): []any{[]any{uint64(1), h.measurement}}}})
	}
	class := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x03, 0x01} // 1.3.6.1.4.1.3704.3.1, by chip
	if h.byCSP {
		class[len(class)-1] = 0x02
	}
	env := map[any]any{uint64(0): map[any]any{uint64(0): cbor.Tag{Number: tagOID, Content: class}}}
	comid := map[any]any{
		uint64(0): "en-GB",
		uint64(4): map[any]any{uint64(0): []any{[]any{env, measurements}}},
	}
	inner, err := cbor.Marshal(comid)
	require.NoError(t, err)
	outer, err := cbor.Marshal(cbor.Tag{Number: tagCoMID, Content: inner})
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(outer)
}

// signEAR signs, with the verifier's key, an EAR that reports nonce for the
// submodule with the status and the annotated evidence: for SEVSNP the
// CoMID (snpCoMID), for TDX the bench verifier's map of strings.
func signEAR(t *testing.T, key *ecdsa.PrivateKey, nonce []byte, iat time.Time, submod, status string, annotated any) string {
	var evidence any
	switch a := annotated.(type) {
	case string:
		evidence = map[string]any{"corim-id": "test", "tags": []string{a}}
	default:
		evidence = a
	}
	claims := map[string]any{
		"ear.verifier-id": map[string]string{"build": "test", "developer": "test"},
		"eat_nonce":       base64.RawURLEncoding.EncodeToString(nonce),
		"eat_profile":     "tag:github.com,2023:veraison/ear",
		"iat":             iat.Unix(),
		"submods": map[string]any{
			submod: map[string]any{
				"ear.status":                      status,
				"ear.veraison.annotated-evidence": evidence,
			},
		},
	}
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	require.NoError(t, err)
	sig, err := signer.Sign(payload)
	require.NoError(t, err)
	jws, err := sig.CompactSerialize()
	require.NoError(t, err)
	return jws
}

func newTestKey(t *testing.T) *ecdsa.PrivateKey {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// testCSR is a PKCS#10 CSR signed with a P-256 key, as the Workload makes it.
func testCSR(t *testing.T) []byte {
	key := newTestKey(t)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "workload"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	require.NoError(t, err)
	return der
}

// testEvidence is Evidence as the bench's platform code produces it: a CBOR
// map whose provider names the TSM report provider; the verifier reads the
// rest.
func testEvidence(t *testing.T, provider string) []byte {
	b, err := cbor.Marshal(map[string]any{"provider": provider, "report": []byte("report")})
	require.NoError(t, err)
	return b
}
