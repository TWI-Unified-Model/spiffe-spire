package credentialacquisition

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

func TestEARVerify(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	veraisonKey := newTestKey(t)
	otherKey := newTestKey(t)
	nonce := []byte("the binding value, 64 octets in production...................")
	comid := snpCoMID(t, gcpMilan())

	v := &earVerifier{
		keys: []earKey{
			{name: "veraison", key: &veraisonKey.PublicKey, submods: []string{"SEVSNP"}},
			{name: "other", key: &otherKey.PublicKey, submods: []string{"TDX"}},
		},
		maxAge: 2 * time.Minute,
		skew:   5 * time.Second,
		now:    func() time.Time { return now },
	}

	t.Run("affirming results signed by the Verifier of the policy are taken", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, nonce, now.Add(-10*time.Second), "SEVSNP", "affirming", comid)
		res, err := v.verify(jws, []string{"veraison"}, nonce)
		require.NoError(t, err)
		require.Equal(t, "veraison", res.Verifier)
		require.Equal(t, "SEVSNP", res.Submod)
		require.Equal(t, testMeasurement, res.Measurement)
		require.NotNil(t, res.SNP)
		require.Equal(t, uint64(0x30000), res.SNP.policy)
		require.Equal(t, classByChip, res.SNP.class)
		require.Equal(t, now.Add(-10*time.Second), res.IssuedAt.UTC())
	})
	t.Run("results of a Verifier the policy does not take are refused", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, nonce, now, "SEVSNP", "affirming", comid)
		_, err := v.verify(jws, []string{"other"}, nonce)
		require.ErrorIs(t, err, ErrEARSignature)
	})
	t.Run("results signed by an unknown key are refused", func(t *testing.T) {
		jws := signEAR(t, newTestKey(t), nonce, now, "SEVSNP", "affirming", comid)
		_, err := v.verify(jws, []string{"veraison"}, nonce)
		require.ErrorIs(t, err, ErrEARSignature)
	})
	t.Run("stale results are refused", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, nonce, now.Add(-3*time.Minute), "SEVSNP", "affirming", comid)
		_, err := v.verify(jws, []string{"veraison"}, nonce)
		require.ErrorIs(t, err, ErrEARStale)
		jws = signEAR(t, veraisonKey, nonce, now.Add(time.Minute), "SEVSNP", "affirming", comid)
		_, err = v.verify(jws, []string{"veraison"}, nonce)
		require.ErrorIs(t, err, ErrEARStale)
	})
	t.Run("results for another nonce are refused", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, []byte("another nonce"), now, "SEVSNP", "affirming", comid)
		_, err := v.verify(jws, []string{"veraison"}, nonce)
		require.ErrorIs(t, err, ErrEARNonce)
	})
	t.Run("results that are not affirming are refused", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, nonce, now, "SEVSNP", "contraindicated", comid)
		_, err := v.verify(jws, []string{"veraison"}, nonce)
		require.ErrorIs(t, err, ErrEARNotAffirming)
	})
	t.Run("results without the submodule of the Verifier are refused", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, nonce, now, "TDX", "affirming", comid)
		_, err := v.verify(jws, []string{"veraison"}, nonce)
		require.ErrorIs(t, err, ErrEARNotAffirming)
	})
	t.Run("a malformed token is refused", func(t *testing.T) {
		_, err := v.verify("not.a.jws", []string{"veraison"}, nonce)
		require.ErrorIs(t, err, ErrEARMalformed)
	})
	t.Run("results without an annotated measurement are taken without one", func(t *testing.T) {
		h := gcpMilan()
		h.noMeasurement = true
		jws := signEAR(t, veraisonKey, nonce, now, "SEVSNP", "affirming", snpCoMID(t, h))
		res, err := v.verify(jws, []string{"veraison"}, nonce)
		require.NoError(t, err)
		require.Nil(t, res.Measurement)
		require.Nil(t, res.SNP)
		require.ErrorContains(t, res.SNPErr, "no launch measurement")
	})
	t.Run("TDX results carry the MRTD and the TD attributes", func(t *testing.T) {
		mrtd := make([]byte, 48)
		for i := range mrtd {
			mrtd[i] = byte(0x10 + i)
		}
		jws := signEAR(t, otherKey, nonce, now, "TDX", "affirming", map[string]string{"mrtd": hex.EncodeToString(mrtd), "td_attributes": "0000000010000000"})
		res, err := v.verify(jws, []string{"other"}, nonce)
		require.NoError(t, err)
		require.Equal(t, "TDX", res.Submod)
		require.Equal(t, mrtd, res.Measurement)
		require.Equal(t, "0000000010000000", res.TDX["td_attributes"])
	})
}

func TestParseSNPClaims(t *testing.T) {
	h := gcpMilan()
	h.policy = 0xB0000
	raw, err := json.Marshal(map[string]any{"corim-id": "x", "tags": []string{snpCoMID(t, h)}})
	require.NoError(t, err)
	claims, err := parseSNPClaims(raw)
	require.NoError(t, err)
	require.Equal(t, testMeasurement, claims.measurement)
	require.Equal(t, uint64(0xB0000), claims.policy)
	require.Equal(t, uint64(0x25), claims.platformInfo)
	require.Equal(t, uint64(0xDE1D000000000004), claims.reportedTCB)
	require.Equal(t, uint64(0xDE1D000000000004), claims.committedTCB)
	require.True(t, claims.hasCPUID)
	require.Equal(t, byte(0x19), claims.family)
	require.Equal(t, byte(0x01), claims.model)
	require.Equal(t, h.chipID, claims.chipID)
	require.True(t, claims.hasMitVectors)
	require.Equal(t, uint64(0xb), claims.launchMitVector)
	require.Equal(t, classByChip, claims.class)

	h = gcpMilan()
	h.byCSP, h.chipID, h.noMitVectors = true, nil, true
	raw, err = json.Marshal(map[string]any{"tags": []string{snpCoMID(t, h)}})
	require.NoError(t, err)
	claims, err = parseSNPClaims(raw)
	require.NoError(t, err)
	require.Equal(t, classByCSP, claims.class)
	require.Nil(t, claims.chipID)
	require.False(t, claims.hasMitVectors)

	_, err = parseSNPClaims([]byte(`{"corim-id":"x"}`))
	require.Error(t, err)
	_, err = parseSNPClaims([]byte(`{"tags":["bm90IGNib3I="]}`))
	require.Error(t, err)
}

func TestOIDString(t *testing.T) {
	require.Equal(t, "1.3.6.1.4.1.3704.3.1", oidString([]byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x9c, 0x78, 0x03, 0x01}))
	require.Equal(t, "", oidString(nil))
}

func TestParseEARKey(t *testing.T) {
	key := newTestKey(t)

	jwk := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: "ES256"}
	raw, err := jwk.MarshalJSON()
	require.NoError(t, err)
	pub, err := parseEARKey(raw)
	require.NoError(t, err)
	require.True(t, pub.Equal(&key.PublicKey))

	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pub, err = parseEARKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	require.NoError(t, err)
	require.True(t, pub.Equal(&key.PublicKey))

	private := jose.JSONWebKey{Key: key, Algorithm: "ES256"}
	raw, err = private.MarshalJSON()
	require.NoError(t, err)
	_, err = parseEARKey(raw)
	require.ErrorContains(t, err, "private key")

	_, err = parseEARKey([]byte("garbage"))
	require.Error(t, err)
}
