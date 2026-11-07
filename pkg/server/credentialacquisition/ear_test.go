package credentialacquisition

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
)

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
