package platform

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-sev-guest/verify/trust"
	"github.com/stretchr/testify/require"
)

// TestShippedAMDChains checks that the copies this Workload ships are the
// bundles go-sev-guest embeds, byte for byte, one per product line and key
// type, indexed by the issuer of the VCEK or VLEK.
func TestShippedAMDChains(t *testing.T) {
	chains, err := loadAMDChains("")
	require.NoError(t, err)
	for issuer, bundle := range map[string][]byte{
		"SEV-Milan": trust.AskArkMilanVcekBytes, "SEV-VLEK-Milan": trust.AskArkMilanVlekBytes,
		"SEV-Genoa": trust.AskArkGenoaVcekBytes, "SEV-VLEK-Genoa": trust.AskArkGenoaVlekBytes,
		"SEV-Turin": trust.AskArkTurinVcekBytes, "SEV-VLEK-Turin": trust.AskArkTurinVlekBytes,
	} {
		ch, ok := chains.chain(issuer)
		require.True(t, ok, issuer)
		raw, err := shippedAMDChains.ReadFile("amdchains/" + ch.file)
		require.NoError(t, err)
		require.Equal(t, bundle, raw, "%s differs from the bundle go-sev-guest embeds", ch.file)
		require.NotEmpty(t, ch.ask)
		require.NotEmpty(t, ch.ark)
	}
	require.Len(t, chains.byIssuer, 6)
	_, ok := chains.chain("SEV-Venice")
	require.False(t, ok)
}

// TestAMDChainsDirectory checks that a directory replaces the copies this
// Workload ships, and that a bad directory is refused with its reason.
func TestAMDChainsDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "turin.pem"), trust.AskArkTurinVlekBytes, 0o600))
	chains, err := loadAMDChains(dir)
	require.NoError(t, err)
	require.Len(t, chains.byIssuer, 1)
	_, ok := chains.chain("SEV-VLEK-Turin")
	require.True(t, ok)
	_, ok = chains.chain("SEV-Milan")
	require.False(t, ok, "the directory replaces the copies this Workload ships")

	require.NoError(t, os.WriteFile(filepath.Join(dir, "again.pem"), trust.AskArkTurinVlekBytes, 0o600))
	_, err = loadAMDChains(dir)
	require.ErrorContains(t, err, `both hold the chain of "SEV-VLEK-Turin"`)

	bad := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(bad, "x.pem"), []byte("not a chain"), 0o600))
	_, err = loadAMDChains(bad)
	require.ErrorContains(t, err, "x.pem")
	_, err = loadAMDChains(t.TempDir())
	require.ErrorContains(t, err, "no PEM file")
	_, err = loadAMDChains(filepath.Join(bad, "missing"))
	require.Error(t, err)
}

// TestCompleteCertTable checks that a table with the VCEK alone gets the ASK
// and ARK of its product line appended, and that a table with both, or with a
// VCEK of a product line the chains do not cover, is left as it is.
func TestCompleteCertTable(t *testing.T) {
	chains, err := loadAMDChains("")
	require.NoError(t, err)
	leaf := func(t *testing.T, issuer string) []byte {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)
		now := time.Now()
		parent := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: issuer}, NotBefore: now, NotAfter: now.Add(time.Hour)}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "VCEK"}, NotBefore: now, NotAfter: now.Add(time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, key)
		require.NoError(t, err)
		return der
	}
	vcek, err := hex.DecodeString(guidVCEK)
	require.NoError(t, err)

	table := encodeCertTable([]certEntry{{vcek, leaf(t, "SEV-Milan")}})
	out, added, err := completeCertTable(table, chains)
	require.NoError(t, err)
	require.True(t, added)
	entries, err := certTableEntries(out)
	require.NoError(t, err)
	require.Len(t, entries, 3)
	milan, _ := chains.chain("SEV-Milan")
	require.Equal(t, milan.ask, entries[1].cert)
	require.Equal(t, milan.ark, entries[2].cert)

	again, added, err := completeCertTable(out, chains)
	require.NoError(t, err)
	require.False(t, added, "a table with both is left as it is")
	require.Equal(t, out, again)

	table = encodeCertTable([]certEntry{{vcek, leaf(t, "SEV-Venice")}})
	same, added, err := completeCertTable(table, chains)
	require.NoError(t, err)
	require.False(t, added, "a product line the chains do not cover is left to the Verifier")
	require.Equal(t, table, same)
}
