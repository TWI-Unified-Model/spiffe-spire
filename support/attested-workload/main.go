// Command attested-workload is an attested Workload of the TACRA proof of
// concept: the Attester of draft-novak-rats-tacra, in a hardware-based
// trusted execution environment, obtaining an X509-SVID through the attested
// credential acquisition calls of the Workload API.
//
// The Workload asks the Agent to initiate credential acquisition for a
// Target. In enroll mode it generates a Credential Signing Key and a PKCS#10
// CSR for it, has the hardware produce Evidence whose freshness input is the
// TACRA binding value over the Freshness Handle, the Target and the CSR, and
// enrolls the CSR with that Evidence: the X509-SVID it receives carries its
// own key, which never left the Workload, and it verifies the chain against
// the bundle of the trust domain. In retrieve mode it generates a Credential
// Encryption Key, binds its public half into the Evidence the same way, and
// opens the container the Secret Vault sealed to it: the credential never
// crossed the Agent or the Server in the clear. It records the exchange.
//
//	attested-workload -target spiffe://example.org [-tee sev-snp|tdx] [-out DIR]
//	attested-workload -target https://ledger.example -credentialType api-key -hint payments [-vaultOriginKey FILE]
package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-sev-guest/abi"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	"github.com/spiffe/spire/support/attested-workload/container"
	"github.com/spiffe/spire/support/attested-workload/platform"
)

// The binding of TACRA, which the Workload API carries unchanged, and the
// CSK algorithm of this Workload.
const (
	bindingMethod = "binding-input"
	bindingHash   = "sha512"
	cskAlgorithm  = "ecdsa-p256-sha256"
)

// result is the record of one exchange, written as result.json.
type result struct {
	OK                 bool      `json:"ok"`
	Error              string    `json:"error,omitempty"`
	Target             string    `json:"target"`
	CredentialType     string    `json:"credential_type"`
	CredentialHint     string    `json:"credential_hint,omitempty"`
	TEE                string    `json:"tee"`
	Mode               string    `json:"mode,omitempty"`
	FreshnessKind      string    `json:"freshness_kind,omitempty"`
	HandleHex          string    `json:"handle_hex,omitempty"`
	ExpiresIn          uint32    `json:"expires_in,omitempty"`
	AcceptableCSK      []string  `json:"acceptable_csk,omitempty"`
	AcceptableEvidence []string  `json:"acceptable_evidence,omitempty"`
	BindingValueHex    string    `json:"binding_value_hex,omitempty"`
	CSRSHA256          string    `json:"csr_sha256,omitempty"`
	EvidenceBytes      int       `json:"evidence_bytes,omitempty"`
	EvidenceMediaType  string    `json:"evidence_media_type,omitempty"`
	ReportProvider     string    `json:"report_provider,omitempty"`
	ReportVersion      uint32    `json:"report_version,omitempty"`
	ReportMeasurement  string    `json:"report_measurement_hex,omitempty"` // SEV-SNP: MEASUREMENT; TDX: MRTD
	ReportSigner       string    `json:"report_signer,omitempty"`
	ReportTDAttributes string    `json:"report_td_attributes_hex,omitempty"`
	SPIFFEID           string    `json:"spiffe_id,omitempty"`
	Hint               string    `json:"hint,omitempty"`
	CertSerial         string    `json:"cert_serial,omitempty"`
	CertIssuer         string    `json:"cert_issuer,omitempty"`
	NotBefore          string    `json:"not_before,omitempty"`
	NotAfter           string    `json:"not_after,omitempty"`
	ChainVerified      bool      `json:"chain_verified"`
	KeyMatches         bool      `json:"key_matches"`
	AcceptableCEK      []string  `json:"acceptable_cek,omitempty"`
	Suite              string    `json:"suite,omitempty"`
	CEKPubBytes        int       `json:"cek_pub_bytes,omitempty"`
	GroupID            string    `json:"group_id,omitempty"`
	OriginVerified     bool      `json:"origin_verified,omitempty"`
	ItemType           string    `json:"item_type,omitempty"`
	ItemKid            string    `json:"item_kid,omitempty"`
	ItemPurpose        []string  `json:"item_purpose,omitempty"`
	ItemAlgorithm      string    `json:"item_algorithm,omitempty"`
	SecretSHA256       string    `json:"secret_sha256,omitempty"`
	SecretBytes        int       `json:"secret_bytes,omitempty"`
	InitiateMs         float64   `json:"initiate_ms,omitempty"`
	EnrollMs           float64   `json:"enroll_ms,omitempty"`
	RetrieveMs         float64   `json:"retrieve_ms,omitempty"`
	StartedAt          time.Time `json:"started_at"`
	FinishedAt         time.Time `json:"finished_at"`
}

func main() {
	os.Exit(mainWithCode())
}

func mainWithCode() int {
	socketPath := flag.String("socketPath", "/tmp/spire-agent/public/api.sock", "path of the Workload API socket of the Agent")
	target := flag.String("target", "", "the Target of the exchange (required), for example the SPIFFE ID of the trust domain")
	credentialType := flag.String("credentialType", "x509", "the Credential Type: x509 or wic to enroll, api-key, jwt, psk, wit or private-key to retrieve")
	hint := flag.String("hint", "", "the Credential Hint: the hint of the registration entry whose identity to acquire, or what the Secret Vault selects by")
	vaultOriginKey := flag.String("vaultOriginKey", "", "a file holding the signature key of the Secret Vault (PEM or DER SubjectPublicKeyInfo); given, the container must be signed under it")
	maxValidity := flag.Int("maxValidity", 3600, "the longest validity_seconds of a retrieved credential this Workload takes")
	tee := flag.String("tee", "sev-snp", "the trusted execution environment: sev-snp or tdx")
	out := flag.String("out", ".", "the directory the SVID, its key, the bundle and result.json are written to")
	timeout := flag.Duration("timeout", 2*time.Minute, "how long the exchange may take")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "attested-workload: -target is required")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	r := &result{Target: *target, CredentialType: *credentialType, CredentialHint: *hint, TEE: *tee, StartedAt: time.Now().UTC()}
	err := run(ctx, r, *socketPath, *out, *vaultOriginKey, *maxValidity)
	r.FinishedAt = time.Now().UTC()
	r.OK = err == nil
	if err != nil {
		r.Error = err.Error()
	}
	if werr := writeJSON(filepath.Join(*out, "result.json"), r); werr != nil {
		fmt.Fprintln(os.Stderr, "attested-workload:", werr)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "attested-workload:", err)
		return 1
	}
	if r.SPIFFEID != "" {
		fmt.Printf("enrolled %s, serial %s, not after %s, launch measurement %s\n", r.SPIFFEID, r.CertSerial, r.NotAfter, r.ReportMeasurement)
	} else {
		fmt.Printf("retrieved %s (%s, %d octets, sha256 %s) under %s, launch measurement %s\n", r.ItemType, r.ItemKid, r.SecretBytes, r.SecretSHA256, r.Suite, r.ReportMeasurement)
	}
	return 0
}

func run(ctx context.Context, r *result, socketPath, out, vaultOriginKey string, maxValidity int) error {
	if err := os.MkdirAll(out, 0o750); err != nil {
		return err
	}
	credentialType, ok := map[string]workload.CredentialType{
		"x509":        workload.CredentialType_CREDENTIAL_TYPE_X509,
		"wic":         workload.CredentialType_CREDENTIAL_TYPE_WIC,
		"wit":         workload.CredentialType_CREDENTIAL_TYPE_WIT,
		"jwt":         workload.CredentialType_CREDENTIAL_TYPE_JWT,
		"api-key":     workload.CredentialType_CREDENTIAL_TYPE_API_KEY,
		"psk":         workload.CredentialType_CREDENTIAL_TYPE_PSK,
		"private-key": workload.CredentialType_CREDENTIAL_TYPE_PRIVATE_KEY,
	}[r.CredentialType]
	if !ok {
		return fmt.Errorf("the Credential Type %q is not one of TACRA", r.CredentialType)
	}
	var vaultKey *ecdsa.PublicKey
	if vaultOriginKey != "" {
		var err error
		if vaultKey, err = loadVaultKey(vaultOriginKey); err != nil {
			return fmt.Errorf("vault origin key: %w", err)
		}
	}
	var plugin platform.Plugin
	var err error
	switch r.TEE {
	case "sev-snp":
		plugin, err = platform.NewSEVSNP()
	case "tdx":
		plugin, err = platform.NewTDX()
	default:
		err = fmt.Errorf("tee %q: sev-snp or tdx", r.TEE)
	}
	if err != nil {
		return err
	}

	client, err := workloadapi.New(ctx, workloadapi.WithAddr("unix://"+socketPath))
	if err != nil {
		return fmt.Errorf("calling the Workload API: %w", err)
	}
	defer client.Close()

	// 1. Initiate-Credential-Acquisition: the Freshness Kind and Handle, the
	// mode and the algorithms.
	start := time.Now()
	initiation, err := client.InitiateCredentialAcquisition(ctx, &workload.InitiateCredentialAcquisitionRequest{
		Target:         r.Target,
		CredentialType: credentialType,
		CredentialHint: r.CredentialHint,
	})
	if err != nil {
		return fmt.Errorf("initiate: %w", err)
	}
	r.InitiateMs = ms(start)
	r.Mode = initiation.Mode.String()
	r.FreshnessKind = initiation.FreshnessKind.String()
	r.HandleHex = hex.EncodeToString(initiation.FreshnessHandle)
	r.ExpiresIn = initiation.ExpiresIn
	r.AcceptableCSK = initiation.AcceptableCsk
	r.AcceptableCEK = initiation.AcceptableCek
	r.AcceptableEvidence = initiation.AcceptableEvidence
	switch {
	case initiation.FreshnessKind != workload.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE:
		return fmt.Errorf("initiate: Freshness Kind %s, this Workload embeds a present-nonce Handle", initiation.FreshnessKind)
	case len(initiation.FreshnessHandle) < 16 || len(initiation.FreshnessHandle) > 64:
		return fmt.Errorf("initiate: a present-nonce Handle of %d octets", len(initiation.FreshnessHandle))
	case len(initiation.AcceptableEvidence) > 0 && !slices.Contains(initiation.AcceptableEvidence, platform.TSMReportMediaTypeCBOR):
		return fmt.Errorf("initiate: the Evidence formats accepted are %v, this Workload produces %s", initiation.AcceptableEvidence, platform.TSMReportMediaTypeCBOR)
	}
	switch initiation.Mode {
	case workload.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_ENROLL:
		if !slices.Contains(initiation.AcceptableCsk, cskAlgorithm) {
			return fmt.Errorf("initiate: the Credential Authority accepts %v, this Workload signs with %s", initiation.AcceptableCsk, cskAlgorithm)
		}
		return enroll(ctx, r, client, plugin, initiation, credentialType, out)
	case workload.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_RETRIEVE:
		return retrieve(ctx, r, client, plugin, initiation, credentialType, out, vaultKey, maxValidity)
	default:
		return fmt.Errorf("initiate: the Target is served in mode %s", initiation.Mode)
	}
}

// enroll is Enroll-Credential: a Credential Signing Key, a CSR, Evidence bound
// to the CSR, and an X509-SVID for the key.
func enroll(ctx context.Context, r *result, client *workloadapi.Client, plugin platform.Plugin, initiation *workload.InitiateCredentialAcquisitionResponse, credentialType workload.CredentialType, out string) error {
	// 2. The Credential Signing Key and the CSR that proves possession of it.
	csk, err := plugin.GenerateCSK(platform.SigningAlgorithmECDSAP256)
	if err != nil {
		return fmt.Errorf("csk: %w", err)
	}
	signer, err := csk.Signer()
	if err != nil {
		return fmt.Errorf("csk: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: truncate(r.Target, 64)},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, signer)
	if err != nil {
		return fmt.Errorf("csr: %w", err)
	}
	r.CSRSHA256 = sha256Hex(csr)

	// 3. Evidence bound to the Handle, the Target and the CSR: the hardware
	// report whose report data is the binding value.
	evidence, err := plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKind(initiation.FreshnessKind),
		FreshnessHandle: initiation.FreshnessHandle,
		BoundKey:        csk.Public(),
		CSR:             csr,
		BoundKeyUse:     platform.BoundKeyUseSign,
		Target:          r.Target,
	})
	if err != nil {
		return fmt.Errorf("generating Evidence: %w", err)
	}
	bv := platform.BindingValue(initiation.FreshnessHandle, r.Target, csr)
	r.BindingValueHex = hex.EncodeToString(bv[:])
	r.EvidenceBytes = len(evidence.Token)
	r.EvidenceMediaType = evidence.MediaType
	describeReport(r, evidence.Token)

	// 4. Enroll-Credential: the CSR and the Evidence; an X509-SVID back.
	start := time.Now()
	enrollment := &workload.EnrollCredentialRequest{
		Target:           r.Target,
		CredentialType:   credentialType,
		CredentialHint:   r.CredentialHint,
		FreshnessKind:    initiation.FreshnessKind,
		FreshnessElement: initiation.FreshnessHandle,
		Csr:              csr,
		Evidence:         evidence.Token,
		Binding:          &workload.EvidenceBinding{Method: bindingMethod, Hash: bindingHash},
	}
	if len(initiation.AcceptableEvidence) > 0 {
		enrollment.EvidenceProfile = evidence.MediaType
	}
	resp, err := client.EnrollCredential(ctx, enrollment)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}
	r.EnrollMs = ms(start)
	r.SPIFFEID = resp.SpiffeId
	r.Hint = resp.Hint

	// 5. The credential: its chain verified against the bundle, its key ours.
	certs, err := x509.ParseCertificates(resp.X509Svid)
	if err != nil || len(certs) == 0 {
		return fmt.Errorf("enroll: the X509-SVID is not a DER chain: %w", err)
	}
	roots, err := x509.ParseCertificates(resp.Bundle)
	if err != nil || len(roots) == 0 {
		return fmt.Errorf("enroll: the bundle is not a DER chain: %w", err)
	}
	leaf := certs[0]
	r.CertSerial = leaf.SerialNumber.String()
	r.CertIssuer = leaf.Issuer.String()
	r.NotBefore = leaf.NotBefore.UTC().Format(time.RFC3339)
	r.NotAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
	id, err := spiffeid.FromString(resp.SpiffeId)
	if err != nil {
		return fmt.Errorf("enroll: SPIFFE ID %q: %w", resp.SpiffeId, err)
	}
	verifiedID, _, err := x509svid.Verify(certs, x509bundle.FromX509Authorities(id.TrustDomain(), roots))
	if err != nil {
		return fmt.Errorf("enroll: the X509-SVID does not verify against the bundle: %w", err)
	}
	if verifiedID != id {
		return fmt.Errorf("enroll: the X509-SVID is for %s, the response names %s", verifiedID, id)
	}
	r.ChainVerified = true
	pub, ok := leaf.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(csk.Public()) {
		return errors.New("enroll: the X509-SVID does not carry the Credential Signing Key")
	}
	r.KeyMatches = true

	// 6. The record: the chain, the key (ours alone), the bundle.
	if err := writePEM(filepath.Join(out, "svid.pem"), "CERTIFICATE", rawCerts(certs), 0o644); err != nil {
		return err
	}
	if err := writePEM(filepath.Join(out, "bundle.pem"), "CERTIFICATE", rawCerts(roots), 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(csk.Private)
	if err != nil {
		return fmt.Errorf("key: %w", err)
	}
	if err := writePEM(filepath.Join(out, "svid.key"), "PRIVATE KEY", [][]byte{keyDER}, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "evidence.tsm.cbor"), evidence.Token, 0o644) //nolint:gosec // the Evidence is public material
}

// retrieve is Retrieve-Credential: a Credential Encryption Key for a suite
// the Secret Vault accepts, Evidence bound to its public half, and the
// container the Secret Vault sealed to it, opened here and nowhere else.
func retrieve(ctx context.Context, r *result, client *workloadapi.Client, plugin platform.Plugin, initiation *workload.InitiateCredentialAcquisitionResponse, credentialType workload.CredentialType, out string, vaultKey *ecdsa.PublicKey, maxValidity int) error {
	// 2. The Credential Encryption Key, for the first suite of the Secret Vault
	// that this Workload supports: the hybrid MLKEM768-P256 first, then P-256.
	var alg platform.EncryptionAlgorithm
	var suite container.Suite
	for _, token := range initiation.AcceptableCek {
		s, ok := container.SuiteOf(token)
		if !ok {
			continue
		}
		switch s {
		case container.SuiteMLKEM768P256:
			alg = platform.EncryptionAlgorithmMLKEM768P256
		case container.SuiteDHKEMP256:
			alg = platform.EncryptionAlgorithmECDHP256
		}
		suite = s
		break
	}
	if alg == platform.EncryptionAlgorithmUnspecified {
		return fmt.Errorf("initiate: the Secret Vault seals to %v, none of which this Workload opens", initiation.AcceptableCek)
	}
	r.Suite = suite.KEM + "+" + suite.KDF + "+" + suite.AEAD
	cek, err := plugin.GenerateCEK(alg)
	if err != nil {
		return fmt.Errorf("cek: %w", err)
	}
	cekPub, err := platform.CEKPub(cek.Public())
	if err != nil {
		return fmt.Errorf("cek: %w", err)
	}
	r.CEKPubBytes = len(cekPub)

	// 3. Evidence bound to the Handle, the Target and CEKpub.
	evidence, err := plugin.GenerateEvidence(platform.EvidenceRequest{
		FreshnessKind:   platform.FreshnessKind(initiation.FreshnessKind),
		FreshnessHandle: initiation.FreshnessHandle,
		BoundKey:        cek.Public(),
		BoundKeyUse:     platform.BoundKeyUseEncrypt,
		Target:          r.Target,
	})
	if err != nil {
		return fmt.Errorf("generating Evidence: %w", err)
	}
	bv := platform.BindingValue(initiation.FreshnessHandle, r.Target, cekPub)
	r.BindingValueHex = hex.EncodeToString(bv[:])
	r.EvidenceBytes = len(evidence.Token)
	r.EvidenceMediaType = evidence.MediaType
	describeReport(r, evidence.Token)

	// 4. Retrieve-Credential: CEKpub and the Evidence; the sealed container back.
	start := time.Now()
	request := &workload.RetrieveCredentialRequest{
		Target:           r.Target,
		CredentialType:   credentialType,
		CredentialHint:   r.CredentialHint,
		FreshnessKind:    initiation.FreshnessKind,
		FreshnessElement: initiation.FreshnessHandle,
		CekPub:           cekPub,
		Evidence:         evidence.Token,
		Binding:          &workload.EvidenceBinding{Method: bindingMethod, Hash: bindingHash},
	}
	if len(initiation.AcceptableEvidence) > 0 {
		request.EvidenceProfile = evidence.MediaType
	}
	resp, err := client.RetrieveCredential(ctx, request)
	if err != nil {
		return fmt.Errorf("retrieve: %w", err)
	}
	r.RetrieveMs = ms(start)

	// 5. The container: the associated data names this request, the origin
	// member verifies under the key of the Secret Vault when one is held, and
	// only the CEK of this Workload opens it.
	var bundle container.Bundle
	if err := json.Unmarshal(resp.EncryptedCredentialBundle, &bundle); err != nil {
		return fmt.Errorf("retrieve: the container is not the JSON of an encrypted credential bundle: %w", err)
	}
	r.GroupID = bundle.AAD.GroupID
	recipient, err := container.DHKEMPrivateKey(cek.Private)
	if err != nil {
		return fmt.Errorf("retrieve: %w", err)
	}
	content, err := container.Open(&bundle, container.Expect{
		Target:         r.Target,
		Handle:         initiation.FreshnessHandle,
		CredentialHint: r.CredentialHint,
		CEK:            recipient,
		CEKPub:         cekPub,
		VaultKey:       vaultKey,
		RequireOrigin:  vaultKey != nil,
	})
	if err != nil {
		return fmt.Errorf("retrieve: %w", err)
	}
	r.OriginVerified = vaultKey != nil && bundle.Origin != nil
	if err := container.CheckItems(content, false, maxValidity); err != nil {
		return fmt.Errorf("retrieve: %w", err)
	}
	if len(content.CredentialItems) == 0 {
		return errors.New("retrieve: the bundle carries no credential")
	}
	item := content.CredentialItems[0]
	secret, err := container.ItemOctets(item)
	if err != nil {
		return fmt.Errorf("retrieve: the credential is not base64url: %w", err)
	}
	r.ItemType, r.ItemKid, r.ItemPurpose, r.ItemAlgorithm = item.Type, item.Kid, item.Purpose, item.Algorithm
	r.SecretSHA256 = sha256Hex(secret)
	r.SecretBytes = len(secret)

	// 6. The record: the container as received, the credential for this
	// Workload alone, the Evidence.
	if err := os.WriteFile(filepath.Join(out, "bundle.json"), resp.EncryptedCredentialBundle, 0o644); err != nil { //nolint:gosec // sealed to the key of this Workload
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "credential.secret"), secret, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(out, "evidence.tsm.cbor"), evidence.Token, 0o644) //nolint:gosec // the Evidence is public material
}

// loadVaultKey reads the signature key of the Secret Vault: a PEM or DER
// SubjectPublicKeyInfo of an EC P-256 key.
func loadVaultKey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	der := raw
	if b, _ := pem.Decode(raw); b != nil {
		der = b.Bytes
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return key, nil
}

// describeReport records what the Evidence says of the launch: the TSM
// report provider; for SEV-SNP the report version, its launch measurement
// and the key that signed it; for TDX the MRTD and TD attributes of the quote.
func describeReport(r *result, token []byte) {
	var report struct {
		OutBlob  []byte `json:"outblob"`
		Provider string `json:"provider"`
	}
	if cbor.Unmarshal(token, &report) != nil {
		return
	}
	r.ReportProvider = report.Provider
	switch report.Provider {
	case "sev_guest":
		rep, err := abi.ReportToProto(report.OutBlob)
		if err != nil {
			return
		}
		r.ReportVersion = rep.GetVersion()
		r.ReportMeasurement = hex.EncodeToString(rep.GetMeasurement())
		if info, err := abi.ParseSignerInfo(rep.GetSignerInfo()); err == nil {
			r.ReportSigner = info.SigningKey.String()
		}
	case "tdx_guest":
		// A TDX quote: the 48-octet header, then the 584-octet TD report
		// body, whose MRTD is at 136 and TD attributes at 120.
		const header, body = 48, 584
		if len(report.OutBlob) < header+body {
			return
		}
		td := report.OutBlob[header : header+body]
		r.ReportVersion = uint32(binary.LittleEndian.Uint16(report.OutBlob[0:2]))
		r.ReportMeasurement = hex.EncodeToString(td[136:184])
		r.ReportTDAttributes = hex.EncodeToString(td[120:128])
	}
}

func ms(since time.Time) float64 { return float64(time.Since(since).Microseconds()) / 1000 }

func sha256Hex(b []byte) string {
	h := crypto.SHA256.New()
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func rawCerts(certs []*x509.Certificate) [][]byte {
	out := make([][]byte, 0, len(certs))
	for _, c := range certs {
		out = append(out, c.Raw)
	}
	return out
}

func writePEM(path, typ string, blocks [][]byte, mode os.FileMode) error {
	var buf []byte
	for _, b := range blocks {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b})...)
	}
	return os.WriteFile(path, buf, mode)
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644) //nolint:gosec // the record of the exchange
}
