package credentialacquisition

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testTarget         = "spiffe://example.org"
	testVaultTarget    = "https://api.example"
	testPassportTarget = "https://passport.example"
	testEntryID        = "entry-1"
	testAgentID        = "spiffe://example.org/spire/agent/x509pop/abc"
	testProfile        = "application/vnd.veraison.tsm-report+cbor"
)

type acquirerTest struct {
	a           *Acquirer
	verifier    *mockVerifier
	vault       *mockVault
	veraisonKey *ecdsa.PrivateKey
	now         time.Time
}

// newAcquirerTest builds the Acquirer with a mock Verifier that signs
// affirming Attestation Results for the nonce it is asked for, with the
// test measurement, and a mock Secret Vault.
func newAcquirerTest(t *testing.T) *acquirerTest {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	veraisonKey := newTestKey(t)
	f := newMockVerifier(t)
	f.setAnswer(func(nonce, _ []byte, _ string) (string, string) {
		return "complete", signEAR(t, veraisonKey, nonce, now, "SEVSNP", "affirming", snpCoMID(t, gcpMilan()))
	})
	vault := newMockVault(t)
	log, _ := test.NewNullLogger()
	policies := map[string]*Policy{
		testTarget: {Name: testTarget, Mode: ModeEnroll, CredentialTypes: []string{"x509"}, FreshnessKind: FreshnessPresentNonce,
			ExpiresIn: 5 * time.Minute, Verifiers: []string{"veraison"}, AcceptableCSK: []string{"ecdsa-p256-sha256"},
			Measurements: [][]byte{testMeasurement}},
		testVaultTarget: {Name: testVaultTarget, Mode: ModeRetrieve, CredentialTypes: []string{"jwt"}, FreshnessKind: FreshnessPresentNonce,
			ExpiresIn: 5 * time.Minute, RATSModel: ModelBackgroundCheck},
		testPassportTarget: {Name: testPassportTarget, Mode: ModeRetrieve, CredentialTypes: []string{"api-key"}, FreshnessKind: FreshnessPresentNonce,
			ExpiresIn: 5 * time.Minute, RATSModel: ModelPassport, Verifiers: []string{"veraison"}},
	}
	ear := &earVerifier{
		keys:   []earKey{{name: "veraison", key: &veraisonKey.PublicKey, submods: []string{"SEVSNP"}}},
		maxAge: 2 * time.Minute, skew: 5 * time.Second, now: func() time.Time { return now },
	}
	a := newAcquirer(log, policies, []string{testProfile}, newTestAppraiser(f), ear, newTestVaultClient(vault), func() time.Time { return now })
	return &acquirerTest{a: a, verifier: f, vault: vault, veraisonKey: veraisonKey, now: now}
}

func requireStatus(t *testing.T, err error, code codes.Code, contains string) {
	t.Helper()
	require.Error(t, err)
	require.Equal(t, code, status.Code(err), err.Error())
	require.Contains(t, status.Convert(err).Message(), contains)
}

func TestInitiate(t *testing.T) {
	ctx := context.Background()
	x := newAcquirerTest(t)

	t.Run("enroll Target: the Server mints the Handle", func(t *testing.T) {
		res, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testTarget, CredentialType: "x509"})
		require.NoError(t, err)
		require.Equal(t, ModeEnroll, res.Mode)
		require.Equal(t, FreshnessPresentNonce, res.FreshnessKind)
		require.Len(t, res.Handle, 32)
		require.Equal(t, uint32(300), res.ExpiresIn)
		require.Equal(t, []string{"ecdsa-p256-sha256"}, res.AcceptableCSK)
		require.Empty(t, res.AcceptableCEK)
		require.Equal(t, []string{testProfile}, res.AcceptableEvidence)
	})
	t.Run("retrieve Target: the Secret Vault originates the Handle", func(t *testing.T) {
		res, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testVaultTarget, CredentialType: "jwt", CredentialHint: "billing"})
		require.NoError(t, err)
		require.Equal(t, ModeRetrieve, res.Mode)
		require.Equal(t, x.vault.handle, res.Handle)
		require.Equal(t, uint32(120), res.ExpiresIn)
		require.Equal(t, []string{"DHKEM(P-256, HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"}, res.AcceptableCEK)
		require.Equal(t, map[string]string{"target": testVaultTarget, "credential_type": "jwt", "credential_hint": "billing"}, x.vault.lastInitiate)
	})
	t.Run("missing Target", func(t *testing.T) {
		_, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID})
		requireStatus(t, err, codes.InvalidArgument, "Target must be specified")
	})
	t.Run("unsupported Target", func(t *testing.T) {
		_, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: "https://other.example"})
		requireStatus(t, err, codes.NotFound, "unsupported Target")
	})
	t.Run("a Credential Type that is not one of TACRA", func(t *testing.T) {
		_, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testTarget, CredentialType: "password"})
		requireStatus(t, err, codes.InvalidArgument, `Credential Type "password" is not one of TACRA`)
	})
	t.Run("a Credential Type not supported for the Target", func(t *testing.T) {
		_, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testTarget, CredentialType: "jwt"})
		requireStatus(t, err, codes.Unimplemented, `Credential Type "jwt" is not supported for Target "spiffe://example.org"`)
	})
	t.Run("a refusal of the Secret Vault is relayed", func(t *testing.T) {
		x.vault.mu.Lock()
		x.vault.initiateErr = &vaultRefusal{Status: http.StatusForbidden, Code: "unsupported-target", Detail: "not served"}
		x.vault.mu.Unlock()
		defer func() { x.vault.mu.Lock(); x.vault.initiateErr = nil; x.vault.mu.Unlock() }()
		_, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testVaultTarget})
		requireStatus(t, err, codes.PermissionDenied, "unsupported-target: not served")
	})
}

func TestEnroll(t *testing.T) {
	ctx := context.Background()
	x := newAcquirerTest(t)
	csr := testCSR(t)

	initiate := func(t *testing.T, credentialType, hint string) []byte {
		res, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testTarget, CredentialType: credentialType, CredentialHint: hint})
		require.NoError(t, err)
		return res.Handle
	}
	enrollment := func(handle []byte) Enrollment {
		return Enrollment{
			EntryID: testEntryID, AgentID: testAgentID, Target: testTarget, CredentialType: "x509",
			FreshnessKind: FreshnessPresentNonce, FreshnessElement: handle, CSR: csr,
			Evidence: testEvidence(t, "sev_guest"), EvidenceProfile: testProfile,
			BindingMethod: BindingMethod, BindingHash: BindingHash,
		}
	}

	t.Run("success: the Evidence is appraised with the binding value and the CSR key is returned", func(t *testing.T) {
		handle := initiate(t, "x509", "")
		res, err := x.a.Enroll(ctx, enrollment(handle))
		require.NoError(t, err)
		require.Equal(t, "veraison", res.Verifier)
		require.Equal(t, "SEVSNP", res.Submod)
		require.Equal(t, testMeasurement, res.Measurement)
		require.NotNil(t, res.CSR.PublicKey)
		x.verifier.mu.Lock()
		last := x.verifier.nonces[len(x.verifier.nonces)-1]
		x.verifier.mu.Unlock()
		require.Equal(t, BindingValue(handle, testTarget, csr), last, "the Verifier was asked with the binding value as the nonce")
	})
	t.Run("a Credential Type not supported, named at enrollment only, is refused after the attestation", func(t *testing.T) {
		handle := initiate(t, "", "")
		e := enrollment(handle)
		e.CredentialType = "jwt"
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.Unimplemented, `Credential Type "jwt" is not supported for Target "spiffe://example.org"`)
	})
	t.Run("a failed attestation is refused before the Credential Type is considered", func(t *testing.T) {
		x.verifier.setAnswer(func(_, _ []byte, _ string) (string, string) {
			key := newTestKey(t)
			return "complete", signEAR(t, key, []byte("other"), x.now, "SEVSNP", "affirming", snpCoMID(t, gcpMilan()))
		})
		defer x.restoreVerifier(t)
		handle := initiate(t, "", "")
		e := enrollment(handle)
		e.CredentialType = "jwt"
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.PermissionDenied, "the Attestation Results are not signed by a Verifier specified by the policy for the Target")
	})
	t.Run("a Handle is single use", func(t *testing.T) {
		handle := initiate(t, "x509", "")
		_, err := x.a.Enroll(ctx, enrollment(handle))
		require.NoError(t, err)
		_, err = x.a.Enroll(ctx, enrollment(handle))
		requireStatus(t, err, codes.InvalidArgument, "no initiation returned this Handle")
	})
	t.Run("no initiation", func(t *testing.T) {
		_, err := x.a.Enroll(ctx, enrollment([]byte("0123456789abcdef0123456789abcdef")))
		requireStatus(t, err, codes.InvalidArgument, "no initiation returned this Handle")
	})
	t.Run("the Handle of another Workload", func(t *testing.T) {
		handle := initiate(t, "x509", "")
		e := enrollment(handle)
		e.EntryID = "entry-2"
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.InvalidArgument, "differ from the initiation")
	})
	t.Run("the Credential Type named at initiation must be repeated", func(t *testing.T) {
		handle := initiate(t, "x509", "")
		e := enrollment(handle)
		e.CredentialType = ""
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.InvalidArgument, "a Credential Type or Credential Hint it named is not repeated")
	})
	t.Run("the binding must name binding-input and sha512", func(t *testing.T) {
		handle := initiate(t, "x509", "")
		e := enrollment(handle)
		e.BindingHash = "sha256"
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.InvalidArgument, `binding "binding-input" with "sha256" is not recognized`)
	})
	t.Run("the Freshness Kind must be the one named at initiation", func(t *testing.T) {
		handle := initiate(t, "x509", "")
		e := enrollment(handle)
		e.FreshnessKind = FreshnessAbsentNone
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.InvalidArgument, "differs from present-nonce, the kind named at initiation")
	})
	t.Run("an Evidence format not accepted", func(t *testing.T) {
		handle := initiate(t, "x509", "")
		e := enrollment(handle)
		e.EvidenceProfile = "application/octet-stream"
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.InvalidArgument, `Evidence format "application/octet-stream" is not accepted`)
	})
	t.Run("a CSR of another key algorithm", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		rsaCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "w"}}, rsaKey)
		require.NoError(t, err)
		handle := initiate(t, "x509", "")
		e := enrollment(handle)
		e.CSR = rsaCSR
		_, err = x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.InvalidArgument, "the CSR key or signature is not one of the acceptable CSK algorithms")
	})
	t.Run("a malformed CSR", func(t *testing.T) {
		handle := initiate(t, "x509", "")
		e := enrollment(handle)
		e.CSR = []byte("not a csr")
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.InvalidArgument, "malformed CSR")
	})
	t.Run("a substituted CSR fails the binding", func(t *testing.T) {
		// The mock Verifier puts, as the nonce of its Attestation Results, the
		// binding value the Server sent when it opened the session; the Server
		// computes that value from the CSR it received, so the CSR cannot be
		// substituted after the fact. The mock reports another nonce instead,
		// which is what a substituted CSR looks like to the Server.
		x.verifier.setAnswer(func(_, _ []byte, _ string) (string, string) {
			return "complete", signEAR(t, x.veraisonKey, []byte("other"), x.now, "SEVSNP", "affirming", snpCoMID(t, gcpMilan()))
		})
		defer x.restoreVerifier(t)
		handle := initiate(t, "x509", "")
		_, err := x.a.Enroll(ctx, enrollment(handle))
		requireStatus(t, err, codes.PermissionDenied, "the Attestation Results report a nonce that is not the binding value")
	})
	t.Run("a launch measurement not admitted", func(t *testing.T) {
		h := gcpMilan()
		h.measurement = append([]byte(nil), testMeasurement...)
		h.measurement[0] ^= 0xff
		x.setVerifierHost(t, h)
		defer x.restoreVerifier(t)
		handle := initiate(t, "x509", "")
		_, err := x.a.Enroll(ctx, enrollment(handle))
		requireStatus(t, err, codes.PermissionDenied, "the launch measurement is not admitted for Target")
	})
	t.Run("a guest policy with DEBUG", func(t *testing.T) {
		h := gcpMilan()
		h.policy |= 1 << 19
		x.setVerifierHost(t, h)
		defer x.restoreVerifier(t)
		handle := initiate(t, "x509", "")
		_, err := x.a.Enroll(ctx, enrollment(handle))
		requireStatus(t, err, codes.PermissionDenied, "the guest policy has DEBUG set")
	})
	t.Run("results that are not affirming", func(t *testing.T) {
		// contraindicated is the lowest of the EAR trust tiers (affirming,
		// warning, contraindicated, none): the Verifier appraised the Evidence
		// and found it against its policy. The Server accepts affirming results
		// alone.
		x.verifier.setAnswer(func(nonce, _ []byte, _ string) (string, string) {
			return "complete", signEAR(t, x.veraisonKey, nonce, x.now, "SEVSNP", "contraindicated", snpCoMID(t, gcpMilan()))
		})
		defer x.restoreVerifier(t)
		handle := initiate(t, "x509", "")
		_, err := x.a.Enroll(ctx, enrollment(handle))
		requireStatus(t, err, codes.PermissionDenied, `the Verifier did not affirm the Evidence: SEVSNP is "contraindicated"`)
	})
	t.Run("Evidence of a provider no policy Verifier appraises", func(t *testing.T) {
		handle := initiate(t, "x509", "")
		e := enrollment(handle)
		e.Evidence = testEvidence(t, "tdx_guest")
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.PermissionDenied, "the policy for the Target specifies no Verifier for Evidence of this provider")
	})
	t.Run("a retrieve Target refuses enrollment", func(t *testing.T) {
		e := enrollment([]byte("0123456789abcdef0123456789abcdef"))
		e.Target = testVaultTarget
		e.CredentialType = "jwt"
		_, err := x.a.Enroll(ctx, e)
		requireStatus(t, err, codes.InvalidArgument, "is served in retrieve mode")
	})
}

func TestRetrieve(t *testing.T) {
	ctx := context.Background()
	x := newAcquirerTest(t)
	evidence := testEvidence(t, "sev_guest")

	res, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testVaultTarget, CredentialType: "jwt", CredentialHint: "billing"})
	require.NoError(t, err)

	retrieval := func() Retrieval {
		return Retrieval{
			EntryID: testEntryID, AgentID: testAgentID, Target: testVaultTarget, CredentialType: "jwt", CredentialHint: "billing",
			FreshnessKind: FreshnessPresentNonce, FreshnessElement: res.Handle, CEKPub: []byte("cek-spki"),
			Evidence: evidence, EvidenceProfile: testProfile, BindingMethod: BindingMethod, BindingHash: BindingHash,
		}
	}

	t.Run("the request is forwarded to the Secret Vault with the container coming back opaque", func(t *testing.T) {
		container, err := x.a.Retrieve(ctx, retrieval())
		require.NoError(t, err)
		require.JSONEq(t, x.vault.container, string(container))
		require.Equal(t, vaultRetrieval{
			FreshnessKind: FreshnessPresentNonce, Target: testVaultTarget, CredentialType: "jwt",
			Handle: "dmF1bHQtaGFuZGxlLTAxMjM0NTY3ODlhYmNkZWYwMTI", CredentialHint: "billing",
			Evidence: b64u(evidence), Profile: testProfile, CEKPub: "Y2VrLXNwa2k",
		}, x.vault.lastRetrieve)
	})
	t.Run("the Handle was consumed", func(t *testing.T) {
		_, err := x.a.Retrieve(ctx, retrieval())
		requireStatus(t, err, codes.InvalidArgument, "no initiation returned this Handle")
	})
	t.Run("a refusal of the Secret Vault is relayed with its reason", func(t *testing.T) {
		res, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testVaultTarget, CredentialType: "jwt", CredentialHint: "billing"})
		require.NoError(t, err)
		x.vault.mu.Lock()
		x.vault.retrieveErr = &vaultRefusal{Status: http.StatusBadRequest, Code: "binding", Detail: "the bound value differs"}
		x.vault.mu.Unlock()
		defer func() { x.vault.mu.Lock(); x.vault.retrieveErr = nil; x.vault.mu.Unlock() }()
		r := retrieval()
		r.FreshnessElement = res.Handle
		_, err = x.a.Retrieve(ctx, r)
		requireStatus(t, err, codes.InvalidArgument, "binding: the bound value differs")
	})
	t.Run("passport: the Server obtains the Attestation Results and forwards them", func(t *testing.T) {
		res, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testPassportTarget, CredentialType: "api-key", CredentialHint: "billing"})
		require.NoError(t, err)
		r := retrieval()
		r.Target, r.CredentialType, r.FreshnessElement = testPassportTarget, "api-key", res.Handle
		container, err := x.a.Retrieve(ctx, r)
		require.NoError(t, err)
		require.JSONEq(t, x.vault.container, string(container))
		x.verifier.mu.Lock()
		last := x.verifier.nonces[len(x.verifier.nonces)-1]
		x.verifier.mu.Unlock()
		require.Equal(t, BindingValue(res.Handle, testPassportTarget, r.CEKPub), last, "the Verifier was asked with the binding value over CEKpub")
		retrieval := x.vault.lastRetrieve
		require.NotEmpty(t, retrieval.EAR, "the Attestation Results go to the Secret Vault")
		require.Empty(t, retrieval.Evidence, "the Evidence stays with the Server")
		require.Empty(t, retrieval.Profile)
		require.Equal(t, testPassportTarget, retrieval.Target)
		require.Equal(t, "api-key", retrieval.CredentialType)
	})
	t.Run("passport: a Credential Type not supported, named at retrieval only, is refused after the Attestation Results", func(t *testing.T) {
		res, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testPassportTarget, CredentialHint: "billing"})
		require.NoError(t, err)
		r := retrieval()
		r.Target, r.CredentialType, r.FreshnessElement = testPassportTarget, "psk", res.Handle
		_, err = x.a.Retrieve(ctx, r)
		requireStatus(t, err, codes.Unimplemented, `Credential Type "psk" is not supported for Target "https://passport.example"`)
		x.verifier.mu.Lock()
		asked := len(x.verifier.nonces)
		x.verifier.mu.Unlock()
		require.Positive(t, asked, "the Verifier was asked before the type was refused")
	})
	t.Run("passport: no Verifier for the provider of the Evidence", func(t *testing.T) {
		res, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testPassportTarget, CredentialType: "api-key", CredentialHint: "billing"})
		require.NoError(t, err)
		r := retrieval()
		r.Target, r.CredentialType, r.FreshnessElement = testPassportTarget, "api-key", res.Handle
		r.Evidence = testEvidence(t, "tdx_guest")
		_, err = x.a.Retrieve(ctx, r)
		requireStatus(t, err, codes.PermissionDenied, "the policy for the Target specifies no Verifier for Evidence of this provider")
	})
	t.Run("an enroll Target refuses retrieval", func(t *testing.T) {
		r := retrieval()
		r.Target = testTarget
		r.CredentialType = "x509"
		_, err := x.a.Retrieve(ctx, r)
		requireStatus(t, err, codes.InvalidArgument, "is served in enroll mode")
	})
}

func (x *acquirerTest) setVerifierHost(t *testing.T, h snpHost) {
	x.verifier.setAnswer(func(nonce, _ []byte, _ string) (string, string) {
		return "complete", signEAR(t, x.veraisonKey, nonce, x.now, "SEVSNP", "affirming", snpCoMID(t, h))
	})
}

func (x *acquirerTest) restoreVerifier(t *testing.T) {
	x.setVerifierHost(t, gcpMilan())
}

// TestEnrollPlatformRule applies the platform rule of the recorded runs: the Milan host of
// the records passes under the waiver of mitigation bit 4, a host below the
// TCB floor is refused, and a product line not admitted is refused.
func TestEnrollPlatformRule(t *testing.T) {
	ctx := context.Background()
	x := newAcquirerTest(t)
	x.a.platform = recordedRule(t)
	csr := testCSR(t)
	enroll := func(t *testing.T) (*EnrollmentResult, error) {
		res, err := x.a.Initiate(ctx, Initiation{EntryID: testEntryID, AgentID: testAgentID, Target: testTarget, CredentialType: "x509"})
		require.NoError(t, err)
		return x.a.Enroll(ctx, Enrollment{
			EntryID: testEntryID, AgentID: testAgentID, Target: testTarget, CredentialType: "x509",
			FreshnessKind: FreshnessPresentNonce, FreshnessElement: res.Handle, CSR: csr,
			Evidence: testEvidence(t, "sev_guest"), EvidenceProfile: testProfile,
			BindingMethod: BindingMethod, BindingHash: BindingHash,
		})
	}
	t.Run("the host of the records is admitted under the waiver", func(t *testing.T) {
		res, err := enroll(t)
		require.NoError(t, err)
		require.Len(t, res.Waived, 1)
		require.Contains(t, res.Waived[0], "admitted without bit 4")
	})
	t.Run("a TCB below the floor is refused", func(t *testing.T) {
		h := gcpMilan()
		h.reportedTCB = 0xDE1C000000000004 // SNP 28, below the Milan floor of 29
		x.setVerifierHost(t, h)
		defer x.restoreVerifier(t)
		_, err := enroll(t)
		requireStatus(t, err, codes.PermissionDenied, "REPORTED_TCB snp 28 is below the floor 29")
	})
	t.Run("a product line not admitted is refused", func(t *testing.T) {
		h := gcpMilan()
		h.family, h.model = 0x19, 0xA0 // Siena
		x.setVerifierHost(t, h)
		defer x.restoreVerifier(t)
		_, err := enroll(t)
		requireStatus(t, err, codes.PermissionDenied, `product line "Siena"`)
	})
	t.Run("a report without mitigation vectors is refused where bits are required", func(t *testing.T) {
		h := gcpMilan()
		h.noMitVectors = true
		x.setVerifierHost(t, h)
		defer x.restoreVerifier(t)
		_, err := enroll(t)
		requireStatus(t, err, codes.PermissionDenied, "the report carries no mitigation vector")
	})
}

// TestVaultErrorCodes: a refusal of the Secret Vault reaches the Workload with
// the gRPC code of its HTTP status; anything else from the Secret Vault is
// Unavailable.
func TestVaultErrorCodes(t *testing.T) {
	for _, tt := range []struct {
		status int
		code   codes.Code
	}{
		{http.StatusBadRequest, codes.InvalidArgument},
		{http.StatusUnsupportedMediaType, codes.InvalidArgument},
		{http.StatusForbidden, codes.PermissionDenied},
		{http.StatusUnprocessableEntity, codes.Unimplemented},
		{http.StatusNotFound, codes.NotFound},
		{http.StatusTooManyRequests, codes.ResourceExhausted},
		{http.StatusBadGateway, codes.Unavailable},
		{http.StatusInternalServerError, codes.Unavailable},
	} {
		err := vaultError(&vaultRefusal{Status: tt.status, Code: "code", Detail: "detail"})
		require.Equal(t, tt.code, status.Code(err), "HTTP %d", tt.status)
		require.Contains(t, err.Error(), "code: detail")
	}
	require.Equal(t, codes.Unavailable, status.Code(vaultError(errors.New("connection refused"))))
}
