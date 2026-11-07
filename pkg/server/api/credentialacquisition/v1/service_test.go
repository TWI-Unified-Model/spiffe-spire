package credentialacquisition_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"testing"
	"time"

	"github.com/sirupsen/logrus/hooks/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	credentialacquisitionv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/credentialacquisition/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/server/api"
	credentialacquisition "github.com/spiffe/spire/pkg/server/api/credentialacquisition/v1"
	"github.com/spiffe/spire/pkg/server/api/middleware"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	acquisition "github.com/spiffe/spire/pkg/server/credentialacquisition"
	"github.com/spiffe/spire/test/fakes/fakeserverca"
	"github.com/spiffe/spire/test/grpctest"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	td         = spiffeid.RequireTrustDomainFromString("example.org")
	agentID    = spiffeid.RequireFromPath(td, "/agent")
	workloadID = spiffeid.RequireFromPath(td, "/workload")
	testHandle = []byte("0123456789abcdef0123456789abcdef")
	binding    = &types.EvidenceBinding{Method: "binding-input", Hash: "sha512"}
)

type mockAcquirer struct {
	initiateResult *acquisition.InitiationResult
	enrollResult   *acquisition.EnrollmentResult
	container      []byte
	err            error
	lastInitiation *acquisition.Initiation
	lastEnrollment *acquisition.Enrollment
	lastRetrieval  *acquisition.Retrieval
}

func (f *mockAcquirer) Initiate(_ context.Context, in acquisition.Initiation) (*acquisition.InitiationResult, error) {
	f.lastInitiation = &in
	return f.initiateResult, f.err
}

func (f *mockAcquirer) Enroll(_ context.Context, in acquisition.Enrollment) (*acquisition.EnrollmentResult, error) {
	f.lastEnrollment = &in
	return f.enrollResult, f.err
}

func (f *mockAcquirer) Retrieve(_ context.Context, in acquisition.Retrieval) ([]byte, error) {
	f.lastRetrieval = &in
	return f.container, f.err
}

type entryFetcher struct {
	entries []*types.Entry
}

func (f *entryFetcher) LookupAuthorizedEntries(ctx context.Context, id spiffeid.ID, _ map[string]struct{}) (map[string]api.ReadOnlyEntry, error) {
	entries, err := f.FetchAuthorizedEntries(ctx, id)
	if err != nil {
		return nil, err
	}
	out := make(map[string]api.ReadOnlyEntry)
	for _, entry := range entries {
		out[entry.GetId()] = entry
	}
	return out, nil
}

func (f *entryFetcher) FetchAuthorizedEntries(ctx context.Context, id spiffeid.ID) ([]api.ReadOnlyEntry, error) {
	caller, ok := rpccontext.CallerID(ctx)
	if !ok {
		return nil, errors.New("missing caller ID")
	}
	if caller != id {
		return nil, errors.New("provided caller id is different to expected")
	}
	out := make([]api.ReadOnlyEntry, 0, len(f.entries))
	for _, entry := range f.entries {
		out = append(out, api.NewReadOnlyEntry(entry))
	}
	return out, nil
}

type serviceTest struct {
	ca           *fakeserverca.CA
	ef           *entryFetcher
	acquirer     *mockAcquirer
	logHook      *test.Hook
	client       credentialacquisitionv1.CredentialAcquisitionClient
	withCallerID bool
	done         func()
}

func setupServiceTest(t *testing.T) *serviceTest {
	ca := fakeserverca.New(t, td, &fakeserverca.Options{})
	ef := &entryFetcher{entries: []*types.Entry{{
		Id:          "entry-1",
		SpiffeId:    &types.SPIFFEID{TrustDomain: td.Name(), Path: "/workload"},
		ParentId:    &types.SPIFFEID{TrustDomain: td.Name(), Path: "/agent"},
		X509SvidTtl: 600,
		Hint:        "internal",
	}}}
	acquirer := &mockAcquirer{}
	service := credentialacquisition.New(credentialacquisition.Config{
		Acquirer:     acquirer,
		EntryFetcher: ef,
		ServerCA:     ca,
		TrustDomain:  td,
	})

	log, logHook := test.NewNullLogger()
	st := &serviceTest{ca: ca, ef: ef, acquirer: acquirer, logHook: logHook, withCallerID: true}
	overrideContext := func(ctx context.Context) context.Context {
		ctx = rpccontext.WithLogger(ctx, log)
		ctx = rpccontext.WithRateLimiter(ctx, &mockRateLimiter{})
		if st.withCallerID {
			ctx = rpccontext.WithCallerID(ctx, agentID)
		}
		return ctx
	}
	server := grpctest.StartServer(t, func(s grpc.ServiceRegistrar) {
		credentialacquisition.RegisterService(s, service)
	},
		grpctest.OverrideContext(overrideContext),
		grpctest.Middleware(middleware.WithAuditLog(false, false)),
	)
	conn := server.NewGRPCClient(t)
	st.client = credentialacquisitionv1.NewCredentialAcquisitionClient(conn)
	st.done = server.Stop
	return st
}

type mockRateLimiter struct{}

func (f *mockRateLimiter) RateLimit(context.Context, int) error { return nil }

func testCSR(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "workload"},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, key)
	require.NoError(t, err)
	return der, key
}

func TestInitiateCredentialAcquisition(t *testing.T) {
	st := setupServiceTest(t)
	defer st.done()
	ctx := context.Background()

	st.acquirer.initiateResult = &acquisition.InitiationResult{
		Mode:               acquisition.ModeEnroll,
		FreshnessKind:      acquisition.FreshnessPresentNonce,
		Handle:             testHandle,
		ExpiresInSeconds:   300,
		AcceptableCSK:      []string{"ecdsa-p256-sha256"},
		AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"},
	}

	t.Run("missing entry ID", func(t *testing.T) {
		_, err := st.client.InitiateCredentialAcquisition(ctx, &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{Target: td.IDString()})
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "missing entry ID")
	})
	t.Run("entry not authorized for the Agent", func(t *testing.T) {
		_, err := st.client.InitiateCredentialAcquisition(ctx, &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{EntryId: "entry-2", Target: td.IDString()})
		spiretest.RequireGRPCStatus(t, err, codes.NotFound, "entry not found or not authorized")
	})
	t.Run("a refusal of the acquirer is relayed", func(t *testing.T) {
		st.acquirer.err = status.Error(codes.Unimplemented, `credential type "jwt" is not supported for target "spiffe://example.org"; supported: x509`)
		defer func() { st.acquirer.err = nil }()
		_, err := st.client.InitiateCredentialAcquisition(ctx, &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{EntryId: "entry-1", Target: td.IDString(), CredentialType: types.CredentialType_CREDENTIAL_TYPE_JWT})
		spiretest.RequireGRPCStatus(t, err, codes.Unimplemented, `failed to initiate credential acquisition: credential type "jwt" is not supported for target "spiffe://example.org"; supported: x509`)
	})
	t.Run("success", func(t *testing.T) {
		resp, err := st.client.InitiateCredentialAcquisition(ctx, &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
			EntryId: "entry-1", Target: td.IDString(), CredentialType: types.CredentialType_CREDENTIAL_TYPE_X509, CredentialHint: "internal",
		})
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, &credentialacquisitionv1.InitiateCredentialAcquisitionResponse{
			Mode:               types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_ENROLL,
			FreshnessKind:      types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
			FreshnessHandle:    testHandle,
			ExpiresIn:          300,
			AcceptableCsk:      []string{"ecdsa-p256-sha256"},
			AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"},
		}, resp)
		require.Equal(t, &acquisition.Initiation{
			EntryID: "entry-1", AgentID: agentID.String(), Target: td.IDString(), CredentialType: "x509", CredentialHint: "internal",
		}, st.acquirer.lastInitiation)
	})
}

func TestEnrollCredential(t *testing.T) {
	st := setupServiceTest(t)
	defer st.done()
	ctx := context.Background()
	csrDER, key := testCSR(t)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	measurement := []byte{0xa0, 0xa1, 0xa2}

	req := &credentialacquisitionv1.EnrollCredentialRequest{
		EntryId:          "entry-1",
		Target:           td.IDString(),
		CredentialType:   types.CredentialType_CREDENTIAL_TYPE_X509,
		CredentialHint:   "internal",
		FreshnessKind:    types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessElement: testHandle,
		Csr:              csrDER,
		Evidence:         []byte("evidence"),
		EvidenceProfile:  "application/vnd.veraison.tsm-report+cbor",
		Binding:          binding,
	}

	t.Run("missing CSR", func(t *testing.T) {
		_, err := st.client.EnrollCredential(ctx, &credentialacquisitionv1.EnrollCredentialRequest{EntryId: "entry-1", Evidence: []byte("e"), Binding: binding})
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "missing CSR")
	})
	t.Run("missing Binding", func(t *testing.T) {
		_, err := st.client.EnrollCredential(ctx, &credentialacquisitionv1.EnrollCredentialRequest{EntryId: "entry-1", Csr: csrDER, Evidence: []byte("e")})
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "missing Binding")
	})
	t.Run("a refusal of the acquirer is relayed", func(t *testing.T) {
		st.acquirer.err = status.Error(codes.PermissionDenied, "remote attestation failed: Attestation Results: not affirming: SEVSNP is \"contraindicated\"")
		defer func() { st.acquirer.err = nil }()
		_, err := st.client.EnrollCredential(ctx, req)
		spiretest.RequireGRPCStatus(t, err, codes.PermissionDenied, "failed to enroll credential: remote attestation failed: Attestation Results: not affirming: SEVSNP is \"contraindicated\"")
	})
	t.Run("success: an X509-SVID for the CSR key and the SPIFFE ID of the entry", func(t *testing.T) {
		st.logHook.Reset()
		st.acquirer.enrollResult = &acquisition.EnrollmentResult{CSR: csr, Verifier: "veraison", Family: "sevsnp", Measurement: measurement, IssuedAt: time.Now()}
		resp, err := st.client.EnrollCredential(ctx, req)
		require.NoError(t, err)
		require.Equal(t, &acquisition.Enrollment{
			EntryID: "entry-1", AgentID: agentID.String(), Target: td.IDString(), CredentialType: "x509", CredentialHint: "internal",
			FreshnessKind: acquisition.FreshnessPresentNonce, FreshnessElement: testHandle, CSR: csrDER, Evidence: []byte("evidence"),
			EvidenceProfile: "application/vnd.veraison.tsm-report+cbor", BindingMethod: "binding-input", BindingHash: "sha512",
		}, st.acquirer.lastEnrollment)

		svid := resp.GetSvid()
		require.NotNil(t, svid)
		spiretest.AssertProtoEqual(t, &types.SPIFFEID{TrustDomain: td.Name(), Path: "/workload"}, svid.Id)
		require.NotEmpty(t, svid.CertChain)
		cert, err := x509.ParseCertificate(svid.CertChain[0])
		require.NoError(t, err)
		require.Equal(t, workloadID.URL().String(), cert.URIs[0].String())
		require.True(t, key.PublicKey.Equal(cert.PublicKey), "the certificate carries the CSR key")
		require.Equal(t, cert.NotAfter.Unix(), svid.ExpiresAt)
		require.WithinDuration(t, st.ca.Clock().Now().Add(600*time.Second), cert.NotAfter, 2*time.Second)

		entries := st.logHook.AllEntries()
		var audited bool
		for _, e := range entries {
			if e.Message == "API accessed" {
				audited = true
				require.Equal(t, "success", e.Data[telemetry.Status])
				require.Equal(t, "entry-1", e.Data[telemetry.RegistrationID])
				require.Equal(t, "veraison", e.Data["verifier"])
				require.Equal(t, "a0a1a2", e.Data["measurement"])
				require.Equal(t, workloadID.String(), e.Data[telemetry.SPIFFEID])
			}
		}
		require.True(t, audited, "the enrollment is audited")
	})
}

func TestRetrieveCredential(t *testing.T) {
	st := setupServiceTest(t)
	defer st.done()
	ctx := context.Background()
	container := []byte(`{"container":"hpke-base"}`)

	req := &credentialacquisitionv1.RetrieveCredentialRequest{
		EntryId:          "entry-1",
		Target:           "https://api.example",
		CredentialType:   types.CredentialType_CREDENTIAL_TYPE_JWT,
		FreshnessKind:    types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessElement: testHandle,
		CekPub:           []byte("cek"),
		Evidence:         []byte("evidence"),
		Binding:          binding,
	}

	t.Run("missing CEKpub", func(t *testing.T) {
		_, err := st.client.RetrieveCredential(ctx, &credentialacquisitionv1.RetrieveCredentialRequest{EntryId: "entry-1", Evidence: []byte("e"), Binding: binding})
		spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "missing CEKpub")
	})
	t.Run("no caller ID", func(t *testing.T) {
		st.withCallerID = false
		defer func() { st.withCallerID = true }()
		_, err := st.client.RetrieveCredential(ctx, req)
		spiretest.RequireGRPCStatus(t, err, codes.Internal, "caller ID missing from request context")
	})
	t.Run("success: the container comes back as the Secret Vault released it", func(t *testing.T) {
		st.acquirer.container = container
		resp, err := st.client.RetrieveCredential(ctx, req)
		require.NoError(t, err)
		require.Equal(t, container, resp.EncryptedCredentialBundle)
		require.Equal(t, &acquisition.Retrieval{
			EntryID: "entry-1", AgentID: agentID.String(), Target: "https://api.example", CredentialType: "jwt",
			FreshnessKind: acquisition.FreshnessPresentNonce, FreshnessElement: testHandle, CEKPub: []byte("cek"), Evidence: []byte("evidence"),
			BindingMethod: "binding-input", BindingHash: "sha512",
		}, st.acquirer.lastRetrieval)
	})
}
