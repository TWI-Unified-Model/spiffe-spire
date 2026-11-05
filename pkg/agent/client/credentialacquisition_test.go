package client

import (
	"context"
	"sync"
	"testing"

	credentialacquisitionv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/credentialacquisition/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type mockCredentialAcquisitionServer struct {
	credentialacquisitionv1.UnimplementedCredentialAcquisitionServer

	mu           sync.Mutex
	err          error
	initiateResp *credentialacquisitionv1.InitiateCredentialAcquisitionResponse
	enrollResp   *credentialacquisitionv1.EnrollCredentialResponse
	retrieveResp *credentialacquisitionv1.RetrieveCredentialResponse
	lastInitiate *credentialacquisitionv1.InitiateCredentialAcquisitionRequest
	lastEnroll   *credentialacquisitionv1.EnrollCredentialRequest
	lastRetrieve *credentialacquisitionv1.RetrieveCredentialRequest
}

func (s *mockCredentialAcquisitionServer) InitiateCredentialAcquisition(_ context.Context, req *credentialacquisitionv1.InitiateCredentialAcquisitionRequest) (*credentialacquisitionv1.InitiateCredentialAcquisitionResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastInitiate = req
	if s.err != nil {
		return nil, s.err
	}
	return s.initiateResp, nil
}

func (s *mockCredentialAcquisitionServer) EnrollCredential(_ context.Context, req *credentialacquisitionv1.EnrollCredentialRequest) (*credentialacquisitionv1.EnrollCredentialResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastEnroll = req
	if s.err != nil {
		return nil, s.err
	}
	return s.enrollResp, nil
}

func (s *mockCredentialAcquisitionServer) RetrieveCredential(_ context.Context, req *credentialacquisitionv1.RetrieveCredentialRequest) (*credentialacquisitionv1.RetrieveCredentialResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastRetrieve = req
	if s.err != nil {
		return nil, s.err
	}
	return s.retrieveResp, nil
}

func TestInitiateCredentialAcquisition(t *testing.T) {
	client, tc := createClient(t)

	req := &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
		EntryId:        "entry-1",
		Target:         "spiffe://example.org",
		CredentialType: types.CredentialType_CREDENTIAL_TYPE_X509,
	}
	want := &credentialacquisitionv1.InitiateCredentialAcquisitionResponse{
		Mode:            types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_ENROLL,
		FreshnessKind:   types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessHandle: []byte("0123456789abcdef0123456789abcdef"),
		ExpiresIn:       300,
		AcceptableCsk:   []string{"ecdsa-p256-sha256"},
	}

	t.Run("success keeps the connection", func(t *testing.T) {
		tc.credentialAcquisitionServer.initiateResp = want
		tc.credentialAcquisitionServer.err = nil

		resp, err := client.InitiateCredentialAcquisition(context.Background(), req)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, want, resp)
		spiretest.AssertProtoEqual(t, req, tc.credentialAcquisitionServer.lastInitiate)
		assertConnectionIsNotNil(t, client)
	})

	t.Run("refusal carries the status of the Server and releases the connection", func(t *testing.T) {
		tc.credentialAcquisitionServer.err = status.Error(codes.PermissionDenied, "unsupported Target")

		resp, err := client.InitiateCredentialAcquisition(context.Background(), req)
		require.Nil(t, resp)
		require.EqualError(t, err, "failed to initiate credential acquisition: rpc error: code = PermissionDenied desc = unsupported Target")
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		assertConnectionIsNil(t, client)
	})
}

func TestEnrollCredential(t *testing.T) {
	client, tc := createClient(t)

	req := &credentialacquisitionv1.EnrollCredentialRequest{
		EntryId:          "entry-1",
		Target:           "spiffe://example.org",
		FreshnessKind:    types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessElement: []byte("0123456789abcdef0123456789abcdef"),
		Csr:              []byte("csr"),
		Evidence:         []byte("evidence"),
		Binding:          &types.EvidenceBinding{Method: "binding-input", Hash: "sha512"},
	}
	want := &credentialacquisitionv1.EnrollCredentialResponse{
		Svid: &types.X509SVID{
			Id:        &types.SPIFFEID{TrustDomain: "example.org", Path: "/workload"},
			CertChain: [][]byte{[]byte("cert")},
			ExpiresAt: 1234,
		},
	}

	t.Run("success keeps the connection", func(t *testing.T) {
		tc.credentialAcquisitionServer.enrollResp = want
		tc.credentialAcquisitionServer.err = nil

		resp, err := client.EnrollCredential(context.Background(), req)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, want, resp)
		spiretest.AssertProtoEqual(t, req, tc.credentialAcquisitionServer.lastEnroll)
		assertConnectionIsNotNil(t, client)
	})

	t.Run("refusal carries the status of the Server and releases the connection", func(t *testing.T) {
		tc.credentialAcquisitionServer.err = status.Error(codes.InvalidArgument, "binding mismatch")

		resp, err := client.EnrollCredential(context.Background(), req)
		require.Nil(t, resp)
		require.EqualError(t, err, "failed to enroll credential: rpc error: code = InvalidArgument desc = binding mismatch")
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		assertConnectionIsNil(t, client)
	})
}

func TestRetrieveCredential(t *testing.T) {
	client, tc := createClient(t)

	req := &credentialacquisitionv1.RetrieveCredentialRequest{
		EntryId:          "entry-1",
		Target:           "https://vault.example",
		CredentialType:   types.CredentialType_CREDENTIAL_TYPE_JWT,
		FreshnessKind:    types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessElement: []byte("0123456789abcdef0123456789abcdef"),
		CekPub:           []byte("cek_pub"),
		Evidence:         []byte("evidence"),
		Binding:          &types.EvidenceBinding{Method: "binding-input", Hash: "sha512"},
	}
	want := &credentialacquisitionv1.RetrieveCredentialResponse{EncryptedCredentialBundle: []byte(`{"container":"hpke-base"}`)}

	t.Run("success keeps the connection", func(t *testing.T) {
		tc.credentialAcquisitionServer.retrieveResp = want
		tc.credentialAcquisitionServer.err = nil

		resp, err := client.RetrieveCredential(context.Background(), req)
		require.NoError(t, err)
		spiretest.AssertProtoEqual(t, want, resp)
		spiretest.AssertProtoEqual(t, req, tc.credentialAcquisitionServer.lastRetrieve)
		assertConnectionIsNotNil(t, client)
	})

	t.Run("refusal carries the status of the Server and releases the connection", func(t *testing.T) {
		tc.credentialAcquisitionServer.err = status.Error(codes.PermissionDenied, "unsupported Credential Type")

		resp, err := client.RetrieveCredential(context.Background(), req)
		require.Nil(t, resp)
		require.EqualError(t, err, "failed to retrieve credential: rpc error: code = PermissionDenied desc = unsupported Credential Type")
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		assertConnectionIsNil(t, client)
	})
}
