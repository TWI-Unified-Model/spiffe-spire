package manager

import (
	"context"
	"testing"

	credentialacquisitionv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/credentialacquisition/v1"
	"github.com/spiffe/spire/pkg/agent/client"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/stretchr/testify/require"
)

// fakeCredentialAcquisitionClient records the requests the manager forwards
// to the Server for attested credential acquisition.
type fakeCredentialAcquisitionClient struct {
	client.Client

	initiateReq *credentialacquisitionv1.InitiateCredentialAcquisitionRequest
	enrollReq   *credentialacquisitionv1.EnrollCredentialRequest
	retrieveReq *credentialacquisitionv1.RetrieveCredentialRequest
}

func (c *fakeCredentialAcquisitionClient) InitiateCredentialAcquisition(_ context.Context, req *credentialacquisitionv1.InitiateCredentialAcquisitionRequest) (*credentialacquisitionv1.InitiateCredentialAcquisitionResponse, error) {
	c.initiateReq = req
	return &credentialacquisitionv1.InitiateCredentialAcquisitionResponse{FreshnessHandle: []byte("handle")}, nil
}

func (c *fakeCredentialAcquisitionClient) EnrollCredential(_ context.Context, req *credentialacquisitionv1.EnrollCredentialRequest) (*credentialacquisitionv1.EnrollCredentialResponse, error) {
	c.enrollReq = req
	return &credentialacquisitionv1.EnrollCredentialResponse{}, nil
}

func (c *fakeCredentialAcquisitionClient) RetrieveCredential(_ context.Context, req *credentialacquisitionv1.RetrieveCredentialRequest) (*credentialacquisitionv1.RetrieveCredentialResponse, error) {
	c.retrieveReq = req
	return &credentialacquisitionv1.RetrieveCredentialResponse{EncryptedCredentialBundle: []byte("bundle")}, nil
}

// TestCredentialAcquisitionNamesTheEntry checks that the manager forwards each
// call for the registration entry the handler chose: the entry ID travels in
// the request, as the Server authorizes the Agent per entry.
func TestCredentialAcquisitionNamesTheEntry(t *testing.T) {
	fake := &fakeCredentialAcquisitionClient{}
	m := &manager{client: fake}
	entry := &common.RegistrationEntry{EntryId: "entry-1", SpiffeId: "spiffe://example.org/workload"}

	initiateResp, err := m.InitiateCredentialAcquisition(context.Background(), entry, &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{Target: "spiffe://example.org"})
	require.NoError(t, err)
	require.Equal(t, []byte("handle"), initiateResp.FreshnessHandle)
	spiretest.AssertProtoEqual(t, &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{EntryId: "entry-1", Target: "spiffe://example.org"}, fake.initiateReq)

	_, err = m.EnrollCredential(context.Background(), entry, &credentialacquisitionv1.EnrollCredentialRequest{Target: "spiffe://example.org", Csr: []byte("csr")})
	require.NoError(t, err)
	spiretest.AssertProtoEqual(t, &credentialacquisitionv1.EnrollCredentialRequest{EntryId: "entry-1", Target: "spiffe://example.org", Csr: []byte("csr")}, fake.enrollReq)

	retrieveResp, err := m.RetrieveCredential(context.Background(), entry, &credentialacquisitionv1.RetrieveCredentialRequest{Target: "https://vault.example", CekPub: []byte("cek")})
	require.NoError(t, err)
	require.Equal(t, []byte("bundle"), retrieveResp.EncryptedCredentialBundle)
	spiretest.AssertProtoEqual(t, &credentialacquisitionv1.RetrieveCredentialRequest{EntryId: "entry-1", Target: "https://vault.example", CekPub: []byte("cek")}, fake.retrieveReq)
}
