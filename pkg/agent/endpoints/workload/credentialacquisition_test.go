package workload_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/sirupsen/logrus"
	workloadPB "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	credentialacquisitionv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/credentialacquisition/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/proto/spire/common"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

var (
	testHandle  = []byte("0123456789abcdef0123456789abcdef")
	testBinding = &workloadPB.EvidenceBinding{Method: "binding-input", Hash: "sha512"}
)

func credentialAcquisitionIdentities(ca *testca.CA) []cache.X509Identity {
	internal := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/internal"))
	internal.Hint = "internal"
	external := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/external"))
	external.Hint = "external"
	return []cache.X509Identity{
		identityFromX509SVID(internal, "id-internal"),
		identityFromX509SVID(external, "id-external"),
	}
}

func TestInitiateCredentialAcquisition(t *testing.T) {
	ca := testca.New(t, td)
	identities := credentialAcquisitionIdentities(ca)

	serverResp := &credentialacquisitionv1.InitiateCredentialAcquisitionResponse{
		Mode:               types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_ENROLL,
		FreshnessKind:      types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessHandle:    testHandle,
		ExpiresIn:          300,
		AcceptableCsk:      []string{"ecdsa-p256-sha256"},
		AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"},
	}
	workloadResp := &workloadPB.InitiateCredentialAcquisitionResponse{
		Mode:               workloadPB.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_ENROLL,
		FreshnessKind:      workloadPB.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessHandle:    testHandle,
		ExpiresIn:          300,
		AcceptableCsk:      []string{"ecdsa-p256-sha256"},
		AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"},
	}

	for _, tt := range []struct {
		name           string
		identities     []cache.X509Identity
		req            *workloadPB.InitiateCredentialAcquisitionRequest
		attestErr      error
		managerErr     error
		expectCode     codes.Code
		expectMsg      string
		expectResp     *workloadPB.InitiateCredentialAcquisitionResponse
		expectEntryID  string
		expectForwards *credentialacquisitionv1.InitiateCredentialAcquisitionRequest
		expectLogs     []spiretest.LogEntry
	}{
		{
			name:       "missing required Target",
			identities: identities,
			req:        &workloadPB.InitiateCredentialAcquisitionRequest{},
			expectCode: codes.InvalidArgument,
			expectMsg:  "Target must be specified",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Missing required Target parameter",
					Data: logrus.Fields{
						"service": "WorkloadAPI",
						"method":  "InitiateCredentialAcquisition",
					},
				},
			},
		},
		{
			name:       "attest error",
			identities: identities,
			req:        &workloadPB.InitiateCredentialAcquisitionRequest{Target: td.IDString()},
			attestErr:  errors.New("ohno"),
			expectCode: codes.Unavailable,
			expectMsg:  "workload attestation failed",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Workload attestation failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "InitiateCredentialAcquisition",
						logrus.ErrorKey: "ohno",
					},
				},
			},
		},
		{
			name:       "no identity issued",
			req:        &workloadPB.InitiateCredentialAcquisitionRequest{Target: td.IDString()},
			expectCode: codes.PermissionDenied,
			expectMsg:  "no identity issued",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "No identity issued",
					Data: logrus.Fields{
						"registered": "false",
						"service":    "WorkloadAPI",
						"method":     "InitiateCredentialAcquisition",
					},
				},
			},
		},
		{
			name:          "a Credential Hint that no entry carries goes on with the default identity",
			identities:    identities,
			req:           &workloadPB.InitiateCredentialAcquisitionRequest{Target: td.IDString(), CredentialHint: "payments.workload.example"},
			expectResp:    workloadResp,
			expectEntryID: "id-internal",
			expectForwards: &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
				Target:         td.IDString(),
				CredentialHint: "payments.workload.example",
			},
		},
		{
			name:       "Server refuses the call",
			identities: identities,
			req:        &workloadPB.InitiateCredentialAcquisitionRequest{Target: "https://other.example"},
			managerErr: status.Error(codes.PermissionDenied, "unsupported Target"),
			expectCode: codes.PermissionDenied,
			expectMsg:  "unsupported Target",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Initiate credential acquisition failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "InitiateCredentialAcquisition",
						"spiffe_id":     "spiffe://domain.test/internal",
						"entry_id":      "id-internal",
						logrus.ErrorKey: "rpc error: code = PermissionDenied desc = unsupported Target",
					},
				},
			},
		},
		{
			name:       "Server refuses the call, wrapped by the client",
			identities: identities,
			req:        &workloadPB.InitiateCredentialAcquisitionRequest{Target: "https://other.example"},
			managerErr: fmt.Errorf("failed to initiate credential acquisition: %w", status.Error(codes.PermissionDenied, "unsupported Target")),
			expectCode: codes.PermissionDenied,
			expectMsg:  "unsupported Target",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Initiate credential acquisition failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "InitiateCredentialAcquisition",
						"spiffe_id":     "spiffe://domain.test/internal",
						"entry_id":      "id-internal",
						logrus.ErrorKey: "failed to initiate credential acquisition: rpc error: code = PermissionDenied desc = unsupported Target",
					},
				},
			},
		},
		{
			name:       "Server unreachable",
			identities: identities,
			req:        &workloadPB.InitiateCredentialAcquisitionRequest{Target: td.IDString()},
			managerErr: errors.New("ohno"),
			expectCode: codes.Unavailable,
			expectMsg:  "Initiate credential acquisition failed: ohno",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Initiate credential acquisition failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "InitiateCredentialAcquisition",
						"spiffe_id":     "spiffe://domain.test/internal",
						"entry_id":      "id-internal",
						logrus.ErrorKey: "ohno",
					},
				},
			},
		},
		{
			name:          "success with the default identity",
			identities:    identities,
			req:           &workloadPB.InitiateCredentialAcquisitionRequest{Target: td.IDString(), CredentialType: workloadPB.CredentialType_CREDENTIAL_TYPE_X509},
			expectResp:    workloadResp,
			expectEntryID: "id-internal",
			expectForwards: &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
				Target:         td.IDString(),
				CredentialType: types.CredentialType_CREDENTIAL_TYPE_X509,
			},
		},
		{
			name:          "success with the identity of the Credential Hint",
			identities:    identities,
			req:           &workloadPB.InitiateCredentialAcquisitionRequest{Target: td.IDString(), CredentialHint: "external"},
			expectResp:    workloadResp,
			expectEntryID: "id-external",
			expectForwards: &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
				Target:         td.IDString(),
				CredentialHint: "external",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := &credentialAcquisitionCalls{}
			params := testParams{
				CA:                         ca,
				Identities:                 tt.identities,
				AttestErr:                  tt.attestErr,
				CredentialAcquisitionErr:   tt.managerErr,
				InitiateResponse:           serverResp,
				CredentialAcquisitionCalls: calls,
				ExpectLogs:                 tt.expectLogs,
			}
			runTest(t, params,
				func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
					resp, err := client.InitiateCredentialAcquisition(ctx, tt.req)
					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
					if tt.expectCode != codes.OK {
						assert.Nil(t, resp)
						return
					}
					spiretest.AssertProtoEqual(t, tt.expectResp, resp)
					require.Equal(t, []string{tt.expectEntryID}, calls.entryIDs)
					require.Len(t, calls.requests, 1)
					spiretest.AssertProtoEqual(t, tt.expectForwards, calls.requests[0].(proto.Message))
				})
		})
	}
}

func TestEnrollCredential(t *testing.T) {
	ca := testca.New(t, td)
	identities := credentialAcquisitionIdentities(ca)
	minted := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/internal"))
	bundle := x509util.DERFromCertificates(ca.Bundle().X509Authorities())

	fullReq := &workloadPB.EnrollCredentialRequest{
		Target:           td.IDString(),
		CredentialType:   workloadPB.CredentialType_CREDENTIAL_TYPE_X509,
		CredentialHint:   "internal",
		FreshnessKind:    workloadPB.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessElement: testHandle,
		Csr:              []byte("csr"),
		Evidence:         []byte("evidence"),
		EvidenceProfile:  "application/vnd.veraison.tsm-report+cbor",
		Binding:          testBinding,
	}
	serverResp := &credentialacquisitionv1.EnrollCredentialResponse{
		Svid: &types.X509SVID{
			Id:        &types.SPIFFEID{TrustDomain: td.Name(), Path: "/internal"},
			CertChain: x509util.RawCertsFromCertificates(minted.Certificates),
			ExpiresAt: minted.Certificates[0].NotAfter.Unix(),
		},
	}

	for _, tt := range []struct {
		name          string
		identities    []cache.X509Identity
		req           *workloadPB.EnrollCredentialRequest
		serverResp    *credentialacquisitionv1.EnrollCredentialResponse
		managerErr    error
		expectCode    codes.Code
		expectMsg     string
		expectResp    *workloadPB.EnrollCredentialResponse
		expectEntryID string
		expectLogs    []spiretest.LogEntry
	}{
		{
			name:       "missing required CSR",
			identities: identities,
			req:        &workloadPB.EnrollCredentialRequest{Target: td.IDString(), Evidence: []byte("evidence"), Binding: testBinding},
			expectCode: codes.InvalidArgument,
			expectMsg:  "CSR must be specified",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Missing required CSR parameter",
					Data:    logrus.Fields{"service": "WorkloadAPI", "method": "EnrollCredential"},
				},
			},
		},
		{
			name:       "missing required Evidence",
			identities: identities,
			req:        &workloadPB.EnrollCredentialRequest{Target: td.IDString(), Csr: []byte("csr"), Binding: testBinding},
			expectCode: codes.InvalidArgument,
			expectMsg:  "Evidence must be specified",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Missing required Evidence parameter",
					Data:    logrus.Fields{"service": "WorkloadAPI", "method": "EnrollCredential"},
				},
			},
		},
		{
			name:       "missing required Binding",
			identities: identities,
			req:        &workloadPB.EnrollCredentialRequest{Target: td.IDString(), Csr: []byte("csr"), Evidence: []byte("evidence")},
			expectCode: codes.InvalidArgument,
			expectMsg:  "Binding must be specified",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Missing required Binding parameter",
					Data:    logrus.Fields{"service": "WorkloadAPI", "method": "EnrollCredential"},
				},
			},
		},
		{
			name:       "Server refuses the binding",
			identities: identities,
			req:        fullReq,
			serverResp: serverResp,
			managerErr: status.Error(codes.InvalidArgument, "binding mismatch"),
			expectCode: codes.InvalidArgument,
			expectMsg:  "binding mismatch",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Enroll credential failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "EnrollCredential",
						"spiffe_id":     "spiffe://domain.test/internal",
						"entry_id":      "id-internal",
						logrus.ErrorKey: "rpc error: code = InvalidArgument desc = binding mismatch",
					},
				},
			},
		},
		{
			name:       "Server returns no SVID",
			identities: identities,
			req:        fullReq,
			serverResp: &credentialacquisitionv1.EnrollCredentialResponse{},
			expectCode: codes.Internal,
			expectMsg:  "the Server returned no X509-SVID",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "The Server returned no X509-SVID",
					Data: logrus.Fields{
						"service":   "WorkloadAPI",
						"method":    "EnrollCredential",
						"spiffe_id": "spiffe://domain.test/internal",
						"entry_id":  "id-internal",
					},
				},
			},
		},
		{
			name:       "Server returns an SVID with a malformed SPIFFE ID",
			identities: identities,
			req:        fullReq,
			serverResp: &credentialacquisitionv1.EnrollCredentialResponse{
				Svid: &types.X509SVID{
					Id:        &types.SPIFFEID{TrustDomain: "domain.test", Path: "no-leading-slash"},
					CertChain: x509util.RawCertsFromCertificates(minted.Certificates),
				},
			},
			expectCode: codes.Internal,
			expectMsg:  "the Server returned an X509-SVID with a malformed SPIFFE ID: path must have a leading slash",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "The Server returned an X509-SVID with a malformed SPIFFE ID",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "EnrollCredential",
						"spiffe_id":     "spiffe://domain.test/internal",
						"entry_id":      "id-internal",
						logrus.ErrorKey: "path must have a leading slash",
					},
				},
			},
		},
		{
			name:       "success",
			identities: identities,
			req:        fullReq,
			serverResp: serverResp,
			expectResp: &workloadPB.EnrollCredentialResponse{
				SpiffeId: "spiffe://domain.test/internal",
				X509Svid: x509util.DERFromCertificates(minted.Certificates),
				Bundle:   bundle,
				Hint:     "internal",
			},
			expectEntryID: "id-internal",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := &credentialAcquisitionCalls{}
			params := testParams{
				CA:                         ca,
				Identities:                 tt.identities,
				EntriesAndBundlesUpdates:   []*cache.EntriesAndBundlesUpdate{{Bundle: ca.Bundle()}},
				CredentialAcquisitionErr:   tt.managerErr,
				EnrollResponse:             tt.serverResp,
				CredentialAcquisitionCalls: calls,
				ExpectLogs:                 tt.expectLogs,
			}
			runTest(t, params,
				func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
					resp, err := client.EnrollCredential(ctx, tt.req)
					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
					if tt.expectCode != codes.OK {
						assert.Nil(t, resp)
						return
					}
					spiretest.AssertProtoEqual(t, tt.expectResp, resp)
					require.Equal(t, []string{tt.expectEntryID}, calls.entryIDs)
					require.Len(t, calls.requests, 1)
					spiretest.AssertProtoEqual(t, &credentialacquisitionv1.EnrollCredentialRequest{
						Target:           tt.req.Target,
						CredentialType:   types.CredentialType_CREDENTIAL_TYPE_X509,
						CredentialHint:   tt.req.CredentialHint,
						FreshnessKind:    types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
						FreshnessElement: tt.req.FreshnessElement,
						Csr:              tt.req.Csr,
						Evidence:         tt.req.Evidence,
						EvidenceProfile:  tt.req.EvidenceProfile,
						Binding:          &types.EvidenceBinding{Method: "binding-input", Hash: "sha512"},
					}, calls.requests[0].(proto.Message))
				})
		})
	}
}

func TestRetrieveCredential(t *testing.T) {
	ca := testca.New(t, td)
	identities := credentialAcquisitionIdentities(ca)

	fullReq := &workloadPB.RetrieveCredentialRequest{
		Target:           "https://vault.example",
		CredentialType:   workloadPB.CredentialType_CREDENTIAL_TYPE_JWT,
		FreshnessKind:    workloadPB.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessElement: testHandle,
		CekPub:           []byte("cek_pub"),
		Evidence:         []byte("evidence"),
		Binding:          testBinding,
	}
	container := []byte(`{"container":"hpke-base"}`)

	for _, tt := range []struct {
		name       string
		identities []cache.X509Identity
		req        *workloadPB.RetrieveCredentialRequest
		serverResp *credentialacquisitionv1.RetrieveCredentialResponse
		managerErr error
		expectCode codes.Code
		expectMsg  string
		expectResp *workloadPB.RetrieveCredentialResponse
		expectLogs []spiretest.LogEntry
	}{
		{
			name:       "missing required CEKpub",
			identities: identities,
			req:        &workloadPB.RetrieveCredentialRequest{Target: fullReq.Target, Evidence: []byte("evidence"), Binding: testBinding},
			expectCode: codes.InvalidArgument,
			expectMsg:  "CEKpub must be specified",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Missing required CEKpub parameter",
					Data:    logrus.Fields{"service": "WorkloadAPI", "method": "RetrieveCredential"},
				},
			},
		},
		{
			name:       "Server refuses the Credential Type",
			identities: identities,
			req:        fullReq,
			managerErr: status.Error(codes.Unimplemented, "unsupported Credential Type"),
			expectCode: codes.Unimplemented,
			expectMsg:  "unsupported Credential Type",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Retrieve credential failed",
					Data: logrus.Fields{
						"service":       "WorkloadAPI",
						"method":        "RetrieveCredential",
						"spiffe_id":     "spiffe://domain.test/internal",
						"entry_id":      "id-internal",
						logrus.ErrorKey: "rpc error: code = Unimplemented desc = unsupported Credential Type",
					},
				},
			},
		},
		{
			name:       "Server returns no bundle",
			identities: identities,
			req:        fullReq,
			serverResp: &credentialacquisitionv1.RetrieveCredentialResponse{},
			expectCode: codes.Internal,
			expectMsg:  "the Server returned no credential bundle",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "The Server returned no credential bundle",
					Data: logrus.Fields{
						"service":   "WorkloadAPI",
						"method":    "RetrieveCredential",
						"spiffe_id": "spiffe://domain.test/internal",
						"entry_id":  "id-internal",
					},
				},
			},
		},
		{
			name:       "success",
			identities: identities,
			req:        fullReq,
			serverResp: &credentialacquisitionv1.RetrieveCredentialResponse{EncryptedCredentialBundle: container},
			expectResp: &workloadPB.RetrieveCredentialResponse{EncryptedCredentialBundle: container},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := &credentialAcquisitionCalls{}
			params := testParams{
				CA:                         ca,
				Identities:                 tt.identities,
				CredentialAcquisitionErr:   tt.managerErr,
				RetrieveResponse:           tt.serverResp,
				CredentialAcquisitionCalls: calls,
				ExpectLogs:                 tt.expectLogs,
			}
			runTest(t, params,
				func(ctx context.Context, client workloadPB.SpiffeWorkloadAPIClient) {
					resp, err := client.RetrieveCredential(ctx, tt.req)
					spiretest.RequireGRPCStatus(t, err, tt.expectCode, tt.expectMsg)
					if tt.expectCode != codes.OK {
						assert.Nil(t, resp)
						return
					}
					spiretest.AssertProtoEqual(t, tt.expectResp, resp)
					require.Equal(t, []string{"id-internal"}, calls.entryIDs)
					require.Len(t, calls.requests, 1)
					spiretest.AssertProtoEqual(t, &credentialacquisitionv1.RetrieveCredentialRequest{
						Target:           tt.req.Target,
						CredentialType:   types.CredentialType_CREDENTIAL_TYPE_JWT,
						FreshnessKind:    types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
						FreshnessElement: tt.req.FreshnessElement,
						CekPub:           tt.req.CekPub,
						Evidence:         tt.req.Evidence,
						Binding:          &types.EvidenceBinding{Method: "binding-input", Hash: "sha512"},
					}, calls.requests[0].(proto.Message))
				})
		})
	}
}

// TestCredentialAcquisitionEnumsMatch guards the casts between the enums of
// the Workload API and those of the Server API: the handler converts one into
// the other by value, so the two must name the same values.
func TestCredentialAcquisitionEnumsMatch(t *testing.T) {
	assert.Equal(t, workloadPB.FreshnessKind_name, types.FreshnessKind_name)
	assert.Equal(t, workloadPB.CredentialAcquisitionMode_name, types.CredentialAcquisitionMode_name)
	assert.Equal(t, workloadPB.CredentialType_name, types.CredentialType_name)
}

var _ = common.RegistrationEntry{}
