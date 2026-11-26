package workload_test

import (
	"context"
	"encoding/pem"
	"testing"

	"github.com/TWI-Unified-Model/tacra/container"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/sirupsen/logrus"
	workloadPB "github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	credentialacquisitionv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/credentialacquisition/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/manager/cache"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/test/spiretest"
	"github.com/spiffe/spire/test/testca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// The three calls of CAAPI are the calls of the same name of the Workload
// API with the messages of CAAPI. These tests cover what CAAPI adds: the
// translation of the messages in both directions. What the Workload API does
// with a call is covered by the tests of its handler.

func TestCAAPIInitiateRemoteAttestation(t *testing.T) {
	ca := testca.New(t, td)
	identities := credentialAcquisitionIdentities(ca)

	for _, tt := range []struct {
		name           string
		req            *caapiv1.InitiateCredentialAcquistionRequest
		serverResp     *credentialacquisitionv1.InitiateCredentialAcquisitionResponse
		managerErr     error
		expectCode     codes.Code
		expectMsg      string
		expectResp     *caapiv1.InitiateCredentialAcquisitionResponse
		expectEntryID  string
		expectForwards *credentialacquisitionv1.InitiateCredentialAcquisitionRequest
		expectLogs     []spiretest.LogEntry
	}{
		{
			name:       "a Credential Type that TACRA does not define",
			req:        &caapiv1.InitiateCredentialAcquistionRequest{Target: td.IDString(), CredentialType: caapiv1.CredentialType(99)},
			expectCode: codes.InvalidArgument,
			expectMsg:  "Credential Type 99 is not defined by TACRA",
		},
		{
			name:       "the refusal of the Server reaches the Workload as it is",
			req:        &caapiv1.InitiateCredentialAcquistionRequest{Target: "https://other.example", CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509},
			managerErr: status.Error(codes.PermissionDenied, "unsupported Target"),
			expectCode: codes.PermissionDenied,
			expectMsg:  "unsupported Target",
			expectLogs: []spiretest.LogEntry{
				{
					Level:   logrus.ErrorLevel,
					Message: "Initiate credential acquisition failed",
					Data: logrus.Fields{
						// The log names the API that the Workload called.
						"service":       "caapi.v1.CredentialAcquisitionService",
						"method":        "InitiateRemoteAttestation",
						"spiffe_id":     "spiffe://domain.test/internal",
						"entry_id":      "id-internal",
						logrus.ErrorKey: "rpc error: code = PermissionDenied desc = unsupported Target",
					},
				},
			},
		},
		{
			name: "enroll: the CSK algorithm that CAAPI and the Server share",
			req:  &caapiv1.InitiateCredentialAcquistionRequest{Target: td.IDString(), CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509, CredentialHint: "external"},
			serverResp: &credentialacquisitionv1.InitiateCredentialAcquisitionResponse{
				Mode:            types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_ENROLL,
				FreshnessKind:   types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessHandle: testHandle,
				ExpiresIn:       300,
				AcceptableCsk:   []string{"ecdsa-p256-sha256"},
			},
			expectResp: &caapiv1.InitiateCredentialAcquisitionResponse{
				Mode:             caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL,
				FreshnessKind:    caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessHandle:  testHandle,
				SigningAlgorithm: caapiv1.SigningAlgorithm_SIGNING_ALGORITHM_ECDSA_P256.Enum(),
			},
			expectEntryID: "id-external",
			expectForwards: &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
				Target:         td.IDString(),
				CredentialType: types.CredentialType_CREDENTIAL_TYPE_X509,
				CredentialHint: "external",
			},
		},
		{
			name: "enroll: no CSK algorithm that CAAPI knows",
			req:  &caapiv1.InitiateCredentialAcquistionRequest{Target: td.IDString(), CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_X509},
			serverResp: &credentialacquisitionv1.InitiateCredentialAcquisitionResponse{
				Mode:          types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_ENROLL,
				FreshnessKind: types.FreshnessKind_FRESHNESS_KIND_ABSENT_EPOCH,
				AcceptableCsk: []string{"another-algorithm"},
			},
			expectResp: &caapiv1.InitiateCredentialAcquisitionResponse{
				Mode:          caapiv1.CredentialAcquisitionMode_ACQUISITION_ENROLL,
				FreshnessKind: caapiv1.FreshnessKind_FRESHNESS_KIND_ABSENT_EPOCH,
			},
			expectEntryID: "id-internal",
			expectForwards: &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
				Target:         td.IDString(),
				CredentialType: types.CredentialType_CREDENTIAL_TYPE_X509,
			},
		},
		{
			name: "retrieve: the hybrid suite of the container first",
			req:  &caapiv1.InitiateCredentialAcquistionRequest{Target: "https://vault.example", CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_JWT},
			serverResp: &credentialacquisitionv1.InitiateCredentialAcquisitionResponse{
				Mode:            types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_RETRIEVE,
				FreshnessKind:   types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessHandle: testHandle,
				AcceptableCek:   []string{container.AcceptableDHKEMP256, container.AcceptableMLKEM768P256},
			},
			expectResp: &caapiv1.InitiateCredentialAcquisitionResponse{
				Mode:                caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE,
				FreshnessKind:       caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessHandle:     testHandle,
				EncryptionAlgorithm: caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_MLKEM768_P256.Enum(),
			},
			expectEntryID: "id-internal",
			expectForwards: &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
				Target:         "https://vault.example",
				CredentialType: types.CredentialType_CREDENTIAL_TYPE_JWT,
			},
		},
		{
			name: "retrieve: the suite of P-256 when the Server accepts no other",
			req:  &caapiv1.InitiateCredentialAcquistionRequest{Target: "https://vault.example", CredentialType: caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY},
			serverResp: &credentialacquisitionv1.InitiateCredentialAcquisitionResponse{
				Mode:            types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_RETRIEVE,
				FreshnessKind:   types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessHandle: testHandle,
				AcceptableCek:   []string{container.AcceptableDHKEMP256},
			},
			expectResp: &caapiv1.InitiateCredentialAcquisitionResponse{
				Mode:                caapiv1.CredentialAcquisitionMode_ACQUISITION_RETRIEVE,
				FreshnessKind:       caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessHandle:     testHandle,
				EncryptionAlgorithm: caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_ECDH_P256.Enum(),
			},
			expectEntryID: "id-internal",
			expectForwards: &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
				Target:         "https://vault.example",
				CredentialType: types.CredentialType_CREDENTIAL_TYPE_API_KEY,
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := &credentialAcquisitionCalls{}
			params := testParams{
				CA:                         ca,
				Identities:                 identities,
				CredentialAcquisitionErr:   tt.managerErr,
				InitiateResponse:           tt.serverResp,
				CredentialAcquisitionCalls: calls,
				ExpectLogs:                 tt.expectLogs,
			}
			runTestOverConn(t, params, func(ctx context.Context, conn grpc.ClientConnInterface) {
				resp, err := caapiv1.NewCredentialAcquisitionServiceClient(conn).InitiateRemoteAttestation(ctx, tt.req)
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

func TestCAAPIEnrollCredential(t *testing.T) {
	ca := testca.New(t, td)
	identities := credentialAcquisitionIdentities(ca)
	minted := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/internal"))

	req := &caapiv1.EnrollCredentialRequest{
		Target:           td.IDString(),
		CredentialType:   caapiv1.CredentialType_CREDENTIAL_TYPE_X509,
		CredentialHint:   new("internal"),
		FreshnessKind:    caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessElement: testHandle,
		Csr:              []byte("csr"),
		Evidence:         []byte("evidence"),
		EvidenceProfile:  new("application/psa-attestation-token"),
	}

	t.Run("a Credential Type that TACRA does not define", func(t *testing.T) {
		runTestOverConn(t, testParams{CA: ca, Identities: identities}, func(ctx context.Context, conn grpc.ClientConnInterface) {
			resp, err := caapiv1.NewCredentialAcquisitionServiceClient(conn).EnrollCredential(ctx, &caapiv1.EnrollCredentialRequest{Target: td.IDString(), CredentialType: caapiv1.CredentialType(99)})
			spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "Credential Type 99 is not defined by TACRA")
			assert.Nil(t, resp)
		})
	})

	t.Run("the X509-SVID goes to the Workload as a PEM bundle, leaf first", func(t *testing.T) {
		calls := &credentialAcquisitionCalls{}
		params := testParams{
			CA:                       ca,
			Identities:               identities,
			EntriesAndBundlesUpdates: []*cache.EntriesAndBundlesUpdate{{Bundle: ca.Bundle()}},
			EnrollResponse: &credentialacquisitionv1.EnrollCredentialResponse{
				Svid: &types.X509SVID{
					Id:        &types.SPIFFEID{TrustDomain: td.Name(), Path: "/internal"},
					CertChain: x509util.RawCertsFromCertificates(minted.Certificates),
					ExpiresAt: minted.Certificates[0].NotAfter.Unix(),
				},
			},
			CredentialAcquisitionCalls: calls,
		}
		runTestOverConn(t, params, func(ctx context.Context, conn grpc.ClientConnInterface) {
			resp, err := caapiv1.NewCredentialAcquisitionServiceClient(conn).EnrollCredential(ctx, req)
			require.NoError(t, err)

			var expected []byte
			for _, certificate := range minted.Certificates {
				expected = append(expected, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
			}
			require.NotEmpty(t, expected)
			assert.Equal(t, string(expected), string(resp.GetPlaintextCredential()))

			// The binding that CAAPI names is the one binding of TACRA.
			require.Equal(t, []string{"id-internal"}, calls.entryIDs)
			require.Len(t, calls.requests, 1)
			spiretest.AssertProtoEqual(t, &credentialacquisitionv1.EnrollCredentialRequest{
				Target:           req.Target,
				CredentialType:   types.CredentialType_CREDENTIAL_TYPE_X509,
				CredentialHint:   req.GetCredentialHint(),
				FreshnessKind:    types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessElement: req.FreshnessElement,
				Csr:              req.Csr,
				Evidence:         req.Evidence,
				EvidenceProfile:  req.GetEvidenceProfile(),
				Binding:          &types.EvidenceBinding{Method: "binding-input", Hash: "sha512"},
			}, calls.requests[0].(proto.Message))
		})
	})
}

func TestCAAPIRetrieveCredential(t *testing.T) {
	ca := testca.New(t, td)
	identities := credentialAcquisitionIdentities(ca)
	sealed := []byte(`{"container":"hpke-base"}`)

	req := &caapiv1.RetrieveCredentialRequest{
		Target:           "https://vault.example",
		CredentialType:   caapiv1.CredentialType_CREDENTIAL_TYPE_JWT,
		FreshnessKind:    caapiv1.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
		FreshnessElement: testHandle,
		CekPub:           []byte("cek_pub"),
		Evidence:         []byte("evidence"),
		EvidenceProfile:  new("application/psa-attestation-token"),
	}

	t.Run("a Credential Type that TACRA does not define", func(t *testing.T) {
		runTestOverConn(t, testParams{CA: ca, Identities: identities}, func(ctx context.Context, conn grpc.ClientConnInterface) {
			resp, err := caapiv1.NewCredentialAcquisitionServiceClient(conn).RetrieveCredential(ctx, &caapiv1.RetrieveCredentialRequest{Target: "https://vault.example", CredentialType: caapiv1.CredentialType(99)})
			spiretest.RequireGRPCStatus(t, err, codes.InvalidArgument, "Credential Type 99 is not defined by TACRA")
			assert.Nil(t, resp)
		})
	})

	t.Run("the container goes to the Workload as the Server answered it", func(t *testing.T) {
		calls := &credentialAcquisitionCalls{}
		params := testParams{
			CA:                         ca,
			Identities:                 identities,
			RetrieveResponse:           &credentialacquisitionv1.RetrieveCredentialResponse{EncryptedCredentialBundle: sealed},
			CredentialAcquisitionCalls: calls,
		}
		runTestOverConn(t, params, func(ctx context.Context, conn grpc.ClientConnInterface) {
			resp, err := caapiv1.NewCredentialAcquisitionServiceClient(conn).RetrieveCredential(ctx, req)
			require.NoError(t, err)
			assert.Equal(t, sealed, resp.GetWrappedCredential())

			require.Equal(t, []string{"id-internal"}, calls.entryIDs)
			require.Len(t, calls.requests, 1)
			spiretest.AssertProtoEqual(t, &credentialacquisitionv1.RetrieveCredentialRequest{
				Target:           req.Target,
				CredentialType:   types.CredentialType_CREDENTIAL_TYPE_JWT,
				FreshnessKind:    types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE,
				FreshnessElement: req.FreshnessElement,
				CekPub:           req.CekPub,
				Evidence:         req.Evidence,
				EvidenceProfile:  req.GetEvidenceProfile(),
				Binding:          &types.EvidenceBinding{Method: "binding-input", Hash: "sha512"},
			}, calls.requests[0].(proto.Message))
		})
	})
}

// TestCAAPIEnumsMatch guards the casts between the enums of CAAPI and those
// of the Workload API: CAAPI converts the Freshness Kinds and the modes by
// value, so the two must give the same value the same meaning.
func TestCAAPIEnumsMatch(t *testing.T) {
	assert.Equal(t, workloadPB.FreshnessKind_name, caapiv1.FreshnessKind_name)
	for value, name := range caapiv1.CredentialAcquisitionMode_name {
		assert.Equal(t, "CREDENTIAL_"+name[:len("ACQUISITION")]+"_MODE"+name[len("ACQUISITION"):], workloadPB.CredentialAcquisitionMode_name[value])
	}
	assert.Len(t, workloadPB.CredentialAcquisitionMode_name, len(caapiv1.CredentialAcquisitionMode_name))
}
