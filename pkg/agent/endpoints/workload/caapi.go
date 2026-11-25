package workload

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"slices"

	"github.com/TWI-Unified-Model/tacra/constants"
	"github.com/TWI-Unified-Model/tacra/container"
	caapiv1 "github.com/TWI-Unified-Model/tacra/gen/go/caapi/v1"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// CAAPI serves the Credential Acquisition API of draft-novak-rats-tacra
// (TACRA) as its gRPC service defines it, caapi.v1.CredentialAcquisitionService
// of github.com/TWI-Unified-Model/tacra, on the Workload API endpoint of the
// Agent. A Workload that uses the Credential Acquisition Interface of TACRA
// reaches the Agent with it, as it reaches any other Credential Acquisition
// System Client. Each call is the call of the same name of the Workload API,
// with the messages of CAAPI: the Agent attests the caller, picks its
// registration entry and forwards the call to the Server in the same way.
type CAAPI struct {
	caapiv1.UnimplementedCredentialAcquisitionServiceServer

	handler *Handler
}

// NewCAAPI serves CAAPI with the Workload API handler of the Agent.
func NewCAAPI(handler *Handler) *CAAPI {
	return &CAAPI{handler: handler}
}

// cskECDSAP256 is the name, among the acceptable CSK algorithms of an
// initiation, of the one CSK algorithm that CAAPI and the Server share.
const cskECDSAP256 = "ecdsa-p256-sha256"

var caapiCredentialTypes = map[caapiv1.CredentialType]workload.CredentialType{
	caapiv1.CredentialType_CREDENTIAL_TYPE_X509:    workload.CredentialType_CREDENTIAL_TYPE_X509,
	caapiv1.CredentialType_CREDENTIAL_TYPE_WIC:     workload.CredentialType_CREDENTIAL_TYPE_WIC,
	caapiv1.CredentialType_CREDENTIAL_TYPE_WIT:     workload.CredentialType_CREDENTIAL_TYPE_WIT,
	caapiv1.CredentialType_CREDENTIAL_TYPE_JWT:     workload.CredentialType_CREDENTIAL_TYPE_JWT,
	caapiv1.CredentialType_CREDENTIAL_TYPE_API_KEY: workload.CredentialType_CREDENTIAL_TYPE_API_KEY,
	caapiv1.CredentialType_CREDENTIAL_TYPE_PSK:     workload.CredentialType_CREDENTIAL_TYPE_PSK,
}

func caapiCredentialType(t caapiv1.CredentialType) (workload.CredentialType, error) {
	credentialType, ok := caapiCredentialTypes[t]
	if !ok {
		return 0, status.Errorf(codes.InvalidArgument, "Credential Type %v is not defined by TACRA", t)
	}
	return credentialType, nil
}

// InitiateRemoteAttestation is Initiate-Credential-Acquisition.
func (c *CAAPI) InitiateRemoteAttestation(ctx context.Context, req *caapiv1.InitiateCredentialAcquistionRequest) (*caapiv1.InitiateCredentialAcquisitionResponse, error) {
	credentialType, err := caapiCredentialType(req.GetCredentialType())
	if err != nil {
		return nil, err
	}
	resp, err := c.handler.InitiateCredentialAcquisition(ctx, &workload.InitiateCredentialAcquisitionRequest{
		Target:         req.GetTarget(),
		CredentialType: credentialType,
		CredentialHint: req.GetCredentialHint(),
	})
	if err != nil {
		return nil, err
	}
	out := &caapiv1.InitiateCredentialAcquisitionResponse{
		// The modes and the Freshness Kinds have the same values in both APIs.
		Mode:          caapiv1.CredentialAcquisitionMode(resp.Mode),
		FreshnessKind: caapiv1.FreshnessKind(resp.FreshnessKind),
	}
	if len(resp.FreshnessHandle) > 0 {
		out.FreshnessHandle = resp.FreshnessHandle
	}
	switch resp.Mode {
	case workload.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_ENROLL:
		if slices.Contains(resp.AcceptableCsk, cskECDSAP256) {
			out.SigningAlgorithm = caapiv1.SigningAlgorithm_SIGNING_ALGORITHM_ECDSA_P256.Enum()
		}
	case workload.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_RETRIEVE:
		// The hybrid suite of the container first, when the Server accepts it.
		switch {
		case slices.Contains(resp.AcceptableCek, container.AcceptableMLKEM768P256):
			out.EncryptionAlgorithm = caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_MLKEM768_P256.Enum()
		case slices.Contains(resp.AcceptableCek, container.AcceptableDHKEMP256):
			out.EncryptionAlgorithm = caapiv1.EncryptionAlgorithm_ENCRYPTION_ALGORITHM_ECDH_P256.Enum()
		}
	}
	return out, nil
}

// EnrollCredential is Enroll-Credential. The credential returned is the
// X509-SVID with its chain, as a PEM certificate bundle, leaf first.
func (c *CAAPI) EnrollCredential(ctx context.Context, req *caapiv1.EnrollCredentialRequest) (*caapiv1.EnrollCredentialResponse, error) {
	credentialType, err := caapiCredentialType(req.GetCredentialType())
	if err != nil {
		return nil, err
	}
	resp, err := c.handler.EnrollCredential(ctx, &workload.EnrollCredentialRequest{
		Target:           req.GetTarget(),
		CredentialType:   credentialType,
		CredentialHint:   req.GetCredentialHint(),
		FreshnessKind:    workload.FreshnessKind(req.GetFreshnessKind()),
		FreshnessElement: req.GetFreshnessElement(),
		Csr:              req.GetCsr(),
		Evidence:         req.GetEvidence(),
		EvidenceProfile:  req.GetEvidenceProfile(),
		Binding:          &workload.EvidenceBinding{Method: constants.BindingMethod, Hash: constants.BindingHash},
	})
	if err != nil {
		return nil, err
	}
	chain, err := x509.ParseCertificates(resp.X509Svid)
	if err != nil || len(chain) == 0 {
		return nil, status.Error(codes.Internal, "the Server returned an X509-SVID that is not a certificate chain")
	}
	var bundle []byte
	for _, certificate := range chain {
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})...)
	}
	return &caapiv1.EnrollCredentialResponse{PlaintextCredential: bundle}, nil
}

// RetrieveCredential is Retrieve-Credential. The container goes back to the
// Workload as the Server answered it.
func (c *CAAPI) RetrieveCredential(ctx context.Context, req *caapiv1.RetrieveCredentialRequest) (*caapiv1.RetrieveCredentialResponse, error) {
	credentialType, err := caapiCredentialType(req.GetCredentialType())
	if err != nil {
		return nil, err
	}
	resp, err := c.handler.RetrieveCredential(ctx, &workload.RetrieveCredentialRequest{
		Target:           req.GetTarget(),
		CredentialType:   credentialType,
		CredentialHint:   req.GetCredentialHint(),
		FreshnessKind:    workload.FreshnessKind(req.GetFreshnessKind()),
		FreshnessElement: req.GetFreshnessElement(),
		CekPub:           req.GetCekPub(),
		Evidence:         req.GetEvidence(),
		EvidenceProfile:  req.GetEvidenceProfile(),
		Binding:          &workload.EvidenceBinding{Method: constants.BindingMethod, Hash: constants.BindingHash},
	})
	if err != nil {
		return nil, err
	}
	return &caapiv1.RetrieveCredentialResponse{WrappedCredential: resp.EncryptedCredentialBundle}, nil
}
