package credentialacquisition

import (
	"context"
	"encoding/hex"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	credentialacquisitionv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/credentialacquisition/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	commonapi "github.com/spiffe/spire/pkg/common/api"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/pkg/common/x509util"
	"github.com/spiffe/spire/pkg/server/api"
	"github.com/spiffe/spire/pkg/server/api/rpccontext"
	"github.com/spiffe/spire/pkg/server/ca"
	"github.com/spiffe/spire/pkg/server/credentialacquisition"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegisterService registers the service on the gRPC server.
func RegisterService(s grpc.ServiceRegistrar, service *Service) {
	credentialacquisitionv1.RegisterCredentialAcquisitionServer(s, service)
}

// Acquirer is the Credential Acquisition System Server behind the service.
type Acquirer interface {
	Initiate(ctx context.Context, in credentialacquisition.Initiation) (*credentialacquisition.InitiationResult, error)
	Enroll(ctx context.Context, in credentialacquisition.Enrollment) (*credentialacquisition.EnrollmentResult, error)
	Retrieve(ctx context.Context, in credentialacquisition.Retrieval) ([]byte, error)
}

// Config is the service configuration.
type Config struct {
	Acquirer     Acquirer
	EntryFetcher api.AuthorizedEntryFetcher
	ServerCA     ca.ServerCA
	TrustDomain  spiffeid.TrustDomain
}

// New creates a new CredentialAcquisition service.
func New(config Config) *Service {
	return &Service{
		acquirer: config.Acquirer,
		ef:       config.EntryFetcher,
		ca:       config.ServerCA,
		td:       config.TrustDomain,
	}
}

// Service implements the v1 CredentialAcquisition service: the Credential
// Acquisition System Server of TACRA. The caller is an agent; every call
// names the registration entry of the workload the agent attested, which
// the agent must be authorized for.
type Service struct {
	credentialacquisitionv1.UnsafeCredentialAcquisitionServer

	acquirer Acquirer
	ef       api.AuthorizedEntryFetcher
	ca       ca.ServerCA
	td       spiffeid.TrustDomain
}

// InitiateCredentialAcquisition issues the Freshness Handle of an exchange.
func (s *Service) InitiateCredentialAcquisition(ctx context.Context, req *credentialacquisitionv1.InitiateCredentialAcquisitionRequest) (*credentialacquisitionv1.InitiateCredentialAcquisitionResponse, error) {
	log := rpccontext.Logger(ctx)
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{
		telemetry.RegistrationID: req.EntryId,
		"target":                 req.Target,
		"credential_type":        credentialTypeToken(req.CredentialType),
	})

	entry, agentID, err := s.authorizedEntry(ctx, log, req.EntryId)
	if err != nil {
		return nil, err
	}
	log = log.WithField(telemetry.SPIFFEID, entry.GetSpiffeId().String())

	result, err := s.acquirer.Initiate(ctx, credentialacquisition.Initiation{
		EntryID:        req.EntryId,
		AgentID:        agentID.String(),
		Target:         req.Target,
		CredentialType: credentialTypeToken(req.CredentialType),
		CredentialHint: req.CredentialHint,
	})
	if err != nil {
		return nil, commonapi.MakeErr(log, status.Code(err), "failed to initiate credential acquisition", err)
	}
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{
		"mode":           result.Mode,
		"freshness_kind": result.FreshnessKind,
	})
	rpccontext.AuditRPC(ctx)

	return &credentialacquisitionv1.InitiateCredentialAcquisitionResponse{
		Mode:               modeFromToken(result.Mode),
		FreshnessKind:      freshnessKindFromToken(result.FreshnessKind),
		FreshnessHandle:    result.Handle,
		ExpiresIn:          result.ExpiresIn,
		MaxAge:             result.MaxAge,
		AcceptableCsk:      result.AcceptableCSK,
		AcceptableCek:      result.AcceptableCEK,
		AcceptableEvidence: result.AcceptableEvidence,
	}, nil
}

// EnrollCredential mints an X509-SVID for the registration entry, for the
// key of the CSR the Evidence is bound to.
func (s *Service) EnrollCredential(ctx context.Context, req *credentialacquisitionv1.EnrollCredentialRequest) (*credentialacquisitionv1.EnrollCredentialResponse, error) {
	log := rpccontext.Logger(ctx)
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{
		telemetry.RegistrationID: req.EntryId,
		telemetry.Csr:            api.HashByte(req.Csr),
		"target":                 req.Target,
		"credential_type":        credentialTypeToken(req.CredentialType),
		"freshness_kind":         freshnessKindToken(req.FreshnessKind),
	})

	switch {
	case len(req.Csr) == 0:
		return nil, commonapi.MakeErr(log, codes.InvalidArgument, "missing CSR", nil)
	case len(req.Evidence) == 0:
		return nil, commonapi.MakeErr(log, codes.InvalidArgument, "missing evidence", nil)
	case req.Binding == nil:
		return nil, commonapi.MakeErr(log, codes.InvalidArgument, "missing binding", nil)
	}

	if err := rpccontext.RateLimit(ctx, 1); err != nil {
		return nil, commonapi.MakeErr(log, status.Code(err), "rejecting request due to certificate signing rate limiting", err)
	}

	entry, agentID, err := s.authorizedEntry(ctx, log, req.EntryId)
	if err != nil {
		return nil, err
	}
	spiffeID, err := api.TrustDomainMemberIDFromProto(ctx, s.td, entry.GetSpiffeId())
	if err != nil {
		return nil, commonapi.MakeErr(log, codes.Internal, "entry has malformed SPIFFE ID", err)
	}
	log = log.WithField(telemetry.SPIFFEID, spiffeID.String())

	result, err := s.acquirer.Enroll(ctx, credentialacquisition.Enrollment{
		EntryID:          req.EntryId,
		AgentID:          agentID.String(),
		Target:           req.Target,
		CredentialType:   credentialTypeToken(req.CredentialType),
		CredentialHint:   req.CredentialHint,
		FreshnessKind:    freshnessKindToken(req.FreshnessKind),
		FreshnessElement: req.FreshnessElement,
		CSR:              req.Csr,
		Evidence:         req.Evidence,
		EvidenceProfile:  req.EvidenceProfile,
		BindingMethod:    req.Binding.Method,
		BindingHash:      req.Binding.Hash,
	})
	if err != nil {
		return nil, commonapi.MakeErr(log, status.Code(err), "failed to enroll credential", err)
	}

	x509Svid, err := s.ca.SignWorkloadX509SVID(ctx, ca.WorkloadX509SVIDParams{
		SPIFFEID:  spiffeID,
		PublicKey: result.CSR.PublicKey,
		DNSNames:  entry.GetDnsNames(),
		TTL:       time.Duration(entry.GetX509SvidTtl()) * time.Second,
	})
	if err != nil {
		return nil, commonapi.MakeErr(log, codes.Internal, "failed to sign X509-SVID", err)
	}

	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{
		telemetry.SPIFFEID:  spiffeID.String(),
		telemetry.ExpiresAt: x509Svid[0].NotAfter.Unix(),
		"verifier":          result.Verifier,
		"submod":            result.Submod,
		"measurement":       hex.EncodeToString(result.Measurement),
		"waived":            strings.Join(result.Waived, "; "),
	})
	rpccontext.AuditRPC(ctx)
	log.WithFields(logrus.Fields{
		telemetry.Expiration:   x509Svid[0].NotAfter.Format(time.RFC3339),
		telemetry.SerialNumber: x509Svid[0].SerialNumber.String(),
		"verifier":             result.Verifier,
		"measurement":          hex.EncodeToString(result.Measurement),
	}).Info("Enrolled an attested X509-SVID")

	return &credentialacquisitionv1.EnrollCredentialResponse{
		Svid: &types.X509SVID{
			Id:        entry.GetSpiffeId(),
			CertChain: x509util.RawCertsFromCertificates(x509Svid),
			ExpiresAt: x509Svid[0].NotAfter.Unix(),
		},
	}, nil
}

// RetrieveCredential forwards the request to the Secret Vault and returns
// the credential it released, sealed to the workload's key.
func (s *Service) RetrieveCredential(ctx context.Context, req *credentialacquisitionv1.RetrieveCredentialRequest) (*credentialacquisitionv1.RetrieveCredentialResponse, error) {
	log := rpccontext.Logger(ctx)
	rpccontext.AddRPCAuditFields(ctx, logrus.Fields{
		telemetry.RegistrationID: req.EntryId,
		"target":                 req.Target,
		"credential_type":        credentialTypeToken(req.CredentialType),
		"freshness_kind":         freshnessKindToken(req.FreshnessKind),
	})

	switch {
	case len(req.CekPub) == 0:
		return nil, commonapi.MakeErr(log, codes.InvalidArgument, "missing cek_pub", nil)
	case len(req.Evidence) == 0:
		return nil, commonapi.MakeErr(log, codes.InvalidArgument, "missing evidence", nil)
	case req.Binding == nil:
		return nil, commonapi.MakeErr(log, codes.InvalidArgument, "missing binding", nil)
	}

	entry, agentID, err := s.authorizedEntry(ctx, log, req.EntryId)
	if err != nil {
		return nil, err
	}
	log = log.WithField(telemetry.SPIFFEID, entry.GetSpiffeId().String())

	container, err := s.acquirer.Retrieve(ctx, credentialacquisition.Retrieval{
		EntryID:          req.EntryId,
		AgentID:          agentID.String(),
		Target:           req.Target,
		CredentialType:   credentialTypeToken(req.CredentialType),
		CredentialHint:   req.CredentialHint,
		FreshnessKind:    freshnessKindToken(req.FreshnessKind),
		FreshnessElement: req.FreshnessElement,
		CEKPub:           req.CekPub,
		Evidence:         req.Evidence,
		EvidenceProfile:  req.EvidenceProfile,
		BindingMethod:    req.Binding.Method,
		BindingHash:      req.Binding.Hash,
	})
	if err != nil {
		return nil, commonapi.MakeErr(log, status.Code(err), "failed to retrieve credential", err)
	}
	rpccontext.AuditRPC(ctx)
	log.Info("Retrieved an attested credential bundle")

	return &credentialacquisitionv1.RetrieveCredentialResponse{EncryptedCredentialBundle: container}, nil
}

// authorizedEntry fetches the registration entry the agent names, which the
// calling agent must be authorized for.
func (s *Service) authorizedEntry(ctx context.Context, log logrus.FieldLogger, entryID string) (api.ReadOnlyEntry, spiffeid.ID, error) {
	if entryID == "" {
		return api.ReadOnlyEntry{}, spiffeid.ID{}, commonapi.MakeErr(log, codes.InvalidArgument, "missing entry ID", nil)
	}
	callerID, ok := rpccontext.CallerID(ctx)
	if !ok {
		return api.ReadOnlyEntry{}, spiffeid.ID{}, commonapi.MakeErr(log, codes.Internal, "caller ID missing from request context", nil)
	}
	entries, err := s.ef.LookupAuthorizedEntries(ctx, callerID, map[string]struct{}{entryID: {}})
	if err != nil {
		return api.ReadOnlyEntry{}, spiffeid.ID{}, commonapi.MakeErr(log, codes.Internal, "failed to fetch authorized entries", err)
	}
	entry, ok := entries[entryID]
	if !ok {
		return api.ReadOnlyEntry{}, spiffeid.ID{}, commonapi.MakeErr(log.WithField(telemetry.RegistrationID, entryID), codes.NotFound, "entry not found or not authorized", nil)
	}
	return entry, callerID, nil
}

// The TACRA tokens of the enums of the server API.

func credentialTypeToken(t types.CredentialType) string {
	switch t {
	case types.CredentialType_CREDENTIAL_TYPE_X509:
		return "x509"
	case types.CredentialType_CREDENTIAL_TYPE_WIC:
		return "wic"
	case types.CredentialType_CREDENTIAL_TYPE_WIT:
		return "wit"
	case types.CredentialType_CREDENTIAL_TYPE_JWT:
		return "jwt"
	case types.CredentialType_CREDENTIAL_TYPE_API_KEY:
		return "api-key"
	case types.CredentialType_CREDENTIAL_TYPE_PSK:
		return "psk"
	case types.CredentialType_CREDENTIAL_TYPE_PRIVATE_KEY:
		return "private-key"
	default:
		return ""
	}
}

func freshnessKindToken(k types.FreshnessKind) string {
	switch k {
	case types.FreshnessKind_FRESHNESS_KIND_ABSENT_NONE:
		return credentialacquisition.FreshnessAbsentNone
	case types.FreshnessKind_FRESHNESS_KIND_ABSENT_TIMESTAMP:
		return credentialacquisition.FreshnessAbsentTimestamp
	case types.FreshnessKind_FRESHNESS_KIND_ABSENT_EPOCH:
		return credentialacquisition.FreshnessAbsentEpoch
	case types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE:
		return credentialacquisition.FreshnessPresentNonce
	case types.FreshnessKind_FRESHNESS_KIND_PRESENT_EPOCH:
		return credentialacquisition.FreshnessPresentEpoch
	default:
		return ""
	}
}

func freshnessKindFromToken(k string) types.FreshnessKind {
	switch k {
	case credentialacquisition.FreshnessAbsentNone:
		return types.FreshnessKind_FRESHNESS_KIND_ABSENT_NONE
	case credentialacquisition.FreshnessAbsentTimestamp:
		return types.FreshnessKind_FRESHNESS_KIND_ABSENT_TIMESTAMP
	case credentialacquisition.FreshnessAbsentEpoch:
		return types.FreshnessKind_FRESHNESS_KIND_ABSENT_EPOCH
	case credentialacquisition.FreshnessPresentNonce:
		return types.FreshnessKind_FRESHNESS_KIND_PRESENT_NONCE
	case credentialacquisition.FreshnessPresentEpoch:
		return types.FreshnessKind_FRESHNESS_KIND_PRESENT_EPOCH
	default:
		return types.FreshnessKind_FRESHNESS_KIND_UNSPECIFIED
	}
}

func modeFromToken(m string) types.CredentialAcquisitionMode {
	switch m {
	case credentialacquisition.ModeEnroll:
		return types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_ENROLL
	case credentialacquisition.ModeRetrieve:
		return types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_RETRIEVE
	default:
		return types.CredentialAcquisitionMode_CREDENTIAL_ACQUISITION_MODE_UNSPECIFIED
	}
}
