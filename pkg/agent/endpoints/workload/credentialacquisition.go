package workload

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	credentialacquisitionv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/credentialacquisition/v1"
	"github.com/spiffe/spire-api-sdk/proto/spire/api/types"
	"github.com/spiffe/spire/pkg/agent/api/rpccontext"
	"github.com/spiffe/spire/pkg/agent/common/hintsfilter"
	"github.com/spiffe/spire/pkg/common/idutil"
	"github.com/spiffe/spire/pkg/common/telemetry"
	"github.com/spiffe/spire/proto/spire/common"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The attested credential acquisition calls of the Workload API, the
// Credential Acquisition API of draft-novak-rats-tacra (TACRA). The Agent is
// the Credential Acquisition System Client: it attests the calling Workload
// as it does for FetchX509SVID, picks the registration entry whose identity
// the Workload acquires, and forwards the call to the Server, which issues
// the Freshness Handle, appraises the Evidence, and mints or releases the
// credential. The Workload generates its key and its Evidence; the Agent
// never sees the private key.

// InitiateCredentialAcquisition processes Initiate-Credential-Acquisition for
// a Target.
func (h *Handler) InitiateCredentialAcquisition(ctx context.Context, req *workload.InitiateCredentialAcquisitionRequest) (*workload.InitiateCredentialAcquisitionResponse, error) {
	start := time.Now()
	log := rpccontext.Logger(ctx)
	if req.Target == "" {
		log.Error("Missing required target parameter")
		return nil, status.Error(codes.InvalidArgument, "target must be specified")
	}

	entry, _, err := h.credentialAcquisitionEntry(ctx, log, start, MethodInitiateCredentialAcquisition, req.CredentialHint)
	if err != nil {
		return nil, err
	}
	log = entryLogger(log, entry)

	resp, err := h.c.Manager.InitiateCredentialAcquisition(ctx, entry, &credentialacquisitionv1.InitiateCredentialAcquisitionRequest{
		Target:         req.Target,
		CredentialType: types.CredentialType(req.CredentialType),
		CredentialHint: req.CredentialHint,
	})
	if err != nil {
		return nil, credentialAcquisitionError(loggerWithContextInfo(ctx, log, start, err), "Initiate credential acquisition failed", err)
	}

	return &workload.InitiateCredentialAcquisitionResponse{
		Mode:               workload.CredentialAcquisitionMode(resp.Mode),
		FreshnessKind:      workload.FreshnessKind(resp.FreshnessKind),
		FreshnessHandle:    resp.FreshnessHandle,
		ExpiresIn:          resp.ExpiresIn,
		MaxAge:             resp.MaxAge,
		AcceptableCsk:      resp.AcceptableCsk,
		AcceptableCek:      resp.AcceptableCek,
		AcceptableEvidence: resp.AcceptableEvidence,
	}, nil
}

// EnrollCredential processes Enroll-Credential: an X509-SVID for the key of
// the CSR, which the Evidence is bound to.
func (h *Handler) EnrollCredential(ctx context.Context, req *workload.EnrollCredentialRequest) (*workload.EnrollCredentialResponse, error) {
	start := time.Now()
	log := rpccontext.Logger(ctx)
	switch {
	case req.Target == "":
		log.Error("Missing required target parameter")
		return nil, status.Error(codes.InvalidArgument, "target must be specified")
	case len(req.Csr) == 0:
		log.Error("Missing required csr parameter")
		return nil, status.Error(codes.InvalidArgument, "csr must be specified")
	case len(req.Evidence) == 0:
		log.Error("Missing required evidence parameter")
		return nil, status.Error(codes.InvalidArgument, "evidence must be specified")
	case req.Binding == nil:
		log.Error("Missing required binding parameter")
		return nil, status.Error(codes.InvalidArgument, "binding must be specified")
	}

	entry, selectors, err := h.credentialAcquisitionEntry(ctx, log, start, MethodEnrollCredential, req.CredentialHint)
	if err != nil {
		return nil, err
	}
	log = entryLogger(log, entry)

	resp, err := h.c.Manager.EnrollCredential(ctx, entry, &credentialacquisitionv1.EnrollCredentialRequest{
		Target:           req.Target,
		CredentialType:   types.CredentialType(req.CredentialType),
		CredentialHint:   req.CredentialHint,
		FreshnessKind:    types.FreshnessKind(req.FreshnessKind),
		FreshnessElement: req.FreshnessElement,
		Csr:              req.Csr,
		Evidence:         req.Evidence,
		EvidenceProfile:  req.EvidenceProfile,
		Binding:          &types.EvidenceBinding{Method: req.Binding.Method, Hash: req.Binding.Hash},
	})
	if err != nil {
		return nil, credentialAcquisitionError(loggerWithContextInfo(ctx, log, start, err), "Enroll credential failed", err)
	}

	svid := resp.GetSvid()
	if len(svid.GetCertChain()) == 0 {
		log.Error("Server returned no X509-SVID")
		return nil, status.Error(codes.Internal, "the Server returned no X509-SVID")
	}
	spiffeID, err := idutil.IDProtoString(svid.Id)
	if err != nil {
		log.WithError(err).Error("Server returned an X509-SVID with a malformed SPIFFE ID")
		return nil, status.Errorf(codes.Internal, "the Server returned an X509-SVID with a malformed SPIFFE ID: %v", err)
	}

	var bundle []byte
	if update := h.c.Manager.FetchEntriesAndBundles(selectors); update != nil && update.Bundle != nil {
		bundle = marshalBundle(update.Bundle.X509Authorities())
	}

	var certChain []byte
	for _, cert := range svid.CertChain {
		certChain = append(certChain, cert...)
	}

	log.WithField(telemetry.Expiration, time.Unix(svid.ExpiresAt, 0).UTC().Format(time.RFC3339)).Debug("Enrolled X509-SVID")
	return &workload.EnrollCredentialResponse{
		SpiffeId: spiffeID,
		X509Svid: certChain,
		Bundle:   bundle,
		Hint:     entry.Hint,
	}, nil
}

// RetrieveCredential processes Retrieve-Credential: a credential released by
// the Secret Vault, sealed to the Credential Encryption Key the Evidence is
// bound to.
func (h *Handler) RetrieveCredential(ctx context.Context, req *workload.RetrieveCredentialRequest) (*workload.RetrieveCredentialResponse, error) {
	start := time.Now()
	log := rpccontext.Logger(ctx)
	switch {
	case req.Target == "":
		log.Error("Missing required target parameter")
		return nil, status.Error(codes.InvalidArgument, "target must be specified")
	case len(req.CekPub) == 0:
		log.Error("Missing required cek_pub parameter")
		return nil, status.Error(codes.InvalidArgument, "cek_pub must be specified")
	case len(req.Evidence) == 0:
		log.Error("Missing required evidence parameter")
		return nil, status.Error(codes.InvalidArgument, "evidence must be specified")
	case req.Binding == nil:
		log.Error("Missing required binding parameter")
		return nil, status.Error(codes.InvalidArgument, "binding must be specified")
	}

	entry, _, err := h.credentialAcquisitionEntry(ctx, log, start, MethodRetrieveCredential, req.CredentialHint)
	if err != nil {
		return nil, err
	}
	log = entryLogger(log, entry)

	resp, err := h.c.Manager.RetrieveCredential(ctx, entry, &credentialacquisitionv1.RetrieveCredentialRequest{
		Target:           req.Target,
		CredentialType:   types.CredentialType(req.CredentialType),
		CredentialHint:   req.CredentialHint,
		FreshnessKind:    types.FreshnessKind(req.FreshnessKind),
		FreshnessElement: req.FreshnessElement,
		CekPub:           req.CekPub,
		Evidence:         req.Evidence,
		EvidenceProfile:  req.EvidenceProfile,
		Binding:          &types.EvidenceBinding{Method: req.Binding.Method, Hash: req.Binding.Hash},
	})
	if err != nil {
		return nil, credentialAcquisitionError(loggerWithContextInfo(ctx, log, start, err), "Retrieve credential failed", err)
	}
	if len(resp.GetEncryptedCredentialBundle()) == 0 {
		log.Error("Server returned no credential bundle")
		return nil, status.Error(codes.Internal, "the Server returned no credential bundle")
	}

	log.Debug("Retrieved credential bundle")
	return &workload.RetrieveCredentialResponse{
		EncryptedCredentialBundle: resp.EncryptedCredentialBundle,
	}, nil
}

// credentialAcquisitionEntry attests the calling Workload and picks the
// registration entry whose identity it acquires: the entry whose hint equals
// the Credential Hint, when the Workload names one and one of its entries
// carries it; otherwise the first of its entries, the default identity, in
// the order FetchX509SVID lists them. When no entry carries the Credential
// Hint, the Agent does not drop it: it forwards the hint to the Server with
// the default entry, because in TACRA the Credential Hint is addressed to
// the RATS Relying Party, which uses it, ignores it or refuses the request.
// The Agent does not decide that for the Server.
func (h *Handler) credentialAcquisitionEntry(ctx context.Context, log logrus.FieldLogger, start time.Time, method, hint string) (*common.RegistrationEntry, []*common.Selector, error) {
	selectors, err := h.c.Attestor.Attest(ctx)
	if err != nil {
		loggerWithContextInfo(ctx, log, start, err).Error("Workload attestation failed")
		return nil, nil, workloadAttestationFailedError(ctx)
	}

	if err := h.rateLimit(ctx, method, selectors); err != nil {
		return nil, nil, err
	}

	entries := hintsfilter.FilterRegistrations(h.c.Manager.MatchingRegistrationEntries(selectors), log)
	if len(entries) == 0 {
		h.logNoIdentityIssued(ctx, log, selectors, start)
		return nil, nil, status.Error(codes.PermissionDenied, "no identity issued")
	}
	if hint != "" {
		for _, entry := range entries {
			if entry.Hint == hint {
				return entry, selectors, nil
			}
		}
		log.WithField(telemetry.Hint, hint).Debug("No entry carries the credential hint; it goes to the Server with the default identity")
	}
	return entries[0], selectors, nil
}

// credentialAcquisitionError logs a refused or failed call and returns the
// status the Workload sees: the Server's own code when it refuses the call
// for a reason the Workload can act on (TACRA names those reasons) or fails
// inside, Unavailable when the Server could not be reached or answered with
// a code of its own transport.
func credentialAcquisitionError(log logrus.FieldLogger, msg string, err error) error {
	log.WithError(err).Error(msg)
	var se interface{ GRPCStatus() *status.Status }
	if errors.As(err, &se) {
		st := se.GRPCStatus()
		switch st.Code() {
		case codes.InvalidArgument, codes.NotFound, codes.PermissionDenied, codes.FailedPrecondition,
			codes.ResourceExhausted, codes.Unimplemented, codes.Internal:
			return status.Error(st.Code(), st.Message())
		}
	}
	return status.Errorf(codes.Unavailable, "%s: %v", msg, err)
}

func entryLogger(log logrus.FieldLogger, entry *common.RegistrationEntry) logrus.FieldLogger {
	return log.WithFields(logrus.Fields{
		telemetry.SPIFFEID:       entry.SpiffeId,
		telemetry.RegistrationID: entry.EntryId,
	})
}
