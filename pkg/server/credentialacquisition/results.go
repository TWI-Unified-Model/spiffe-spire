package credentialacquisition

import "time"

// attestationResults is what the Server keeps from verified Attestation
// Results, whatever the kind of the Verifier: which Verifier issued them, the
// platform family they describe, when they were issued, the launch
// measurement, the claims of the family, and the Attestation Results as
// received, for the record.
type attestationResults struct {
	Verifier    string
	Family      string
	IssuedAt    time.Time
	Measurement []byte // the launch measurement the Verifier annotated: MEASUREMENT for SEV-SNP, MRTD for TDX
	Raw         string // the Attestation Results as received, for the record
	// SNP holds the SEV-SNP report fields the Verifier annotated, or nil with
	// SNPErr saying why; TDX holds the annotations of the TDX Verifier.
	SNP    *snpClaims
	SNPErr error
	TDX    map[string]string
	waived []string // what the platform rule admitted the results without
}
