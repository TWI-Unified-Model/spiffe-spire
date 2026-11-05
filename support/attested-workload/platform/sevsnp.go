package platform

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha512"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	"github.com/google/go-configfs-tsm/report"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/verify/trust"
)

// TSMReportMediaTypeCBOR is the media type under which the Veraison sevsnp
// scheme accepts a Linux configfs-tsm report as Evidence.
const TSMReportMediaTypeCBOR = "application/vnd.veraison.tsm-report+cbor"

// The bounds of an eat_nonce (RFC 9711, Section 4.1): 8 to 64 octets.
const (
	minNonceSize = 8
	maxNonceSize = 64
)

// snpProvider is the configfs-tsm provider name of an SEV-SNP guest. The report
// layout and the certificate-table GUIDs come from the abi package of go-sev-guest.
const snpProvider = "sev_guest"

// Names under which ParseSNPCertTable returns the certificates of the host.
const (
	SNPCertVCEK = "VCEK"
	SNPCertVLEK = "VLEK"
	SNPCertASK  = "ASK" // or the ASVK, in a VLEK chain
	SNPCertARK  = "ARK"
)

// Keys of the unsigned Claims of configfs-tsm Evidence (SEV-SNP and TDX): what
// the Relying Party needs to recompute the binding value.
const (
	TSMClaimFreshnessKind    = "freshness-kind"
	TSMClaimFreshnessElement = "freshness-element"
	TSMClaimTarget           = "target"
	TSMClaimBindingValue     = "binding-value"
	// TSMClaimCertTableCompleted (SEV-SNP) is true when the plug-in appended
	// the AMD ASK or ASVK and ARK to the certificate table of the host.
	TSMClaimCertTableCompleted = "cert-table-completed"
)

// snpCertGUIDs names the certificate-table entries of the host by the GUIDs
// go-sev-guest defines.
var snpCertGUIDs = map[string]string{
	abi.VcekGUID: SNPCertVCEK,
	abi.VlekGUID: SNPCertVLEK,
	abi.AskGUID:  SNPCertASK,
	abi.ArkGUID:  SNPCertARK,
}

var (
	// ErrNotSEVSNP is returned when the configfs-tsm provider is not SEV-SNP.
	ErrNotSEVSNP = errors.New("platform: configfs-tsm provider is not sev_guest")
	// ErrReportDataMismatch is returned when the report does not carry the
	// binding value the plug-in asked for.
	ErrReportDataMismatch = errors.New("platform: REPORT_DATA differs from the requested binding value")
	// ErrFreshnessElement is returned when the freshness element does not
	// fit the Freshness Kind.
	ErrFreshnessElement = errors.New("platform: freshness element does not fit the Freshness Kind")
)

// tsmReport is the Veraison TSM report (github.com/veraison/ratsd tokens,
// docs/tsm-report.cddl), encoded as ratsd encodes it: fxamacker/cbor over the
// same struct tags.
type tsmReport struct {
	AuxBlob         []byte  `json:"auxblob,omitempty"`
	OutBlob         []byte  `json:"outblob"`
	Provider        string  `json:"provider"`
	ManifestBlob    []byte  `json:"manifestblob,omitempty"`
	ServiceProvider *string `json:"service_provider,omitempty"`
}

// tsmConfig is what the configfs-tsm back-ends (SEV-SNP, TDX) share.
type tsmConfig struct {
	client        configfsi.Client
	clock         func() time.Time
	localEpoch    []byte
	completeChain bool // SEV-SNP: append AMD's ASK/ASVK and ARK when the host leaves them out
}

// TSMOption configures a configfs-tsm back-end.
type TSMOption func(*tsmConfig)

// WithTSMClient replaces the configfs client (tests use a mock).
func WithTSMClient(c configfsi.Client) TSMOption {
	return func(p *tsmConfig) {
		p.client = c
	}
}

// WithClock sets the clock used for the absent-timestamp freshness element.
func WithClock(clock func() time.Time) TSMOption {
	return func(p *tsmConfig) {
		p.clock = clock
	}
}

// WithLocalEpoch sets the epoch identifier held locally for absent-epoch.
func WithLocalEpoch(epoch []byte) TSMOption {
	return func(p *tsmConfig) {
		p.localEpoch = append([]byte(nil), epoch...)
	}
}

// WithoutChainCompletion keeps the certificate table of the host exactly as delivered.
func WithoutChainCompletion() TSMOption {
	return func(p *tsmConfig) {
		p.completeChain = false
	}
}

func newTSMConfig(opts []TSMOption) (tsmConfig, error) {
	c := tsmConfig{clock: time.Now, completeChain: true}
	for _, o := range opts {
		o(&c)
	}
	if c.client == nil {
		client, err := linuxtsm.MakeClient()
		if err != nil {
			return c, fmt.Errorf("platform: configfs-tsm: %w", err)
		}
		c.client = client
	}
	return c, nil
}

// SEVSNP is the AMD SEV-SNP back-end. Evidence is a configfs-tsm report whose
// REPORT_DATA is BindingValue(freshness element, Target, subject), with the
// certificate table of the host as auxblob, encoded as a
// Veraison TSM report. Keys are generated in guest memory.
type SEVSNP struct {
	tsmConfig

	mu   sync.Mutex
	vcek *ecdsa.PublicKey
}

// NewSEVSNP returns the SEV-SNP back-end, using /sys/kernel/config/tsm unless
// another client is given.
func NewSEVSNP(opts ...TSMOption) (*SEVSNP, error) {
	c, err := newTSMConfig(opts)
	if err != nil {
		return nil, err
	}
	return &SEVSNP{tsmConfig: c}, nil
}

// Name implements Plugin.
func (p *SEVSNP) Name() string {
	return "sev-snp"
}

// GenerateCEK implements Plugin.
func (p *tsmConfig) GenerateCEK(alg EncryptionAlgorithm) (*KeyPair, error) {
	switch alg {
	case EncryptionAlgorithmECDHP256:
		return generateP256()
	case EncryptionAlgorithmRSA2048:
		return generateRSA2048()
	case EncryptionAlgorithmMLKEM768P256:
		return generateMLKEM768P256()
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEncryptionAlgorithm, alg)
	}
}

// GenerateCSK implements Plugin.
func (p *tsmConfig) GenerateCSK(alg SigningAlgorithm) (*KeyPair, error) {
	switch alg {
	case SigningAlgorithmUnspecified, SigningAlgorithmECDSAP256:
		return generateP256()
	case SigningAlgorithmRSA2048:
		return generateRSA2048()
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSigningAlgorithm, alg)
	}
}

// LocalEpoch implements Plugin.
func (p *tsmConfig) LocalEpoch() []byte {
	return append([]byte(nil), p.localEpoch...)
}

// AttestationPublicKey implements Plugin: the key that signed the last report,
// the VCEK or VLEK as SIGNING_KEY of the report names it, from the certificate
// table of the host; nil before the first report or when the table does not
// hold it.
func (p *SEVSNP) AttestationPublicKey() *ecdsa.PublicKey {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.vcek
}

// FreshnessElement returns the value bound as the freshness element for req:
// the Handle for the present kinds, the local epoch (which the CAI passes as
// the Handle) for absent-epoch, eight octets of Unix time for absent-timestamp
// (the Handle of the request when it carries them, else the clock), and nothing for
// absent-none.
func (p *tsmConfig) FreshnessElement(req EvidenceRequest) ([]byte, error) {
	switch req.FreshnessKind {
	case FreshnessKindPresentNonce, FreshnessKindPresentEpoch, FreshnessKindAbsentEpoch:
		if n := len(req.FreshnessHandle); n < minNonceSize || n > maxNonceSize {
			return nil, fmt.Errorf("%w: %d octets", ErrInvalidFreshnessHandle, n)
		}
		return append([]byte(nil), req.FreshnessHandle...), nil
	case FreshnessKindAbsentTimestamp:
		if len(req.FreshnessHandle) == TimestampElementSize {
			return append([]byte(nil), req.FreshnessHandle...), nil
		}
		if len(req.FreshnessHandle) != 0 {
			return nil, fmt.Errorf("%w: absent-timestamp needs %d octets", ErrFreshnessElement, TimestampElementSize)
		}
		return TimestampElement(p.clock().Unix()), nil
	case FreshnessKindAbsentNone:
		if len(req.FreshnessHandle) != 0 {
			return nil, fmt.Errorf("%w: absent-none needs none", ErrFreshnessElement)
		}
		return nil, nil
	default:
		return nil, fmt.Errorf("%w: kind %d", ErrFreshnessElement, req.FreshnessKind)
	}
}

// Subject returns the binding subject: the DER CSR for Enrollment, CEKpub for
// Retrieval (CEKPub: the encapsulation key itself for MLKEM768-P256, else the
// DER SubjectPublicKeyInfo of the bound key).
func Subject(req EvidenceRequest) ([]byte, error) {
	if resolveKeyUse(req) == BoundKeyUseSign {
		if len(req.CSR) == 0 {
			return nil, errors.New("platform: Enrollment needs the CSR")
		}
		return append([]byte(nil), req.CSR...), nil
	}
	if req.BoundKey == nil {
		return nil, ErrMissingBoundKey
	}
	return CEKPub(req.BoundKey)
}

// GenerateEvidence implements Plugin. Claims carries, unsigned, what the
// Relying Party needs to recompute the binding: the freshness element (which
// for absent-timestamp originates here) and the Target.
func (p *SEVSNP) GenerateEvidence(req EvidenceRequest) (*Evidence, error) {
	elem, err := p.FreshnessElement(req)
	if err != nil {
		return nil, err
	}
	subject, err := Subject(req)
	if err != nil {
		return nil, err
	}
	bv := BindingValue(elem, req.Target, subject)

	resp, err := report.Get(p.client, &report.Request{InBlob: bv[:], GetAuxBlob: true})
	if err != nil {
		return nil, fmt.Errorf("platform: configfs-tsm report: %w", err)
	}
	provider := strings.TrimSpace(resp.Provider)
	if provider != snpProvider {
		return nil, fmt.Errorf("%w: %q", ErrNotSEVSNP, provider)
	}
	rep, err := abi.ReportToProto(resp.OutBlob)
	if err != nil {
		return nil, fmt.Errorf("platform: SEV-SNP report: %w", err)
	}
	// The report must carry the binding value we asked for; fail here rather
	// than hand out Evidence the Relying Party would refuse.
	if !bytes.Equal(rep.GetReportData(), bv[:]) {
		return nil, ErrReportDataMismatch
	}
	// Keep the key that signed this report for AttestationPublicKey. The table
	// is outside the signed report, so the key is a hint only; the Verifier
	// checks the report against the AMD chain.
	signer := reportSigner(rep.GetSignerInfo(), resp.AuxBlob)
	p.mu.Lock()
	p.vcek = signer
	p.mu.Unlock()

	aux := resp.AuxBlob
	completed := false
	if p.completeChain && len(aux) > 0 {
		if aux, completed, err = completeCertTable(aux); err != nil {
			return nil, err
		}
	}
	return tsmEvidence(req, elem, bv, tsmReport{AuxBlob: aux, OutBlob: resp.OutBlob, Provider: provider},
		map[string]any{TSMClaimCertTableCompleted: completed})
}

// reportSigner returns the public key of the certificate in the table of the
// host that SIGNING_KEY of the report names (VCEK or VLEK), or nil when the report is
// unsigned or the table does not hold that certificate.
func reportSigner(signerInfo uint32, table []byte) *ecdsa.PublicKey {
	info, err := abi.ParseSignerInfo(signerInfo)
	if err != nil {
		return nil
	}
	certs, err := ParseSNPCertTable(table)
	if err != nil {
		return nil
	}
	var cert []byte
	switch info.SigningKey {
	case abi.VcekReportSigner:
		cert = certs[SNPCertVCEK]
	case abi.VlekReportSigner:
		cert = certs[SNPCertVLEK]
	default:
		return nil
	}
	c, err := trust.ParseCert(cert) // hosts write DER or PEM
	if err != nil {
		return nil
	}
	pub, _ := c.PublicKey.(*ecdsa.PublicKey)
	return pub
}

// tsmEvidence encodes a configfs-tsm report as Evidence. Claims carries,
// unsigned, what the Relying Party needs to recompute the binding, and any
// back-end specific notes in extra.
func tsmEvidence(req EvidenceRequest, elem []byte, bv [sha512.Size]byte, rep tsmReport, extra map[string]any) (*Evidence, error) {
	token, err := cbor.Marshal(rep)
	if err != nil {
		return nil, fmt.Errorf("platform: TSM report CBOR: %w", err)
	}
	c := map[string]any{
		TSMClaimFreshnessKind:    int32(req.FreshnessKind),
		TSMClaimFreshnessElement: elem,
		TSMClaimTarget:           req.Target,
		TSMClaimBindingValue:     bv[:],
	}
	maps.Copy(c, extra)
	claims, err := cbor.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("platform: claims CBOR: %w", err)
	}
	return &Evidence{Token: token, MediaType: TSMReportMediaTypeCBOR, Claims: claims}, nil
}

// ParseSNPCertTable splits the certificate table of the host, as the abi package of go-sev-guest
// reads it, into the certificates keyed by the SNPCert names; unknown GUIDs are
// kept under their GUID string.
func ParseSNPCertTable(buf []byte) (map[string][]byte, error) {
	entries, err := abi.ParseSnpCertTableHeader(buf)
	if err != nil {
		return nil, fmt.Errorf("platform: certificate table: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("platform: empty certificate table")
	}
	out := map[string][]byte{}
	for i, e := range entries {
		if uint64(e.Offset)+uint64(e.Length) > uint64(len(buf)) {
			return nil, fmt.Errorf("platform: certificate table entry %d out of range", i)
		}
		name := e.GUID.String()
		if k, ok := snpCertGUIDs[name]; ok {
			name = k
		}
		out[name] = append([]byte(nil), buf[e.Offset:e.Offset+e.Length]...)
	}
	return out, nil
}

// ReportFromTSMToken returns the SEV-SNP report (outblob) inside a TSM token.
func ReportFromTSMToken(token []byte) ([]byte, error) {
	var t tsmReport
	if err := cbor.Unmarshal(token, &t); err != nil {
		return nil, err
	}
	return t.OutBlob, nil
}
