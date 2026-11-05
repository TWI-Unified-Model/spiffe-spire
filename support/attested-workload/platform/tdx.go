package platform

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/google/go-configfs-tsm/report"
)

// Intel TDX quote, version 4 (Intel TDX DCAP Quoting Library API, "Quote
// Format"): a 48-octet header, then the 584-octet TD quote body, whose last
// 64 octets are REPORTDATA, the only field the guest chooses.
const (
	tdxQuoteHeaderLen   = 48
	tdxQuoteBodyLen     = 584
	tdxReportDataLen    = 64
	tdxReportDataStart  = tdxQuoteHeaderLen + tdxQuoteBodyLen - tdxReportDataLen
	tdxReportDataEnd    = tdxReportDataStart + tdxReportDataLen
	tdxQuoteVersion4    = 4
	tdxTEETypeTDX       = 0x81
	tdxProvider         = "tdx_guest"
	tdxSignatureLenSize = 4 // the signature data after the body starts with its length, a uint32
	tdxMinQuoteLen      = tdxQuoteHeaderLen + tdxQuoteBodyLen + tdxSignatureLenSize
	tdxTEETypeOffset    = 4
	tdxVersionOffset    = 0
	tdxSignatureLenOffs = tdxQuoteHeaderLen + tdxQuoteBodyLen
)

// ErrNotTDX is returned when the configfs-tsm provider is not TDX or the
// outblob is not a TDX quote.
var ErrNotTDX = errors.New("platform: configfs-tsm provider is not tdx_guest")

// TDX is the Intel TDX back-end. Evidence is a configfs-tsm report whose
// outblob is a TDX quote with REPORTDATA = BindingValue(freshness element,
// Target, subject), encoded as a Veraison TSM report like the one of the
// SEV-SNP back-end. Keys are generated in guest memory.
type TDX struct {
	tsmConfig
}

// NewTDX returns the TDX back-end, using /sys/kernel/config/tsm unless another
// client is given.
func NewTDX(opts ...TSMOption) (*TDX, error) {
	c, err := newTSMConfig(opts)
	if err != nil {
		return nil, err
	}
	return &TDX{tsmConfig: c}, nil
}

// Name implements Plugin.
func (p *TDX) Name() string {
	return "tdx"
}

// AttestationPublicKey implements Plugin. A TDX quote carries its own
// attestation key, certified by the Quoting Enclave; the plug-in does not
// hold it.
func (p *TDX) AttestationPublicKey() *ecdsa.PublicKey {
	return nil
}

// GenerateEvidence implements Plugin.
func (p *TDX) GenerateEvidence(req EvidenceRequest) (*Evidence, error) {
	elem, err := p.FreshnessElement(req)
	if err != nil {
		return nil, err
	}
	subject, err := Subject(req)
	if err != nil {
		return nil, err
	}
	bv := BindingValue(elem, req.Target, subject)

	resp, err := report.Get(p.client, &report.Request{InBlob: bv[:]})
	if err != nil {
		return nil, fmt.Errorf("platform: configfs-tsm report: %w", err)
	}
	provider := strings.TrimSpace(resp.Provider)
	if provider != tdxProvider {
		return nil, fmt.Errorf("%w: %q", ErrNotTDX, provider)
	}
	q := resp.OutBlob
	if len(q) < tdxMinQuoteLen || binary.LittleEndian.Uint16(q[tdxVersionOffset:]) != tdxQuoteVersion4 ||
		binary.LittleEndian.Uint32(q[tdxTEETypeOffset:]) != tdxTEETypeTDX {
		return nil, fmt.Errorf("%w: not a version 4 TDX quote (%d octets)", ErrNotTDX, len(q))
	}
	// The kernel hands back its whole buffer; keep the quote and its signature data only.
	if n := tdxSignatureLenOffs + tdxSignatureLenSize + int(binary.LittleEndian.Uint32(q[tdxSignatureLenOffs:])); n <= len(q) {
		q = q[:n]
	}
	// As in the SEV-SNP back-end: the quote must carry the binding value we asked for.
	if !bytes.Equal(q[tdxReportDataStart:tdxReportDataEnd], bv[:]) {
		return nil, ErrReportDataMismatch
	}
	return tsmEvidence(req, elem, bv, tsmReport{OutBlob: q, Provider: provider}, nil)
}
