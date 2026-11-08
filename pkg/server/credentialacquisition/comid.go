package credentialacquisition

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/fxamacker/cbor/v2"
)

// For an SEV-SNP report, a Veraison Verifier puts a CoMID (CoRIM,
// draft-ietf-rats-corim) into its Attestation Results: one reference-value
// triple whose measurements are the fields from the report. The measurement
// keys are those of the AMD SEV-SNP CoRIM profile
// (draft-deeglaze-amd-sev-snp-corim-profile), which go-gen-ref, the converter
// of the Veraison scheme, writes as literals; no package exports them.
const (
	mKeyPolicy       = 2    // POLICY, a raw value of 8 octets
	mKeyPlatformInfo = 7    // PLATFORM_INFO, a raw value of 8 octets
	mKeyMeasurement  = 641  // MEASUREMENT, a digest
	mKeyReportedTCB  = 647  // REPORTED_TCB, an SVN
	mKeyFamily       = 648  // CPUID family, a raw value of 1 octet (report version 3 and later)
	mKeyModel        = 649  // CPUID model
	mKeyStepping     = 650  // CPUID stepping
	mKeyChipID       = 3328 // CHIP_ID, a raw value, when not zero
	mKeyCommittedTCB = 3329 // COMMITTED_TCB, an SVN
	mKeyLaunchMit    = 4032 // LAUNCH_MIT_VECTOR, a raw value of 8 octets (report version 5 and later)
	mKeyCurrentMit   = 4096 // CURRENT_MIT_VECTOR
)

// CBOR tags of the annotated CoMID.
const (
	tagOID      = 111 // an OID in its DER encoding
	tagCoMID    = 506 // tagged-concise-mid-type
	tagSVN      = 552 // tagged-svn
	tagMinSVN   = 553 // tagged-min-svn
	tagRawValue = 560 // tagged-bytes, a raw value
)

// The environment class of the CoMID a Veraison Verifier puts into its
// Attestation Results for an SEV-SNP report: the chip for a VCEK-signed
// report, the cloud provider for a VLEK-signed one.
const (
	classByChip = "1.3.6.1.4.1.3704.3.1"
	classByCSP  = "1.3.6.1.4.1.3704.3.2"
)

// snpClaims are the fields from an SEV-SNP report, read from the CoMID a
// Veraison Verifier puts into its Attestation Results (the annotated
// evidence).
type snpClaims struct {
	class            string
	measurement      []byte
	policy           uint64
	platformInfo     uint64
	reportedTCB      uint64
	committedTCB     uint64
	hasCPUID         bool
	family           byte
	model            byte
	stepping         byte
	chipID           []byte
	launchMitVector  uint64
	currentMitVector uint64
	hasMitVectors    bool
}

// parseSNPClaims reads the annotated CoMID: in the annotated evidence,
// tags[0] is base64 of the CoMID, CBOR tag 506 around the CoMID map. Its
// triples (key 4) hold the reference-values (key 0), each a pair of an
// environment and the measurements; a measurement is a map of mkey (key 0)
// and mval (key 1), whose svn is at key 1, digests at key 2 and raw value at
// key 4.
func parseSNPClaims(raw json.RawMessage) (*snpClaims, error) {
	var a struct {
		Tags []string `json:"tags"`
	}
	if err := json.Unmarshal(raw, &a); err != nil || len(a.Tags) == 0 {
		return nil, errors.New("no annotated CoMID")
	}
	b, err := base64.StdEncoding.DecodeString(a.Tags[0])
	if err != nil {
		return nil, fmt.Errorf("annotated CoMID: %w", err)
	}
	var v any
	if err := cbor.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("annotated CoMID: %w", err)
	}
	if t, ok := v.(cbor.Tag); ok && t.Number == tagCoMID {
		v = t.Content
	}
	if wrapped, ok := v.([]byte); ok { // the CoMID map as a byte string
		v = nil
		if err := cbor.Unmarshal(wrapped, &v); err != nil {
			return nil, fmt.Errorf("annotated CoMID: %w", err)
		}
	}
	comid, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("annotated CoMID: not a map")
	}
	triples, ok := comid[uint64(4)].(map[any]any)
	if !ok {
		return nil, errors.New("annotated CoMID: no triples")
	}
	refs, ok := triples[uint64(0)].([]any)
	if !ok || len(refs) != 1 {
		return nil, errors.New("annotated CoMID: expected one reference-value triple")
	}
	triple, ok := refs[0].([]any)
	if !ok || len(triple) != 2 {
		return nil, errors.New("annotated CoMID: malformed reference-value triple")
	}
	out := &snpClaims{class: environmentClass(triple[0])}
	measurements, ok := triple[1].([]any)
	if !ok {
		return nil, errors.New("annotated CoMID: no measurements")
	}
	seen := map[uint64]bool{}
	for _, m := range measurements {
		mm, ok := m.(map[any]any)
		if !ok {
			continue
		}
		key, ok := mm[uint64(0)].(uint64)
		if !ok {
			continue
		}
		mval, ok := mm[uint64(1)].(map[any]any)
		if !ok {
			continue
		}
		switch key {
		case mKeyMeasurement:
			if digests, ok := mval[uint64(2)].([]any); ok && len(digests) > 0 {
				if d, ok := digests[0].([]any); ok && len(d) == 2 {
					if hash, ok := d[1].([]byte); ok {
						out.measurement = append([]byte(nil), hash...)
					}
				}
			}
		case mKeyPolicy, mKeyPlatformInfo, mKeyLaunchMit, mKeyCurrentMit:
			v, err := rawUint(mval, 8)
			if err != nil {
				return nil, fmt.Errorf("annotated CoMID: MKey %d: %w", key, err)
			}
			switch key {
			case mKeyPolicy:
				out.policy = v
			case mKeyPlatformInfo:
				out.platformInfo = v
			case mKeyLaunchMit:
				out.launchMitVector = v
			default:
				out.currentMitVector = v
			}
		case mKeyReportedTCB, mKeyCommittedTCB:
			v, err := svnUint(mval)
			if err != nil {
				return nil, fmt.Errorf("annotated CoMID: MKey %d: %w", key, err)
			}
			if key == mKeyReportedTCB {
				out.reportedTCB = v
			} else {
				out.committedTCB = v
			}
		case mKeyFamily, mKeyModel, mKeyStepping:
			v, err := rawUint(mval, 1)
			if err != nil {
				return nil, fmt.Errorf("annotated CoMID: MKey %d: %w", key, err)
			}
			switch key {
			case mKeyFamily:
				out.family = byte(v) //nolint:gosec // one octet
			case mKeyModel:
				out.model = byte(v) //nolint:gosec // one octet
			default:
				out.stepping = byte(v) //nolint:gosec // one octet
			}
		case mKeyChipID:
			b, ok := rawValue(mval[uint64(4)])
			if !ok {
				return nil, errors.New("annotated CoMID: MKey 3328: no raw value")
			}
			out.chipID = append([]byte(nil), b...)
		default:
			continue
		}
		seen[key] = true
	}
	if out.measurement == nil {
		return nil, errors.New("annotated CoMID: no launch measurement")
	}
	for _, k := range []uint64{mKeyPolicy, mKeyPlatformInfo, mKeyReportedTCB, mKeyCommittedTCB} {
		if !seen[k] {
			return nil, fmt.Errorf("annotated CoMID: no MKey %d", k)
		}
	}
	out.hasCPUID = seen[mKeyFamily] && seen[mKeyModel]
	out.hasMitVectors = seen[mKeyLaunchMit] && seen[mKeyCurrentMit]
	return out, nil
}

// environmentClass reads the class of the environment map (key 0: class map,
// key 0: the class id, an OID tagged 111) as a dotted string, or "".
func environmentClass(env any) string {
	e, ok := env.(map[any]any)
	if !ok {
		return ""
	}
	class, ok := e[uint64(0)].(map[any]any)
	if !ok {
		return ""
	}
	t, ok := class[uint64(0)].(cbor.Tag)
	if !ok || t.Number != tagOID {
		return ""
	}
	der, ok := t.Content.([]byte)
	if !ok {
		return ""
	}
	return oidString(der)
}

// oidString decodes the DER content octets of an OBJECT IDENTIFIER.
func oidString(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	parts := []string{strconv.Itoa(int(der[0]) / 40), strconv.Itoa(int(der[0]) % 40)}
	var v uint64
	for _, b := range der[1:] {
		v = v<<7 | uint64(b&0x7f)
		if b&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(v, 10))
			v = 0
		}
	}
	return strings.Join(parts, ".")
}

// rawValue reads a raw-value-type: the bytes, tagged 560 or bare.
func rawValue(v any) ([]byte, bool) {
	if t, ok := v.(cbor.Tag); ok && t.Number == tagRawValue {
		v = t.Content
	}
	b, ok := v.([]byte)
	return b, ok
}

// rawUint reads the raw value of a measurement (mval key 4) as a big-endian
// integer of exactly n octets.
func rawUint(mval map[any]any, n int) (uint64, error) {
	b, ok := rawValue(mval[uint64(4)])
	if !ok {
		return 0, errors.New("no raw value")
	}
	if len(b) != n {
		return 0, fmt.Errorf("raw value of %d octets, expected %d", len(b), n)
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

// svnUint reads the svn of a measurement (mval key 1): a TCB_VERSION as an
// SVN (tag 552) or a minimum SVN (tag 553).
func svnUint(mval map[any]any) (uint64, error) {
	v := mval[uint64(1)]
	if t, ok := v.(cbor.Tag); ok && (t.Number == tagSVN || t.Number == tagMinSVN) {
		v = t.Content
	}
	switch n := v.(type) {
	case uint64:
		return n, nil
	case int64:
		if n >= 0 {
			return uint64(n), nil
		}
	}
	return 0, errors.New("no SVN")
}
