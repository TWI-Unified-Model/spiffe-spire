package platform

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/trust"
)

// The public product chains of AMD (ASK or ASVK, and ARK), as embedded in go-sev-guest, by the common name of the ASK or
// ASVK, which is the issuer of the VCEK or VLEK it certifies. The plug-in needs no network to supply them.
var amdChains = map[string][]byte{
	"SEV-Milan":      trust.AskArkMilanVcekBytes,
	"SEV-VLEK-Milan": trust.AskArkMilanVlekBytes,
	"SEV-Genoa":      trust.AskArkGenoaVcekBytes,
	"SEV-VLEK-Genoa": trust.AskArkGenoaVlekBytes,
	"SEV-Turin":      trust.AskArkTurinVcekBytes,
	"SEV-VLEK-Turin": trust.AskArkTurinVlekBytes,
}

// Certificate table GUIDs as the host writes them: the abi constants of
// go-sev-guest, in hex without the dashes (see snpCertGUIDs).
var (
	guidVCEK = strings.ReplaceAll(abi.VcekGUID, "-", "")
	guidVLEK = strings.ReplaceAll(abi.VlekGUID, "-", "")
	guidASK  = strings.ReplaceAll(abi.AskGUID, "-", "") // also carries the ASVK of a VLEK chain
	guidARK  = strings.ReplaceAll(abi.ArkGUID, "-", "")
)

type certEntry struct {
	guid []byte
	cert []byte
}

// completeCertTable returns the certificate table of the host with the AMD ASK (or ASVK) and ARK appended when the host
// left them out, as AWS does. The table is not covered by the report signature; the Verifier checks the chain up to
// the ARK it holds as trust anchor, so a wrong certificate here can only make the Evidence fail. added reports
// whether anything was appended. A table that already has both, or whose VCEK or VLEK is missing, unreadable or
// issued for a product line without an embedded chain, is returned unchanged for the Verifier to judge.
func completeCertTable(table []byte) (out []byte, added bool, err error) {
	entries, err := certTableEntries(table)
	if err != nil {
		return nil, false, err
	}
	have := map[string][]byte{}
	for _, e := range entries {
		have[hex.EncodeToString(e.guid)] = e.cert
	}
	if have[guidASK] != nil && have[guidARK] != nil {
		return table, false, nil
	}
	signer := have[guidVCEK]
	if signer == nil {
		signer = have[guidVLEK]
	}
	if signer == nil {
		return table, false, nil
	}
	leaf, err := trust.ParseCert(signer) // hosts write DER or PEM
	if err != nil {
		return table, false, nil //nolint:nilerr // a signer this plug-in cannot read: the table is left as it is
	}
	chain, ok := amdChains[leaf.Issuer.CommonName]
	if !ok {
		return table, false, nil
	}
	ask, ark, err := parseAMDChain(chain)
	if err != nil {
		return nil, false, err
	}
	for _, add := range []struct {
		guid string
		der  []byte
	}{{guidASK, ask}, {guidARK, ark}} {
		if have[add.guid] == nil {
			g, _ := hex.DecodeString(add.guid)
			entries = append(entries, certEntry{g, add.der})
			added = true
		}
	}
	return encodeCertTable(entries), added, nil
}

// parseAMDChain returns the DER ASK (or ASVK) and ARK of an embedded product chain. It trims the bundle first:
// The Turin VLEK bundle of go-sev-guest (v0.15.0) ends with a blank line, which kds.ParseProductCertChain refuses.
func parseAMDChain(chain []byte) (ask, ark []byte, err error) {
	return kds.ParseProductCertChain(bytes.TrimSpace(chain))
}

func certTableEntries(table []byte) ([]certEntry, error) {
	hdr, err := abi.ParseSnpCertTableHeader(table)
	if err != nil {
		return nil, fmt.Errorf("platform: certificate table: %w", err)
	}
	entries := make([]certEntry, 0, len(hdr))
	for i, h := range hdr {
		if uint64(h.Offset)+uint64(h.Length) > uint64(len(table)) {
			return nil, fmt.Errorf("platform: certificate table entry %d out of range", i)
		}
		entries = append(entries, certEntry{append([]byte(nil), h.GUID[:]...), append([]byte(nil), table[h.Offset:h.Offset+h.Length]...)})
	}
	return entries, nil
}

// encodeCertTable writes the entries in the abi layout of go-sev-guest, ended
// by an all-zero entry, with the certificates after the header.
func encodeCertTable(entries []certEntry) []byte {
	head := make([]byte, abi.CertTableEntrySize*(len(entries)+1))
	var body []byte
	for i, e := range entries {
		h := abi.CertTableHeaderEntry{Offset: uint32(len(head) + len(body)), Length: uint32(len(e.cert))} //nolint:gosec // offsets and lengths of a table in memory
		copy(h.GUID[:], e.guid)
		// The slice holds the whole entry, so Write cannot fail.
		_ = h.Write(head[i*abi.CertTableEntrySize:])
		body = append(body, e.cert...)
	}
	return append(head, body...)
}
