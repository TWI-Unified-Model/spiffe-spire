package credentialacquisition

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
)

// The binding of TACRA (Binding Credential Keys to Evidence) in the TACRA EST
// profile, which the Workload API carries unchanged: the Evidence's freshness
// input holds SHA-512 of the binding input, and the binding object names the
// method and the hash.
const (
	BindingMethod = "binding-input"
	BindingHash   = "sha512"
)

// BindingInput is the octet string of TACRA, Binding Credential Keys to
// Evidence: each value preceded by its length as a 32-bit big-endian integer,
// and no identifier of any party.
//
//	binding_input = len32(freshness) || freshness || len32(target) || target || len32(subject) || subject
//
// freshness is the freshness element (the Freshness Handle, the epoch marker
// or the 8-octet timestamp; empty for absent-none), target the Target, and
// subject the DER CSR (Enrollment) or the public Credential Encryption Key
// as the request carries it (Retrieval).
func BindingInput(freshness []byte, target string, subject []byte) []byte {
	var out []byte
	for _, v := range [][]byte{freshness, []byte(target), subject} {
		out = binary.BigEndian.AppendUint32(out, uint32(len(v))) //nolint:gosec // lengths of octet strings on the wire
		out = append(out, v...)
	}
	return out
}

// BindingValue is SHA-512 of BindingInput: the 64 octets the Attester writes
// into the freshness input of its Evidence (REPORT_DATA on AMD SEV-SNP,
// REPORTDATA on Intel TDX), and the nonce the Verifier reports.
func BindingValue(freshness []byte, target string, subject []byte) []byte {
	sum := sha512.Sum512(BindingInput(freshness, target, subject))
	return sum[:]
}

func decodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
