package platform

import (
	"encoding/hex"
	"testing"
)

// The hardware vector of the TACRA Binding, three fields (the freshness element, the Target, the subject): the
// present-nonce Enrollment of a SEV-SNP run on Google Cloud (20261011T151929Z), whose REPORT_DATA equals
// SHA-512(binding_input).
const (
	tv3HandleHex     = "a8dd37281155a104a3565cc7ce2057d508dd978c00b2f1fa1e2591da88d508b3"
	tv3Target        = "https://db.tacra.example"
	tv3SubjectHex    = "3081dc3081830201003021311f301d06035504031316776f726b6c6f61642e74616372612e6578616d706c653059301306072a8648ce3d020106082a8648ce3d030107034200043f7db1f117615222a44ba5aa38e46f081aba244ac212b9a4fdad6b32c1d652efc8ee87a58a5c527c8fb3f99fb73e9672ee16295162a644d1d8f347514a3cc334a000300a06082a8648ce3d0403020348003045022100faac6730de9d236b9ceda664aaa5c8141ca611994b2be69e7d9faf1a1643aed2022023ddf3e5bd48fcb1e9ced32a21b73a81385f4763a752dfc3d735b7d313998968"
	tv3ReportDataHex = "79e35ac63f0dd8ec89d31afcab8ede5d993de21003af1b16d90f43c5a8f788f99cd8013e75f615ede1acb4fcee27d732063570e97b8a22c2da8d5eec8240c4fd"
)

func TestBindingValueMatchesHardwareVector(t *testing.T) {
	handle, _ := hex.DecodeString(tv3HandleHex)
	subject, _ := hex.DecodeString(tv3SubjectHex)
	bv := BindingValue(handle, tv3Target, subject)
	if got := hex.EncodeToString(bv[:]); got != tv3ReportDataHex {
		t.Fatalf("binding value %s, want REPORT_DATA of the report %s", got, tv3ReportDataHex)
	}
	if n := len(BindingInput(handle, tv3Target, subject)); n != 4+32+4+len(tv3Target)+4+len(subject) {
		t.Fatalf("binding input is %d octets", n)
	}
}
