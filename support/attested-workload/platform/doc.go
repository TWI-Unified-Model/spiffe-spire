// Package platform is the TACRA Platform Plug-In of an attested Workload:
// the side of the Attester in draft-novak-rats-tacra.
//
// The Workload calls this package to generate Credential Signing Keys (CSK)
// and Credential Encryption Keys (CEK), and Remote Attestation Evidence bound
// to them. The back-ends are AMD SEV-SNP (sevsnp.go) and Intel TDX (tdx.go),
// through the Linux configfs-tsm interface: the Evidence is the report of the
// hardware, whose report data is the TACRA binding value (binding.go), with the
// certificates of the host, as the media type application/vnd.veraison.tsm-report+cbor.
//
// The back-ends ran on Google Cloud and AWS SEV-SNP guests and on Google Cloud
// TDX guests against a Veraison Verifier.
package platform
