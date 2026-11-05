// Package platform is the TACRA Platform Plug-In of an attested Workload:
// the Attester's side of draft-novak-rats-tacra.
//
// The Workload calls this package to generate Credential Signing Keys (CSK)
// and Credential Encryption Keys (CEK), and Remote Attestation Evidence bound
// to them. The back-ends are AMD SEV-SNP (sevsnp.go) and Intel TDX (tdx.go),
// through the Linux configfs-tsm interface: the Evidence is the hardware's
// report, whose report data is the TACRA binding value (binding.go), with the
// host's certificates, as the media type application/vnd.veraison.tsm-report+cbor.
//
// The package comes from the TWI-Unified-Model attestation bench (Apache-2.0),
// where it ran on Google Cloud and AWS SEV-SNP guests and Google Cloud TDX
// guests against a Veraison verifier.
package platform
