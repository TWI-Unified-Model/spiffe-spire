# AMD product chains

The ASK or ASVK and the ARK of each AMD product line, as PEM bundles: the chain
that certifies the VCEK or VLEK of the product line. The attested Workload
appends them to the certificate table of a host that leaves them out, as AWS
does. A file is indexed by the subject of its first certificate, the issuer of
the VCEK or VLEK: `SEV-Milan`, `SEV-VLEK-Milan`, and so on.

| File | Chain | Source |
| --- | --- | --- |
| `ask_ark_milan.pem` | SEV-Milan (ASK) and ARK-Milan | AMD KDS, `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain` |
| `ask_ark_milan_vlek.pem` | SEV-VLEK-Milan (ASVK) and ARK-Milan | AMD KDS, `https://kdsintf.amd.com/vlek/v1/Milan/cert_chain` |
| `ask_ark_genoa.pem` | SEV-Genoa (ASK) and ARK-Genoa | AMD KDS, `https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain` |
| `ask_ark_genoa_vlek.pem` | SEV-VLEK-Genoa (ASVK) and ARK-Genoa | AMD KDS, `https://kdsintf.amd.com/vlek/v1/Genoa/cert_chain` |
| `ask_ark_turin_vcek.pem` | SEV-Turin (ASK) and ARK-Turin | AMD KDS, `https://kdsintf.amd.com/vcek/v1/Turin/cert_chain` |
| `ask_ark_turin_vlek.pem` | SEV-VLEK-Turin (ASVK) and ARK-Turin | AMD KDS, `https://kdsintf.amd.com/vlek/v1/Turin/cert_chain` |

The files are the bundles go-sev-guest embeds in its `verify/trust` package, at
the version `go.mod` names; a test checks that they are, byte for byte. To add
a product line, add its bundle from the AMD KDS as a `.pem` file here, or give
the Workload a directory of bundles with `-amdChains`.
