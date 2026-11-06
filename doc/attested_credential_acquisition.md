# Attested credential acquisition

**Warning**: this feature is experimental. Its configuration and its APIs may
change.

SPIRE implements the Credential Acquisition System of TACRA
(draft-novak-rats-tacra): a Workload that runs in a confidential VM acquires a
credential after Remote Attestation of its platform, with the key it holds
bound to the Evidence. The Agent is the Client of that system, SPIRE Server its
Server, and the Workload the Attester.

## Roles

| Role of TACRA | In SPIRE | What it does |
| --- | --- | --- |
| Attester | the Workload; `support/attested-workload` is one | generates the key, a CSK to enroll or a CEK to retrieve, produces Evidence bound to that key and to the Target, and calls the Workload API |
| Credential Acquisition System Client | SPIRE Agent | attests the Workload as it does for FetchX509SVID, picks the registration entry whose identity the Workload acquires, and forwards the three calls to the Server |
| Credential Acquisition System Server | SPIRE Server, package `pkg/server/credentialacquisition` | issues the Freshness Handle in Enrollment, sends the Evidence to a Verifier, verifies the Attestation Results and the binding, and applies the policy for the Target |
| Verifier | a RATS Verifier; Veraison today | appraises the Evidence against its reference values and signs the Attestation Results, an EAR |
| Identity Provider in Enrollment | the CA of SPIRE Server | mints the X509-SVID; the Credential Authority of TACRA and the Server are one process |
| Identity Provider in Retrieval | the Secret Vault | originates the Freshness Handle and releases the credential, sealed to the CEK of the Workload |
| Relying Party | the Server in Enrollment, the Secret Vault in Retrieval | applies the Appraisal Policy for Attestation Results of RFC 9334: which launches are admitted, which platform state is accepted |

The Agent never sees the private key: the Workload generates it and keeps it.
When the Workload names a Credential Hint, the Agent picks the registration
entry whose hint equals it; otherwise it picks the default identity, the first
entry FetchX509SVID lists, and forwards the hint unchanged, because in TACRA
the Credential Hint is addressed to the Relying Party.

## The three calls

The Workload API and the Server API carry the same three calls; the Agent adds
the registration entry and its own identity when it forwards them.

**InitiateCredentialAcquisition** names the Target, and may name a Credential
Type and a Credential Hint. The answer carries the mode, enroll or retrieve,
the Freshness Kind and the Freshness Handle, how long the Handle lives, and
the CSK algorithms, the CEK suites and the Evidence formats accepted.

**EnrollCredential** repeats the Target, the Freshness Kind and the Handle, and
carries the CSR, the Evidence, its media type and the binding. The answer is
the X509-SVID minted for the key of the CSR, with the bundle of the trust
domain.

**RetrieveCredential** repeats the same and carries CEKpub in place of the CSR.
The answer is the encrypted credential bundle the Secret Vault released: an
HPKE container that the CEK of the Workload alone opens.

### The binding

The Evidence carries, as its freshness input (REPORT_DATA of SEV-SNP, REPORTDATA
of TDX), the SHA-512 digest of the binding input of TACRA:

```text
binding_input = len32(freshness) || freshness || len32(target) || target || len32(subject) || subject
```

`freshness` is the freshness element, `target` the Target as the Workload named
it, and `subject` the DER CSR in Enrollment or CEKpub in Retrieval. The Server
recomputes the digest from what it received and refuses Evidence that does not
bind the key. The binding object of the request names the method,
`binding-input`, and the hash, `sha512`.

### Freshness

In Enrollment the Server mints a present-nonce Handle of 32 octets, keeps it for
`expires_in`, and consumes it at the second call. That call must repeat the
Target and the Freshness Kind, and a Credential Type or Credential Hint named at
initiation; the exchange belongs to the Workload the Agent attested at
initiation, and a Handle is consumed once. In Retrieval the Secret Vault
originates the Handle, and the Server forwards it.

## Who decides what

The Verifier owns the appraisal of the Evidence. Its reference values say which
launches it knows; its policy says what is affirming. SPIRE configures no part
of that policy: it is provisioned at the Verifier.

The Server configures two things. First, which Verifiers it trusts and for
what: the URL of the challenge-response API, the certificate of the CA that
signed its TLS certificate, the key that signs its Attestation Results
(provisioned, never fetched), the Evidence provider it appraises, `sev_guest` or
`tdx_guest`, and the EAR submodules it speaks for. Attestation Results signed by
any other key, or older than `ear_max_age`, or without the binding value as
their nonce, are refused. Second, its own policy as the Relying Party, for each
Target: the mode, the Credential Types, the Freshness Kind, the CSK algorithms,
the Verifiers whose results count, the launch measurements admitted, and the
platform rule.

The Secret Vault keeps a Relying Party policy of its own; the Server is the
conduit. In the Passport RATS model the Server obtains the Attestation Results
from the Verifier and forwards them to the Secret Vault. In the Background
Check RATS model the Server forwards the Evidence, and the Secret Vault asks the
Verifier itself.

## Configuration

```hcl
server {
    experimental {
        credential_acquisition {
            acceptable_evidence = ["application/vnd.veraison.tsm-report+cbor"]
            ear_max_age = "2m"
            ear_skew = "5s"
            client_cert_path = "/run/spire/tls/server-client.crt"
            client_key_path = "/run/spire/tls/server-client.key"
            platform_rule_path = "/run/spire/platform-rule.json"

            verifier "veraison" {
                url = "https://verifier.example:8443"
                ca_path = "/run/spire/tls/verifier-ca.crt"
                ear_key_path = "/run/spire/ear/veraison.jwk"
                provider = "sev_guest"
                submods = ["SEVSNP"]
            }

            target "spiffe://example.org" {
                mode = "enroll"
                credential_types = ["x509"]
                freshness_kind = "present-nonce"
                expires_in = "5m"
                verifiers = ["veraison"]
                acceptable_csk = ["ecdsa-p256-sha256"]
                # the launch measurements admitted, 48 octets each as hex
                measurements = ["<MEASUREMENT of an admitted launch>"]
            }

            target "https://ledger.example" {
                mode = "retrieve"
                credential_types = ["api-key"]
                rats_model = "passport"
                verifiers = ["veraison"]
            }

            secret_vault {
                url = "https://vault.example:9102"
                ca_path = "/run/spire/tls/vault-ca.crt"
            }
        }
    }
}
```

Every duration is a string with its unit, as elsewhere in the configuration of
SPIRE: `2m`, `90s`.

| `credential_acquisition` | Description | Default |
| --- | --- | --- |
| `acceptable_evidence` | The Evidence formats the Server forwards, by media type | required |
| `ear_max_age` | How old Attestation Results may be | `2m` |
| `ear_skew` | How far in the future Attestation Results may be dated | `5s` |
| `client_cert_path`, `client_key_path` | The certificate and key the Server presents to the Verifiers and the Secret Vault when they require mutual TLS | none |
| `platform_rule_path` | The JSON file with the platform rule, see below | none: only the debug and migration bits of the guest policy are refused |
| `sevsnp_products_path` | The JSON file with the product data of AMD for SEV-SNP, see below | the copy SPIRE ships |
| `verifier "<name>"` | A Verifier the Server trusts, see below | at least one |
| `target "<name>"` | The policy for a Target, see below | at least one |
| `secret_vault` | The Secret Vault of the Targets in retrieve mode | required when a Target is in retrieve mode |

| `verifier` | Description |
| --- | --- |
| `kind` | The kind of Verifier, how the Server sends it Evidence and reads its Attestation Results: `veraison`, the default and the one kind for now |
| `url` | The base URL of the API of the Verifier; for `veraison`, its challenge-response API |
| `ca_path` | The certificate of the CA that signed the TLS certificate of the Verifier |
| `provider` | The TSM report provider of the Evidence this Verifier appraises: `sev_guest` or `tdx_guest` |
| `ear_key_path` | For `veraison`: the public key that signs the Attestation Results, an EC P-256 JWK or a PEM public key, provisioned |
| `submods` | For `veraison`: the EAR submodules it speaks for, each of a platform family, `SEVSNP` or `TDX` |

| `target` | Description | Default |
| --- | --- | --- |
| `mode` | `enroll` or `retrieve` | required |
| `credential_types` | The Credential Types served for this Target | required |
| `freshness_kind` | The Freshness Kind; the Server issues `present-nonce` Handles | `present-nonce` |
| `expires_in` | The lifetime of a Freshness Handle; TACRA recommends at least `1m` | `5m` |
| `verifiers` | The Verifiers whose Attestation Results count for this Target | required |
| `acceptable_csk` | The CSK algorithms accepted in Enrollment; `ecdsa-p256-sha256` is supported | all supported |
| `measurements` | The launch measurements admitted, or `allow_any_measurement = true` to leave that decision to the Verifier | one of the two is required in enroll mode |
| `rats_model` | For retrieve mode, `passport` or `background-check` | `background-check` |

| `secret_vault` | Description |
| --- | --- |
| `kind` | The kind of Secret Vault, how the Server forwards the initiate and the retrieve parts of the flow: `json`, the TACRA calls as JSON over HTTPS, the default and the one kind for now |
| `url` | The base URL of the API of the Secret Vault |
| `ca_path` | The certificate of the CA that signed the TLS certificate of the Secret Vault |
| `client_cert_path`, `client_key_path` | A certificate and key presented to the Secret Vault in place of the ones above |

## The platform rule

Affirming Attestation Results say that the Evidence matched the reference
values of the Verifier. They do not say that the platform is one this Server
accepts: that is the platform rule, applied by the Server to the fields the
Verifier annotated.

```json
{
  "sevsnp": {
    "require_machine_identity": false,
    "allowed_products": ["Milan", "Genoa", "Turin"],
    "tcb_floors": {
      "Milan": {"bl": 4, "snp": 29, "ucode": 222},
      "Genoa": {"snp": 28, "ucode": 86},
      "Turin": {"snp": 5, "ucode": 81}
    },
    "check_committed_tcb": true,
    "smt": "allow-with-microcode-floor",
    "required_mitigation_bits": {
      "Milan": {"1": "AMD-SB-3020 (CVE-2025-0033)", "4": "AMD-SB-3034 (CVE-2025-54510)"},
      "Genoa": {"1": "AMD-SB-3020 (CVE-2025-0033)"},
      "Turin": {"0": "AMD-SB-3020 (CVE-2025-0033)"}
    },
    "required_platform_info_bits": {
      "Milan": {"5": "AMD-SB-3015 (BadRAM, CVE-2024-21944): ALIAS_CHECK_COMPLETE"}
    },
    "mitigation_waivers": {"Milan": {"4": "admitted without bit 4, AMD-SB-3034"}}
  },
  "tdx": {"td_attributes_refused": "0x2000fff0"}
}
```

For SEV-SNP the rule names the machines admitted (by CHIP_ID, or any machine
that is named), the product lines admitted (from the CPUID family and model of
the report), the floor of each TCB component per product line, applied to
REPORTED_TCB and, when asked, to COMMITTED_TCB, whether SMT is allowed, the
mitigation bits that must be set in both mitigation vectors with the reason
each refusal gives, the PLATFORM_INFO bits required, and the waivers. The guest
policy is the POLICY field of the report, the launch settings of the guest:
its debug and migration bits are refused with or without a rule. For TDX the
rule names the TD ATTRIBUTES bits refused.

The rule has one entry per platform family, keyed by the name of the module of
the Server for the family: `sevsnp`, `tdx`. A module is the counterpart on the
Server side of the platform plug-in of the Attester: it names the EAR submodule
the Verifier annotates for the family, parses and validates the entry, and
applies it to the Attestation Results. A family without an entry is refused. A
new family, CCA for example, is a new module; the rest of the Server does not
change.

The module for SEV-SNP reads the report with the product data of AMD: which
product line a CPUID family and extended model names, and the byte of each
component in TCB_VERSION. That data grows with every product line AMD ships, so
it is a JSON file under version control, not code: the copy SPIRE ships,
[sevsnp_products.json](/pkg/server/credentialacquisition/sevsnp_products.json),
or the file `sevsnp_products_path` names, in the same format.

```json
{
  "products": [
    {
      "name": "Turin",
      "cpuid": [{"family": "0x1A", "extended_model": "0x0"}, {"family": "0x1A", "extended_model": "0x1"}],
      "tcb_layout": {"fmc": 0, "bl": 1, "tee": 2, "snp": 3, "ucode": 7},
      "source": "AMD 57230 Rev. 1.05, Table 4; AMD 56860 Rev. 1.59, Table 4"
    }
  ]
}
```

A product line without a layout is not decoded, so the rule refuses it; an
operator who has the layout adds it to the file. A rule that names a product
line the data does not have is refused when the Server starts.

## Points of extension

The Server has three points of extension, each a list of implementations
behind one interface, named in the configuration or in the rule file. The data
that grows on its own schedule, the product lines of AMD and their chains, is
in files under version control, not in the code.

| Point | Named by | Implementations |
| --- | --- | --- |
| Platform family: how the claims of a family are checked against the platform rule | the key of the entry in the rule file | `sevsnp`, `tdx` |
| Verifier kind: how Evidence is sent to a Verifier and its Attestation Results are verified and read | `kind` of a `verifier` | `veraison` |
| Secret Vault kind: how the initiate and the retrieve parts of the flow are forwarded | `kind` of `secret_vault` | `json` |

The kind is chosen by the operator and confirmed by the Server, not guessed
from what arrives: a Verifier of kind `veraison` reads the profile an EAR names
in `eat_profile`, and refuses Attestation Results that name another, with both
names in the refusal.

## Refusals

The Server answers a refusal with the gRPC code that names its reason, and the
Agent passes it to the Workload.

| Code | When |
| --- | --- |
| `InvalidArgument` | A malformed request: a call of the enroll mode for a Target in retrieve mode or the reverse, a Credential Type that is not one of TACRA, a Freshness Kind or Handle that does not match the initiation, a binding or an Evidence format not accepted, a malformed CSR or one of another algorithm |
| `NotFound` | A Target this Server does not serve |
| `Unimplemented` | A Credential Type this Server does not serve for the Target, named with the ones it serves |
| `PermissionDenied` | Remote Attestation failed: Attestation Results not affirming, not signed by a Verifier of the policy, or reporting another nonce; a launch not admitted; the platform rule refused |
| `Unavailable` | No Verifier or Secret Vault could be reached, or none is configured for the call |
| `ResourceExhausted` | The Secret Vault asked the Server to slow down |
| `Internal` | A failure inside the Server, or a Secret Vault answer that breaks the contract |

A refusal of the Secret Vault is relayed with the gRPC code of its HTTP status
and the reason it gives.

## The attested Workload

`support/attested-workload` is a Workload for the proof of concept: it runs in
an AMD SEV-SNP or Intel TDX guest, generates the key, produces the Evidence
through the Linux configfs-tsm interface with the binding value as the report
data, and runs the three calls over the Workload API socket of the Agent. The
Platform Plug-In it does this with, the interface and the SEV-SNP and TDX
back-ends, is the `platform` module of the TACRA repository,
`github.com/TWI-Unified-Model/tacra`, which the Workload imports; SPIRE holds
no copy of it. In
Enrollment it writes the X509-SVID, its key and the bundle; in Retrieval it
opens the container with its CEK, checks the associated data and, when a key is
given with `-vaultOriginKey`, the origin signature of the Secret Vault, and
writes the credential it received. `result.json` records the exchange.

For SEV-SNP the plug-in completes the certificate table of a host that leaves
out the ASK or ASVK and the ARK of AMD, as AWS does. Those chains grow with
every product line, so they are PEM files under version control in that module,
`platform/amdchains` with their sources in its README, embedded as the copies
the plug-in ships; `-amdChains` names a directory of files in their place. A
file is indexed by the subject of its first certificate, the issuer of the VCEK
or VLEK.

## The shape of the proof of concept

The Server issues present-nonce Handles; a Target in retrieve mode uses the
Freshness Kind its Secret Vault answers. Enrollment mints `x509`; `wic` is named
and not minted yet. The Server speaks to one kind of Verifier, `veraison`, and one kind of Secret
Vault, `json`; another is a new implementation at its point of extension. The
policy is a table keyed by the Target name.
