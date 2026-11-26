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
| Attester | the Workload; `support/attested-workload` is one | generates the key, a CSK to enroll or a CEK to retrieve, produces Evidence bound to that key and to the Target, and calls the Workload API, or CAAPI on the same socket |
| Credential Acquisition System Client | SPIRE Agent | attests the Workload as it does for FetchX509SVID, picks the registration entry whose identity the Workload acquires, and forwards the three calls to the Server |
| Credential Acquisition System Server | SPIRE Server, with the CAS Server Plug-in: the `casserver` module of the TACRA repository | issues the Freshness Handle in Enrollment, sends the Evidence to a Verifier, verifies the Attestation Results and the binding, and applies the policy for the Target |
| Verifier | a RATS Verifier; Veraison today | appraises the Evidence against its reference values and signs the Attestation Results, an EAR |
| Identity Provider in Enrollment | the CA of SPIRE Server | mints the X509-SVID; the Credential Authority of TACRA and the Server are one process |
| Identity Provider in Retrieval | the Secret Vault | originates the Freshness Handle and releases the credential, sealed to the CEK of the Workload; for a Secret Vault that only holds the credential, as HashiCorp Vault does, the Server originates the Handle, appraises and seals |
| Relying Party | the Server in Enrollment, the Secret Vault in Retrieval; the Server also in Retrieval from a Secret Vault that only holds the credential | applies the Appraisal Policy for Attestation Results of RFC 9334: which launches are admitted, which platform state is accepted |

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
of TDX, the nonce of a PSA attestation token), the SHA-512 digest of the binding
input of TACRA:

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
originates the Handle, and the Server forwards it; for a Secret Vault that only
holds the credential, the Server mints the Handle as in Enrollment.

## CAAPI on the socket of the Workload API

The Agent also serves the Credential Acquisition API of TACRA as its gRPC
service defines it, `caapi.v1.CredentialAcquisitionService` of the TACRA
repository, on the socket of the Workload API. A Workload that uses the
Credential Acquisition Interface of TACRA reaches the Agent with it, as it
reaches any other Credential Acquisition System Client, and needs no code of
SPIRE.

| Call of CAAPI | Call of the Workload API |
| --- | --- |
| `InitiateRemoteAttestation` | `InitiateCredentialAcquisition` |
| `EnrollCredential` | `EnrollCredential` |
| `RetrieveCredential` | `RetrieveCredential` |

Each call is the call of the Workload API with the messages of CAAPI: the
Agent attests the caller, picks its registration entry and forwards the call
to the Server in the same way, and the refusals are the same. Three things
differ, because the messages of CAAPI differ:

- An initiation answers with one CSK algorithm, ECDSA P-256, or with one CEK
  suite: the hybrid suite of the container when the Server accepts it.
- An enrollment answers with the X509-SVID and its chain as a PEM certificate
  bundle, leaf first, without the bundle of the trust domain.
- A request names no binding: the Agent declares `binding-input` and `sha512`.

The security header of the Workload API, `workload.spiffe.io: true`, is
required for the methods of the Workload API only: a call of CAAPI carries
none. The connections of CAAPI count as connections of the Workload API. The
Agent serves CAAPI whenever it serves the Workload API.

## Who decides what

The Verifier owns the appraisal of the Evidence, the Server its own policy as
the Relying Party, and the Secret Vault the release of a credential. The part
of the Server is the CAS Server Plug-in, which SPIRE Server hosts, and
[the document of the plug-in](https://github.com/TWI-Unified-Model/tacra/blob/main/casserver/README.md)
describes it: who decides what, each setting, the platform rule, the points of
extension, the refusals and what is logged.

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

The settings are those of the CAS Server Plug-in, and
[its document](https://github.com/TWI-Unified-Model/tacra/blob/main/casserver/README.md#configuration)
describes each of them. Every duration is a string with its unit, as elsewhere
in the configuration of SPIRE: `2m`, `90s`.

SPIRE Server mints the X509-SVID with its own CA. It refuses a configuration
with a `credential_authority`, or with a `certificate_name` or a
`certificate_validity` for a Target: those settings are for a host of the
plug-in that has no CA of its own.

## Logging

Each side logs with one mechanism per place, so that a reader knows where a
line comes from.

- The Agent, in the Workload API handler: the logger of the call,
  `rpccontext.Logger`, carries the fields of the call. A missing parameter is
  logged with it and refused with `InvalidArgument`, as the other calls of the
  Workload API do. Once the Workload is attested, every failure is logged with
  `loggerWithContextInfo`, which adds the caller and the duration, as
  `FetchX509SVID` does: a failed attestation, a refusal of the Server, an answer
  the Agent cannot use. The rate limiter logs nothing in the handler; its
  refusal is the status it returns, as for every other call. A Workload with no
  registration entry is logged by `logNoIdentityIssued`, the helper the other
  calls use. A success is logged at debug with the fields of the result.
- The Server API: `MakeErr` logs and returns every refusal; the audit fields of
  the call go through `AddRPCAuditFields`, and `AuditRPC` emits the audit line.
  A success is logged at debug with the fields of the result, as `MintX509SVID`
  does.
- The CAS Server Plug-in: a refusal is a gRPC status that names the reason, and
  is not logged again where it is returned. Its document says what the plug-in
  logs itself.

## Refusals

The Server answers a refusal of the plug-in with the gRPC code that names its
reason, and the Agent passes it to the Workload. The codes and their reasons
are in
[the document of the plug-in](https://github.com/TWI-Unified-Model/tacra/blob/main/casserver/README.md#refusals).

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
and not minted yet. The Server speaks to one kind of Verifier, `veraison`, and
to two kinds of Secret Vault, `json` and `hashicorp`; another is a new
implementation at its point of extension in the plug-in. The policy is a table
keyed by the Target name.
