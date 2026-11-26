package run

import (
	"os"
	"path/filepath"
	"testing"

	credentialacquisition "github.com/TWI-Unified-Model/tacra/casserver"
	"github.com/TWI-Unified-Model/tacra/constants"
	"github.com/stretchr/testify/require"
)

// The credential_acquisition block of the experimental configuration decodes
// into the configuration of the package: the Targets and the Verifiers are labeled
// blocks, the rest plain settings.
func TestParseCredentialAcquisitionConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.conf")
	require.NoError(t, os.WriteFile(path, []byte(`
server {
    bind_address = "127.0.0.1"
    bind_port = "8081"
    trust_domain = "example.org"
    data_dir = "./.data"
    experimental {
        credential_acquisition {
            acceptable_evidence = ["application/vnd.veraison.tsm-report+cbor"]
            ear_max_age = "2m"
            client_cert_path = "/certs/server.crt"
            client_key_path = "/certs/server.key"
            verifier "veraison" {
                kind = "veraison"
                url = "https://localhost:8443"
                ca_path = "/certs/veraison-ca.crt"
                ear_key_path = "/keys/veraison.ear.jwk"
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
                measurements = ["a0a1a2"]
            }
            secret_vault {
                kind = "json"
                url = "https://localhost:9102"
                ca_path = "/certs/root.crt"
                client_cert_path = "/certs/conduit.crt"
                client_key_path = "/certs/conduit.key"
            }
            platform_rule_path = "/rules/platform.json"
            sevsnp_products_path = "/rules/sevsnp-products.json"
        }
    }
}
plugins {
    DataStore "sql" {
        plugin_data {
            database_type = "sqlite3"
            connection_string = "./.data/datastore.sqlite3"
        }
    }
}
`), 0o600))

	c, err := ParseFile(path, false)
	require.NoError(t, err)
	ca := c.Server.Experimental.CredentialAcquisition
	require.NotNil(t, ca)
	require.Equal(t, []string{"application/vnd.veraison.tsm-report+cbor"}, ca.AcceptableEvidence)
	require.Equal(t, "2m", ca.EARMaxAge)
	require.Equal(t, "/certs/server.crt", ca.ClientCertPath)
	require.Len(t, ca.Verifier, 1)
	require.Equal(t, &credentialacquisition.VerifierConfig{
		VerifierKind: "veraison", URL: "https://localhost:8443", CAPath: "/certs/veraison-ca.crt", EARKeyPath: "/keys/veraison.ear.jwk",
		Provider: "sev_guest", Submods: []string{"SEVSNP"},
	}, ca.Verifier["veraison"])
	require.Len(t, ca.Target, 1)
	require.Equal(t, &credentialacquisition.TargetConfig{
		Mode: "enroll", CredentialTypes: []constants.CredentialType{"x509"}, FreshnessKind: "present-nonce", ExpiresIn: "5m",
		Verifiers: []string{"veraison"}, AcceptableCSK: []string{"ecdsa-p256-sha256"}, Measurements: []string{"a0a1a2"},
	}, ca.Target["spiffe://example.org"])
	require.Equal(t, &credentialacquisition.SecretVaultConfig{SecretVaultKind: "json", URL: "https://localhost:9102", CAPath: "/certs/root.crt",
		ClientCertPath: "/certs/conduit.crt", ClientKeyPath: "/certs/conduit.key"}, ca.SecretVault)
	require.Equal(t, "/rules/platform.json", ca.PlatformRulePath)
	require.Equal(t, "/rules/sevsnp-products.json", ca.SEVSNPProductsPath)

	policies, err := ca.Validate()
	require.NoError(t, err)
	require.Contains(t, policies, "spiffe://example.org")
}

// SPIRE Server mints the X509-SVID with its own CA: it refuses the settings of
// the plug-in for a host that has no CA of its own.
func TestCredentialAcquisitionRefusesCredentialAuthority(t *testing.T) {
	const target = "spiffe://example.org"
	const refused = `credential_acquisition: Target "spiffe://example.org": certificate_name and certificate_validity do not apply: SPIRE Server mints with its own CA`
	for _, tt := range []struct {
		name   string
		change func(*credentialacquisition.Config)
		expect string
	}{
		{
			name:   "none of them",
			change: func(*credentialacquisition.Config) {},
		},
		{
			name: "a Credential Authority",
			change: func(c *credentialacquisition.Config) {
				c.CredentialAuthority = &credentialacquisition.CredentialAuthorityConfig{
					URL: "https://ca.example.org", Provisioner: "tacra", ProvisionerKeyPath: "/keys/provisioner.jwk",
				}
				c.Target[target].CertificateName = "workload.example.org"
			},
			expect: "credential_acquisition: credential_authority does not apply: SPIRE Server mints with its own CA",
		},
		{
			name:   "the name of a certificate",
			change: func(c *credentialacquisition.Config) { c.Target[target].CertificateName = "workload.example.org" },
			expect: refused,
		},
		{
			name:   "the validity of a certificate",
			change: func(c *credentialacquisition.Config) { c.Target[target].CertificateValidity = "1h" },
			expect: refused,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := defaultValidConfig()
			c.Server.Experimental.CredentialAcquisition = &credentialacquisition.Config{
				AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"},
				Verifier: map[string]*credentialacquisition.VerifierConfig{"veraison": {
					URL: "https://localhost:8443", EARKeyPath: "/keys/veraison.ear.jwk", Provider: "sev_guest", Submods: []string{"SEVSNP"},
				}},
				Target: map[string]*credentialacquisition.TargetConfig{target: {
					Mode: "enroll", Verifiers: []string{"veraison"}, Measurements: []string{"a0a1a2"},
				}},
			}
			tt.change(c.Server.Experimental.CredentialAcquisition)

			sc, err := NewServerConfig(c, nil, false)
			if tt.expect != "" {
				require.EqualError(t, err, tt.expect)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, sc.CredentialAcquisition)
		})
	}
}
