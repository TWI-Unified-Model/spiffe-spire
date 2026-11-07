package run

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spiffe/spire/pkg/server/credentialacquisition"
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
		Mode: "enroll", CredentialTypes: []credentialacquisition.CredentialType{"x509"}, FreshnessKind: "present-nonce", ExpiresIn: "5m",
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
