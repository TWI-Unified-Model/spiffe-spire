package credentialacquisition

import (
	"testing"
	"time"

	"github.com/TWI-Unified-Model/tacra/constants"
	"github.com/stretchr/testify/require"
)

func validConfig() *Config {
	return &Config{
		Target: map[string]*TargetConfig{
			"spiffe://example.org": {
				Mode:         constants.CredentialAcquisitionModeEnroll,
				Verifiers:    []string{"veraison"},
				Measurements: []string{"a0a1a2"},
			},
		},
		Verifier: map[string]*VerifierConfig{
			"veraison": {URL: "https://veraison.example", EARKeyPath: "/keys/veraison.jwk", Provider: "sev_guest", Submods: []string{"SEVSNP"}},
		},
		AcceptableEvidence: []string{"application/vnd.veraison.tsm-report+cbor"},
	}
}

func TestConfigValidate(t *testing.T) {
	t.Run("defaults of an enroll Target", func(t *testing.T) {
		policies, err := validConfig().Validate()
		require.NoError(t, err)
		p := policies["spiffe://example.org"]
		require.Equal(t, constants.CredentialAcquisitionModeEnroll, p.Mode)
		require.Equal(t, []constants.CredentialType{constants.CredentialTypeX509}, p.CredentialTypes)
		require.Equal(t, constants.FreshnessKindPresentNonce, p.FreshnessKind)
		require.Equal(t, 5*time.Minute, p.ExpiresIn)
		require.Equal(t, []string{"ecdsa-p256-sha256"}, p.AcceptableCSK)
		require.Equal(t, [][]byte{{0xa0, 0xa1, 0xa2}}, p.Measurements)
	})

	for _, tt := range []struct {
		name   string
		mutate func(c *Config)
		err    string
	}{
		{name: "no Target", mutate: func(c *Config) { c.Target = nil }, err: "at least one Target is required"},
		{name: "no acceptable_evidence", mutate: func(c *Config) { c.AcceptableEvidence = nil }, err: "acceptable_evidence is required"},
		{name: "no mode", mutate: func(c *Config) { c.Target["spiffe://example.org"].Mode = "" }, err: "mode is required"},
		{name: "bad mode", mutate: func(c *Config) { c.Target["spiffe://example.org"].Mode = "mint" }, err: `mode "mint" is not enroll or retrieve`},
		{name: "Credential Type not enrollable", mutate: func(c *Config) { c.Target["spiffe://example.org"].CredentialTypes = []constants.CredentialType{"jwt"} }, err: `Credential Type "jwt" cannot be enrolled`},
		{name: "Freshness Kind not supported", mutate: func(c *Config) { c.Target["spiffe://example.org"].FreshnessKind = "absent-none" }, err: `freshness_kind "absent-none" is not supported`},
		{name: "csk not supported", mutate: func(c *Config) { c.Target["spiffe://example.org"].AcceptableCSK = []string{"rsa-2048-sha256"} }, err: `acceptable_csk "rsa-2048-sha256" is not supported`},
		{name: "no verifiers", mutate: func(c *Config) { c.Target["spiffe://example.org"].Verifiers = nil }, err: "at least one Verifier must be configured"},
		{name: "Verifier not configured", mutate: func(c *Config) { c.Target["spiffe://example.org"].Verifiers = []string{"tdx"} }, err: `Verifier "tdx" is not configured`},
		{name: "measurement not hex", mutate: func(c *Config) { c.Target["spiffe://example.org"].Measurements = []string{"zz"} }, err: `measurement "zz" is not hex`},
		{name: "measurements required", mutate: func(c *Config) { c.Target["spiffe://example.org"].Measurements = nil }, err: "measurements is required, or allow_any_measurement"},
		{name: "expires_in too short", mutate: func(c *Config) { c.Target["spiffe://example.org"].ExpiresIn = "30s" }, err: "is below the minimum of 1m0s"},
		{name: "expires_in malformed", mutate: func(c *Config) { c.Target["spiffe://example.org"].ExpiresIn = "soon" }, err: "expires_in"},
		{name: "retrieve needs a Secret Vault", mutate: func(c *Config) { c.Target["spiffe://example.org"].Mode = constants.CredentialAcquisitionModeRetrieve }, err: "retrieve mode needs a secret_vault"},
		{name: "retrieve passport needs verifiers", mutate: func(c *Config) {
			c.SecretVault = &SecretVaultConfig{URL: "https://vault.example"}
			c.Target["spiffe://example.org"].Mode = constants.CredentialAcquisitionModeRetrieve
			c.Target["spiffe://example.org"].RATSModel = constants.RATSModelPassport
			c.Target["spiffe://example.org"].Verifiers = nil
		}, err: "the Passport RATS model requires one or more Verifiers"},
		{name: "retrieve passport Verifier not configured", mutate: func(c *Config) {
			c.SecretVault = &SecretVaultConfig{URL: "https://vault.example"}
			c.Target["spiffe://example.org"].Mode = constants.CredentialAcquisitionModeRetrieve
			c.Target["spiffe://example.org"].RATSModel = constants.RATSModelPassport
			c.Target["spiffe://example.org"].Verifiers = []string{"tdx"}
		}, err: `Verifier "tdx" is not configured`},
		{name: "retrieve rats_model unknown", mutate: func(c *Config) {
			c.SecretVault = &SecretVaultConfig{URL: "https://vault.example"}
			c.Target["spiffe://example.org"].Mode = constants.CredentialAcquisitionModeRetrieve
			c.Target["spiffe://example.org"].RATSModel = "oracle"
		}, err: `rats_model "oracle" is not passport or background-check`},
		{name: "a Credential Type not defined by TACRA", mutate: func(c *Config) {
			c.SecretVault = &SecretVaultConfig{URL: "https://vault.example"}
			c.Target["spiffe://example.org"].Mode = constants.CredentialAcquisitionModeRetrieve
			c.Target["spiffe://example.org"].CredentialTypes = []constants.CredentialType{"password"}
		}, err: `Credential Type "password" is not defined by TACRA`},
		{name: "Verifier without key", mutate: func(c *Config) { c.Verifier["veraison"].EARKeyPath = "" }, err: "ear_key_path is required"},
		{name: "Verifier without provider", mutate: func(c *Config) { c.Verifier["veraison"].Provider = "" }, err: "provider is required"},
		{name: "Verifier of an unknown kind", mutate: func(c *Config) { c.Verifier["veraison"].VerifierKind = "attestify" }, err: `kind "attestify" is not one of veraison`},
		{name: "Verifier with a submodule of no family", mutate: func(c *Config) { c.Verifier["veraison"].Submods = []string{"CCA"} }, err: `submods: "CCA" is not an EAR submodule`},
		{name: "vault of an unknown kind", mutate: func(c *Config) {
			c.SecretVault = &SecretVaultConfig{SecretVaultKind: "grpc", URL: "https://vault.example"}
		}, err: `secret_vault: kind "grpc" is not one of json`},
		{name: "vault without url", mutate: func(c *Config) { c.SecretVault = &SecretVaultConfig{} }, err: "secret_vault: url is required"},
		{name: "ear_max_age malformed", mutate: func(c *Config) { c.EARMaxAge = "later" }, err: "ear_max_age"},
		// A duration without its unit is refused when the configuration is read, so that minutes and seconds cannot be confused.
		{name: "ear_max_age without a unit", mutate: func(c *Config) { c.EARMaxAge = "120" }, err: `ear_max_age: time: missing unit in duration "120"`},
		{name: "ear_skew without a unit", mutate: func(c *Config) { c.EARSkew = "5" }, err: `ear_skew: time: missing unit in duration "5"`},
		{name: "expires_in without a unit", mutate: func(c *Config) { c.Target["spiffe://example.org"].ExpiresIn = "300" }, err: `expires_in: time: missing unit in duration "300"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := validConfig()
			tt.mutate(c)
			_, err := c.Validate()
			require.ErrorContains(t, err, tt.err)
		})
	}

	t.Run("allow_any_measurement for bring-up", func(t *testing.T) {
		c := validConfig()
		c.Target["spiffe://example.org"].Measurements = nil
		c.Target["spiffe://example.org"].AllowAnyMeasurement = true
		policies, err := c.Validate()
		require.NoError(t, err)
		require.True(t, policies["spiffe://example.org"].AllowAnyMeasurement)
	})

	t.Run("a retrieve Target", func(t *testing.T) {
		c := validConfig()
		c.SecretVault = &SecretVaultConfig{URL: "https://vault.example"}
		c.Target["https://api.example"] = &TargetConfig{Mode: constants.CredentialAcquisitionModeRetrieve, CredentialTypes: []constants.CredentialType{"jwt", "api-key"}}
		policies, err := c.Validate()
		require.NoError(t, err)
		p := policies["https://api.example"]
		require.Equal(t, constants.CredentialAcquisitionModeRetrieve, p.Mode)
		require.Equal(t, constants.FreshnessKindPresentNonce, p.FreshnessKind)
		require.Equal(t, 5*time.Minute, p.ExpiresIn)
		require.Equal(t, constants.RATSModelBackgroundCheck, p.RATSModel)
	})

	t.Run("a retrieve Target in passport", func(t *testing.T) {
		c := validConfig()
		c.SecretVault = &SecretVaultConfig{URL: "https://vault.example"}
		c.Target["https://api.example"] = &TargetConfig{Mode: constants.CredentialAcquisitionModeRetrieve, RATSModel: constants.RATSModelPassport, Verifiers: []string{"veraison"}}
		policies, err := c.Validate()
		require.NoError(t, err)
		require.Equal(t, constants.RATSModelPassport, policies["https://api.example"].RATSModel)
	})
}
