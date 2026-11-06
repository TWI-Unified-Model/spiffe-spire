package credentialacquisition

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// Refusals of the appraisal.
var (
	ErrNoVerifier          = errors.New("the policy for the Target specifies no Verifier for Evidence of this provider")
	ErrVerifierUnavailable = errors.New("the Verifier is unavailable")
	ErrNoResults           = errors.New("the Verifier produced no Attestation Results")
)

// A verifierKind is one kind of RATS Verifier this Server works with: how the
// Server sends it Evidence and obtains its Attestation Results, and how it
// verifies and reads them. The configuration names the kind of each Verifier;
// the kinds are listed in verifierKinds, and another kind is a new type there.
// The rest of the Server sees a verifierClient.
type verifierKind interface {
	// Name is the kind as the configuration spells it.
	Name() string
	// Validate checks the configuration of a Verifier of the kind; the caller
	// names the Verifier.
	Validate(c *VerifierConfig) error
	// New builds a Verifier of the kind from its configuration, with the TLS
	// configuration the Server calls it with and the window its Attestation
	// Results are accepted in.
	New(name string, c *VerifierConfig, tc *tls.Config, window resultsWindow) (verifierClient, error)
}

// A verifierClient is one configured Verifier.
type verifierClient interface {
	// Name is the name of the Verifier in the configuration.
	Name() string
	// Kind is the kind of the Verifier.
	Kind() string
	// Provider is the TSM report provider of the Evidence the Verifier
	// appraises.
	Provider() string
	// Appraise sends the Evidence, with the binding value as the nonce, and
	// returns the Attestation Results as the Verifier issued them, not yet
	// verified.
	Appraise(ctx context.Context, evidence []byte, mediaType string, nonce []byte) (string, error)
	// Verify checks Attestation Results this Verifier returned: that they are
	// its own, in the accepted time window, for the expected nonce and
	// affirming; and reads them.
	Verify(results string, expectedNonce []byte) (*attestationResults, error)
}

// resultsWindow is when Attestation Results are accepted: issued no longer
// than maxAge ago and no further than skew in the future.
type resultsWindow struct {
	maxAge time.Duration
	skew   time.Duration
	now    func() time.Time
}

// verifierKinds lists the kinds: veraison, the one kind for now.
var verifierKinds = []verifierKind{veraisonKind{}}

// defaultVerifierKind is the kind of a Verifier whose configuration names
// none.
const defaultVerifierKind = "veraison"

func verifierKindNamed(name string) (verifierKind, bool) {
	if name == "" {
		name = defaultVerifierKind
	}
	i := slices.IndexFunc(verifierKinds, func(k verifierKind) bool { return k.Name() == name })
	if i < 0 {
		return nil, false
	}
	return verifierKinds[i], true
}

func verifierKindNames() string {
	names := make([]string, 0, len(verifierKinds))
	for _, k := range verifierKinds {
		names = append(names, k.Name())
	}
	return strings.Join(names, ", ")
}

// newVerifiers builds the configured Verifiers, each by its kind.
func newVerifiers(c *Config, window resultsWindow) (map[string]verifierClient, error) {
	verifiers := make(map[string]verifierClient, len(c.Verifier))
	for name, v := range c.Verifier {
		kind, ok := verifierKindNamed(v.Kind)
		if !ok {
			return nil, fmt.Errorf("configuring Verifier %q: kind %q is not one of %s", name, v.Kind, verifierKindNames())
		}
		tc, err := clientTLS(v.CAPath, c.ClientCertPath, c.ClientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("configuring Verifier %q: %w", name, err)
		}
		client, err := kind.New(name, v, tc, window)
		if err != nil {
			return nil, fmt.Errorf("configuring Verifier %q: %w", name, err)
		}
		verifiers[name] = client
	}
	return verifiers, nil
}

// route picks, among the Verifiers specified by the policy for the Target, the
// one for the TSM report provider of the Evidence. The policy chooses the
// Verifier; the Evidence only picks among those, and there is no default for
// the rest. The Verifiers are tried in the order of their names.
func route(verifiers map[string]verifierClient, evidence []byte, accept []string) (verifierClient, error) {
	var t struct {
		Provider string `cbor:"provider"`
	}
	provider := ""
	if cbor.Unmarshal(evidence, &t) == nil {
		provider = strings.TrimSpace(t.Provider)
	}
	for _, name := range slices.Sorted(maps.Keys(verifiers)) {
		v := verifiers[name]
		if slices.Contains(accept, name) && v.Provider() != "" && v.Provider() == provider {
			return v, nil
		}
	}
	return nil, fmt.Errorf("%w: provider %q, Verifiers %v", ErrNoVerifier, provider, accept)
}
