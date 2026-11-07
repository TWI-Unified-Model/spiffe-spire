package credentialacquisition

import (
	"context"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// mockVerifier speaks the challenge-response API of Veraison: it opens a session
// for the nonce of the request, receives the Evidence posted to it, and answers
// the Attestation Results its answer function signs for that nonce.
type mockVerifier struct {
	server  *httptest.Server
	mu      sync.Mutex
	answer  func(nonce []byte, evidence []byte, mediaType string) (status string, result string)
	refuse  bool
	deleted int
	nonces  [][]byte
}

func newMockVerifier(t *testing.T) *mockVerifier {
	f := &mockVerifier{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /challenge-response/v1/newSession", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.refuse {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		nonce, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.nonces = append(f.nonces, nonce)
		w.Header().Set("Location", "session/"+base64.RawURLEncoding.EncodeToString(nonce))
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("POST /challenge-response/v1/session/{id}", func(w http.ResponseWriter, r *http.Request) {
		nonce, err := base64.RawURLEncoding.DecodeString(r.PathValue("id"))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		evidence, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		answer := f.answer
		f.mu.Unlock()
		status, result := "failed", ""
		if answer != nil {
			status, result = answer(nonce, evidence, r.Header.Get("Content-Type"))
		}
		w.Header().Set("Content-Type", "application/vnd.veraison.challenge-response-session+json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": status, "result": result})
	})
	mux.HandleFunc("DELETE /challenge-response/v1/session/{id}", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.deleted++
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *mockVerifier) setAnswer(fn func(nonce, evidence []byte, mediaType string) (string, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = fn
}

// newTestVerifiers are two Veraison Verifiers: veraison, for sev_guest
// Evidence, behind the mock; tdx, for tdx_guest Evidence, at an address
// nothing answers on.
func newTestVerifiers(f *mockVerifier, key *ecdsa.PublicKey, window resultsWindow) map[string]verifierClient {
	return map[string]verifierClient{
		"veraison": &veraisonVerifier{name: "veraison", provider: "sev_guest", url: f.server.URL, client: f.server.Client(),
			key: key, submods: []string{"SEVSNP"}, window: window},
		"tdx": &veraisonVerifier{name: "tdx", provider: "tdx_guest", url: "http://127.0.0.1:1", client: f.server.Client(),
			key: key, submods: []string{"TDX"}, window: window},
	}
}

func TestRoute(t *testing.T) {
	f := newMockVerifier(t)
	verifiers := newTestVerifiers(f, nil, resultsWindow{})
	evidence := testEvidence(t, "sev_guest")

	t.Run("the Verifier the policy names for the provider of the Evidence", func(t *testing.T) {
		v, err := route(verifiers, evidence, []string{"veraison", "tdx"})
		require.NoError(t, err)
		require.Equal(t, "veraison", v.Name())
		require.Equal(t, "veraison", v.Kind())
	})
	t.Run("a Verifier the policy does not name receives nothing", func(t *testing.T) {
		_, err := route(verifiers, evidence, []string{"tdx"})
		require.ErrorIs(t, err, ErrNoVerifier)
	})
	t.Run("Evidence of an unknown provider has no Verifier", func(t *testing.T) {
		_, err := route(verifiers, testEvidence(t, "other"), []string{"veraison"})
		require.ErrorIs(t, err, ErrNoVerifier)
	})
}

func TestVeraisonAppraise(t *testing.T) {
	f := newMockVerifier(t)
	verifiers := newTestVerifiers(f, nil, resultsWindow{})
	v := verifiers["veraison"]
	nonce := []byte("binding value")
	evidence := testEvidence(t, "sev_guest")

	t.Run("the Evidence goes to the Verifier with the binding value as the nonce of the challenge", func(t *testing.T) {
		f.setAnswer(func(gotNonce, gotEvidence []byte, mediaType string) (string, string) {
			require.Equal(t, nonce, gotNonce)
			require.Equal(t, evidence, gotEvidence)
			require.Equal(t, testProfile, mediaType)
			return "complete", "the.ear.jws"
		})
		results, err := v.Appraise(context.Background(), evidence, testProfile, nonce)
		require.NoError(t, err)
		require.Equal(t, "the.ear.jws", results)
		require.Equal(t, 1, f.deleted, "the session is deleted after use")
	})
	t.Run("no results is a refusal", func(t *testing.T) {
		f.setAnswer(func([]byte, []byte, string) (string, string) { return "failed", "" })
		_, err := v.Appraise(context.Background(), evidence, testProfile, nonce)
		require.ErrorIs(t, err, ErrNoResults)
	})
	t.Run("a Verifier that refuses a session is unavailable", func(t *testing.T) {
		f.mu.Lock()
		f.refuse = true
		f.mu.Unlock()
		defer func() { f.mu.Lock(); f.refuse = false; f.mu.Unlock() }()
		_, err := v.Appraise(context.Background(), evidence, testProfile, nonce)
		require.ErrorIs(t, err, ErrVerifierUnavailable)
	})
	t.Run("a Verifier that is down is unavailable", func(t *testing.T) {
		_, err := verifiers["tdx"].Appraise(context.Background(), testEvidence(t, "tdx_guest"), testProfile, nonce)
		require.ErrorIs(t, err, ErrVerifierUnavailable)
	})
}

func TestVeraisonVerify(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	veraisonKey := newTestKey(t)
	otherKey := newTestKey(t)
	nonce := []byte("the binding value, 64 octets in production...................")
	comid := snpCoMID(t, gcpMilan())
	window := resultsWindow{maxAge: 2 * time.Minute, skew: 5 * time.Second, now: func() time.Time { return now }}
	v := &veraisonVerifier{name: "veraison", key: &veraisonKey.PublicKey, submods: []string{"SEVSNP"}, window: window}
	tdx := &veraisonVerifier{name: "tdx", key: &otherKey.PublicKey, submods: []string{"TDX"}, window: window}

	t.Run("affirming results signed by the key of the Verifier are accepted", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, nonce, now.Add(-10*time.Second), "SEVSNP", "affirming", comid)
		res, err := v.Verify(jws, nonce)
		require.NoError(t, err)
		require.Equal(t, "veraison", res.Verifier)
		require.Equal(t, familySEVSNP, res.Family)
		require.Equal(t, testMeasurement, res.Measurement)
		require.NotNil(t, res.SNP)
		require.Equal(t, uint64(0x30000), res.SNP.policy)
		require.Equal(t, classByChip, res.SNP.class)
		require.Equal(t, now.Add(-10*time.Second), res.IssuedAt.UTC())
		require.Equal(t, jws, res.Raw)
	})
	t.Run("results signed by another key are refused", func(t *testing.T) {
		jws := signEAR(t, otherKey, nonce, now, "SEVSNP", "affirming", comid)
		_, err := v.Verify(jws, nonce)
		require.ErrorIs(t, err, ErrEARSignature)
	})
	t.Run("results that name another profile are refused with both names", func(t *testing.T) {
		jws := signEARWithProfile(t, veraisonKey, nonce, now, "SEVSNP", "affirming", comid, "tag:example.com,2026:other")
		_, err := v.Verify(jws, nonce)
		require.ErrorIs(t, err, ErrEARProfile)
		require.ErrorContains(t, err, `eat_profile "tag:example.com,2026:other"; a Verifier of kind veraison issues "tag:github.com,2023:veraison/ear"`)
	})
	t.Run("stale results are refused", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, nonce, now.Add(-3*time.Minute), "SEVSNP", "affirming", comid)
		_, err := v.Verify(jws, nonce)
		require.ErrorIs(t, err, ErrEAROutsideWindow)
		jws = signEAR(t, veraisonKey, nonce, now.Add(time.Minute), "SEVSNP", "affirming", comid)
		_, err = v.Verify(jws, nonce)
		require.ErrorIs(t, err, ErrEAROutsideWindow)
	})
	t.Run("results for another nonce are refused", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, []byte("another nonce"), now, "SEVSNP", "affirming", comid)
		_, err := v.Verify(jws, nonce)
		require.ErrorIs(t, err, ErrEARNonce)
	})
	t.Run("results that are not affirming are refused", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, nonce, now, "SEVSNP", "contraindicated", comid)
		_, err := v.Verify(jws, nonce)
		require.ErrorIs(t, err, ErrEARNotAffirming)
	})
	t.Run("results without the submodule of the Verifier are refused", func(t *testing.T) {
		jws := signEAR(t, veraisonKey, nonce, now, "TDX", "affirming", comid)
		_, err := v.Verify(jws, nonce)
		require.ErrorIs(t, err, ErrEARNotAffirming)
	})
	t.Run("a malformed token is refused", func(t *testing.T) {
		_, err := v.Verify("not.a.jws", nonce)
		require.ErrorIs(t, err, ErrEARMalformed)
	})
	t.Run("results without an annotated measurement are accepted without one", func(t *testing.T) {
		h := gcpMilan()
		h.noMeasurement = true
		jws := signEAR(t, veraisonKey, nonce, now, "SEVSNP", "affirming", snpCoMID(t, h))
		res, err := v.Verify(jws, nonce)
		require.NoError(t, err)
		require.Nil(t, res.Measurement)
		require.Nil(t, res.SNP)
		require.ErrorContains(t, res.SNPErr, "no launch measurement")
	})
	t.Run("TDX results carry the MRTD and the TD attributes", func(t *testing.T) {
		mrtd := make([]byte, 48)
		for i := range mrtd {
			mrtd[i] = byte(0x10 + i)
		}
		jws := signEAR(t, otherKey, nonce, now, "TDX", "affirming", map[string]string{"mrtd": hex.EncodeToString(mrtd), "td_attributes": "0000000010000000"})
		res, err := tdx.Verify(jws, nonce)
		require.NoError(t, err)
		require.Equal(t, familyTDX, res.Family)
		require.Equal(t, mrtd, res.Measurement)
		require.Equal(t, "0000000010000000", res.TDX["td_attributes"])
	})
}

func TestVeraisonKindValidate(t *testing.T) {
	kind := veraisonKind{}
	ok := &VerifierConfig{URL: "https://veraison.example", EARKeyPath: "/keys/veraison.jwk", Provider: "sev_guest", Submods: []string{"SEVSNP"}}
	require.NoError(t, kind.Validate(ok))
	for _, tt := range []struct {
		name   string
		mutate func(c *VerifierConfig)
		err    string
	}{
		{name: "no url", mutate: func(c *VerifierConfig) { c.URL = "" }, err: "url is required"},
		{name: "no key", mutate: func(c *VerifierConfig) { c.EARKeyPath = "" }, err: "ear_key_path is required"},
		{name: "no submods", mutate: func(c *VerifierConfig) { c.Submods = nil }, err: "submods is required"},
		{name: "a submodule of no family", mutate: func(c *VerifierConfig) { c.Submods = []string{"CCA"} }, err: `"CCA" is not an EAR submodule of a platform family this Server knows (SEVSNP, TDX)`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := *ok
			c.Submods = append([]string(nil), ok.Submods...)
			tt.mutate(&c)
			require.ErrorContains(t, kind.Validate(&c), tt.err)
		})
	}
	_, found := verifierKindNamed("")
	require.True(t, found, "the default kind")
	_, found = verifierKindNamed("attestify")
	require.False(t, found)
	require.Equal(t, "veraison", verifierKindNames())
}
