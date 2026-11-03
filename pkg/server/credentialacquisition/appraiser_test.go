package credentialacquisition

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeVerifier speaks Veraison's challenge-response API: it opens a session
// for the nonce of the request, takes the Evidence posted to it, and answers
// the Attestation Results its answer function signs for that nonce.
type fakeVerifier struct {
	server  *httptest.Server
	mu      sync.Mutex
	answer  func(nonce []byte, evidence []byte, mediaType string) (status string, result string)
	refuse  bool
	deleted int
	nonces  [][]byte
}

func newFakeVerifier(t *testing.T) *fakeVerifier {
	f := &fakeVerifier{}
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

func (f *fakeVerifier) setAnswer(fn func(nonce, evidence []byte, mediaType string) (string, string)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answer = fn
}

func newTestAppraiser(f *fakeVerifier) *appraiser {
	return &appraiser{verifiers: []verifier{
		{name: "veraison", provider: "sev_guest", url: f.server.URL, client: f.server.Client()},
		{name: "tdx", provider: "tdx_guest", url: "http://127.0.0.1:1", client: f.server.Client()},
	}}
}

func TestAppraise(t *testing.T) {
	f := newFakeVerifier(t)
	a := newTestAppraiser(f)
	nonce := []byte("binding value")
	evidence := testEvidence(t, "sev_guest")

	t.Run("the verifier of the Evidence's provider is asked with the binding value as the nonce", func(t *testing.T) {
		f.setAnswer(func(gotNonce, gotEvidence []byte, mediaType string) (string, string) {
			require.Equal(t, nonce, gotNonce)
			require.Equal(t, evidence, gotEvidence)
			require.Equal(t, "application/vnd.veraison.tsm-report+cbor", mediaType)
			return "complete", "the.ear.jws"
		})
		ear, name, err := a.appraise(context.Background(), evidence, "application/vnd.veraison.tsm-report+cbor", nonce, []string{"veraison", "tdx"})
		require.NoError(t, err)
		require.Equal(t, "the.ear.jws", ear)
		require.Equal(t, "veraison", name)
		require.Equal(t, 1, f.deleted, "the session is deleted after use")
	})
	t.Run("a verifier the policy does not take is not asked", func(t *testing.T) {
		_, _, err := a.appraise(context.Background(), evidence, "application/vnd.veraison.tsm-report+cbor", nonce, []string{"tdx"})
		require.ErrorIs(t, err, ErrNoVerifier)
	})
	t.Run("Evidence of an unknown provider has no verifier", func(t *testing.T) {
		_, _, err := a.appraise(context.Background(), testEvidence(t, "other"), "application/vnd.veraison.tsm-report+cbor", nonce, []string{"veraison"})
		require.ErrorIs(t, err, ErrNoVerifier)
	})
	t.Run("no results is a refusal", func(t *testing.T) {
		f.setAnswer(func([]byte, []byte, string) (string, string) { return "failed", "" })
		_, _, err := a.appraise(context.Background(), evidence, "application/vnd.veraison.tsm-report+cbor", nonce, []string{"veraison"})
		require.ErrorIs(t, err, ErrNoResults)
	})
	t.Run("a verifier that refuses a session is unavailable", func(t *testing.T) {
		f.mu.Lock()
		f.refuse = true
		f.mu.Unlock()
		defer func() { f.mu.Lock(); f.refuse = false; f.mu.Unlock() }()
		_, _, err := a.appraise(context.Background(), evidence, "application/vnd.veraison.tsm-report+cbor", nonce, []string{"veraison"})
		require.ErrorIs(t, err, ErrVerifierUnavailable)
	})
	t.Run("a verifier that is down is unavailable", func(t *testing.T) {
		_, _, err := a.appraise(context.Background(), testEvidence(t, "tdx_guest"), "application/vnd.veraison.tsm-report+cbor", nonce, []string{"tdx"})
		require.ErrorIs(t, err, ErrVerifierUnavailable)
	})
	_ = strings.TrimSpace
}
