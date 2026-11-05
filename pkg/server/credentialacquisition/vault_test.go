package credentialacquisition

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockVault answers the HTTP API of a TACRA Secret Vault.
type mockVault struct {
	server       *httptest.Server
	mu           sync.Mutex
	handle       []byte
	initiateErr  *vaultRefusal
	retrieveErr  *vaultRefusal
	lastInitiate map[string]string
	lastRetrieve vaultRetrieval
	container    string
}

func newMockVault(t *testing.T) *mockVault {
	f := &mockVault{handle: []byte("vault-handle-0123456789abcdef012"), container: `{"container":"hpke-base","enc":"...","ciphertext":"..."}`}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /tacra/v1/initiate", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastInitiate = map[string]string{}
		_ = json.NewDecoder(r.Body).Decode(&f.lastInitiate)
		if f.initiateErr != nil {
			writeRefusal(w, f.initiateErr)
			return
		}
		_ = json.NewEncoder(w).Encode(vaultInitiation{
			FreshnessKind: FreshnessPresentNonce,
			Handle:        base64.RawURLEncoding.EncodeToString(f.handle),
			ExpiresIn:     120,
			Mode:          ModeRetrieve,
			AcceptableCEK: []string{"DHKEM(P-256, HKDF-SHA256)+HKDF-SHA256+AES-256-GCM"},
		})
	})
	mux.HandleFunc("POST /tacra/v1/retrieve", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.lastRetrieve = vaultRetrieval{}
		_ = json.NewDecoder(r.Body).Decode(&f.lastRetrieve)
		if f.retrieveErr != nil {
			writeRefusal(w, f.retrieveErr)
			return
		}
		w.Header().Set("Content-Type", "application/est-attest-bundle+json")
		_, _ = w.Write([]byte(f.container))
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func writeRefusal(w http.ResponseWriter, e *vaultRefusal) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e.Code, "detail": e.Detail})
}

func newTestVaultClient(f *mockVault) *vaultClient {
	return &vaultClient{url: f.server.URL, client: f.server.Client()}
}

func TestVaultClient(t *testing.T) {
	f := newMockVault(t)
	v := newTestVaultClient(f)

	t.Run("initiate forwards the Target, the Credential Type and the Hint", func(t *testing.T) {
		vi, handle, err := v.initiate(context.Background(), "https://api.example", "jwt", "billing")
		require.NoError(t, err)
		require.Equal(t, f.handle, handle)
		require.Equal(t, ModeRetrieve, vi.Mode)
		require.Equal(t, 120, vi.ExpiresIn)
		require.Equal(t, map[string]string{"target": "https://api.example", "credential_type": "jwt", "credential_hint": "billing"}, f.lastInitiate)
	})
	t.Run("initiate omits what the Workload omitted", func(t *testing.T) {
		_, _, err := v.initiate(context.Background(), "https://api.example", "", "")
		require.NoError(t, err)
		require.Equal(t, map[string]string{"target": "https://api.example"}, f.lastInitiate)
	})
	t.Run("retrieve returns the container as the Secret Vault sent it", func(t *testing.T) {
		req := &vaultRetrieval{FreshnessKind: FreshnessPresentNonce, Target: "https://api.example", Handle: "aGFuZGxl", Evidence: "ZXY", CEKPub: "Y2Vr"}
		container, err := v.retrieve(context.Background(), req)
		require.NoError(t, err)
		require.JSONEq(t, f.container, string(container))
		require.Equal(t, *req, f.lastRetrieve)
	})
	t.Run("a refusal carries the status, code and detail of the Secret Vault", func(t *testing.T) {
		f.mu.Lock()
		f.retrieveErr = &vaultRefusal{Status: http.StatusUnprocessableEntity, Code: "unsupported-credential-type", Detail: "supported: api-key"}
		f.mu.Unlock()
		defer func() { f.mu.Lock(); f.retrieveErr = nil; f.mu.Unlock() }()
		_, err := v.retrieve(context.Background(), &vaultRetrieval{})
		var refusal *vaultRefusal
		require.True(t, errors.As(err, &refusal))
		require.Equal(t, http.StatusUnprocessableEntity, refusal.Status)
		require.Equal(t, "unsupported-credential-type", refusal.Code)
		require.Equal(t, "supported: api-key", refusal.Detail)
	})
	t.Run("a Secret Vault that is down is unavailable", func(t *testing.T) {
		down := &vaultClient{url: "http://127.0.0.1:1", client: http.DefaultClient}
		_, _, err := down.initiate(context.Background(), "https://api.example", "", "")
		require.ErrorIs(t, err, ErrVaultUnavailable)
	})
}
