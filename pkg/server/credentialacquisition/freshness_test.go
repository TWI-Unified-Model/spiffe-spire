package credentialacquisition

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSessionsMintAndTake(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s := newSessions(clock)

	ss := session{kind: FreshnessPresentNonce, target: "spiffe://example.org", credentialType: "x509", hint: "internal",
		mode: ModeEnroll, entryID: "entry-1", agentID: "spiffe://example.org/agent", expires: now.Add(5 * time.Minute)}
	handle, err := s.mint(ss)
	require.NoError(t, err)
	require.Len(t, handle, handleSize)

	t.Run("a Handle never issued is unknown", func(t *testing.T) {
		_, err := s.take(make([]byte, 32), FreshnessPresentNonce, ss.target, "x509", "internal", "entry-1", ss.agentID)
		require.ErrorIs(t, err, ErrUnknownHandle)
	})
	t.Run("another Target is not correlated", func(t *testing.T) {
		_, err := s.take(handle, FreshnessPresentNonce, "https://other.example", "x509", "internal", "entry-1", ss.agentID)
		require.ErrorIs(t, err, ErrNotCorrelated)
	})
	t.Run("another Freshness Kind is not correlated", func(t *testing.T) {
		_, err := s.take(handle, FreshnessPresentEpoch, ss.target, "x509", "internal", "entry-1", ss.agentID)
		require.ErrorIs(t, err, ErrNotCorrelated)
	})
	t.Run("another workload is not correlated", func(t *testing.T) {
		_, err := s.take(handle, FreshnessPresentNonce, ss.target, "x509", "internal", "entry-2", ss.agentID)
		require.ErrorIs(t, err, ErrNotCorrelated)
	})
	t.Run("another agent is not correlated", func(t *testing.T) {
		_, err := s.take(handle, FreshnessPresentNonce, ss.target, "x509", "internal", "entry-1", "spiffe://example.org/other-agent")
		require.ErrorIs(t, err, ErrNotCorrelated)
	})
	t.Run("a Credential Type named at initiation must be repeated", func(t *testing.T) {
		_, err := s.take(handle, FreshnessPresentNonce, ss.target, "wic", "internal", "entry-1", ss.agentID)
		require.ErrorIs(t, err, ErrNotCorrelated)
		_, err = s.take(handle, FreshnessPresentNonce, ss.target, "", "internal", "entry-1", ss.agentID)
		require.ErrorIs(t, err, ErrNotCorrelated)
	})
	t.Run("a Credential Hint named at initiation must be repeated", func(t *testing.T) {
		_, err := s.take(handle, FreshnessPresentNonce, ss.target, "x509", "external", "entry-1", ss.agentID)
		require.ErrorIs(t, err, ErrNotCorrelated)
	})
	t.Run("the matching second call takes the Handle once", func(t *testing.T) {
		got, err := s.take(handle, FreshnessPresentNonce, ss.target, "x509", "internal", "entry-1", ss.agentID)
		require.NoError(t, err)
		require.Equal(t, ss, got)
		_, err = s.take(handle, FreshnessPresentNonce, ss.target, "x509", "internal", "entry-1", ss.agentID)
		require.ErrorIs(t, err, ErrUnknownHandle, "a present-nonce Handle is single use")
	})
}

func TestSessionsOmittedTypeAndHintMayBeNamed(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	s := newSessions(func() time.Time { return now })
	ss := session{kind: FreshnessPresentNonce, target: "spiffe://example.org", mode: ModeEnroll,
		entryID: "entry-1", agentID: "spiffe://example.org/agent", expires: now.Add(time.Minute)}
	handle, err := s.mint(ss)
	require.NoError(t, err)

	got, err := s.take(handle, FreshnessPresentNonce, ss.target, "x509", "internal", "entry-1", ss.agentID)
	require.NoError(t, err)
	require.Equal(t, ss, got)
}

func TestSessionsExpire(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	s := newSessions(func() time.Time { return now })
	ss := session{kind: FreshnessPresentNonce, target: "spiffe://example.org", mode: ModeEnroll,
		entryID: "entry-1", agentID: "spiffe://example.org/agent", expires: now.Add(time.Minute)}
	handle, err := s.mint(ss)
	require.NoError(t, err)

	now = now.Add(time.Minute + time.Second)
	_, err = s.take(handle, FreshnessPresentNonce, ss.target, "", "", "entry-1", ss.agentID)
	require.ErrorIs(t, err, ErrUnknownHandle)

	// a new initiation sweeps the expired session
	_, err = s.mint(ss)
	require.NoError(t, err)
	require.Len(t, s.byID, 1)
}

func TestSessionsRememberReplacesTheSameInitiation(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	s := newSessions(func() time.Time { return now })
	handle := []byte("0123456789abcdef0123456789abcdef")
	ss := session{kind: FreshnessPresentNonce, target: "https://vault.example", mode: ModeRetrieve,
		entryID: "entry-1", agentID: "spiffe://example.org/agent", expires: now.Add(time.Minute)}
	s.remember(handle, ss)
	s.remember(handle, ss)
	require.Len(t, s.byID[string(hexKey(handle))], 1)
}
