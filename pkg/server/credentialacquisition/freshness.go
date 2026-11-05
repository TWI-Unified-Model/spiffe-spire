package credentialacquisition

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// handleSize is the size of a present-nonce Handle this Server mints: 32
// octets, within the 16 to 64 octets of TACRA, with 256 bits of entropy.
const handleSize = 32

// session is one Initiate-Credential-Acquisition whose Handle is still valid:
// what the second call must repeat, and the Workload and Agent it belongs to.
type session struct {
	kind           string
	target         string
	credentialType string
	hint           string
	mode           string
	entryID        string
	agentID        string
	expires        time.Time
}

// Refusals of the second call of an exchange.
var (
	ErrUnknownHandle = errors.New("no initiation returned this Handle, or it expired")
	ErrNotCorrelated = errors.New("the Target, the Freshness Kind, the Workload or the Agent differ from the initiation, or a Credential Type or Credential Hint it named is not repeated")
)

// sessions keeps the sessions by Handle, and forgets the expired ones.
type sessions struct {
	mu   sync.Mutex
	byID map[string][]session
	now  func() time.Time
}

func newSessions(now func() time.Time) *sessions {
	return &sessions{byID: make(map[string][]session), now: now}
}

// mint issues a present-nonce Handle for the session.
func (s *sessions) mint(ss session) ([]byte, error) {
	handle := make([]byte, handleSize)
	if _, err := rand.Read(handle); err != nil {
		return nil, fmt.Errorf("mint Freshness Handle: %w", err)
	}
	s.remember(handle, ss)
	return handle, nil
}

// remember keeps the session under its Handle, in place of an earlier one
// for the same Target, Credential Type, kind, Workload and Agent, and forgets
// every expired session.
func (s *sessions) remember(handle []byte, ss session) {
	key := hex.EncodeToString(handle)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for k, list := range s.byID {
		live := list[:0]
		for _, x := range list {
			if now.After(x.expires) {
				continue
			}
			if k == key && x.target == ss.target && x.credentialType == ss.credentialType && x.hint == ss.hint &&
				x.kind == ss.kind && x.entryID == ss.entryID && x.agentID == ss.agentID {
				continue
			}
			live = append(live, x)
		}
		if len(live) == 0 {
			delete(s.byID, k)
		} else {
			s.byID[k] = live
		}
	}
	s.byID[key] = append(s.byID[key], ss)
}

// take correlates the second call with the initiation that returned its
// Handle: the call must repeat the Target and the Freshness Kind of its
// initiation, and a Credential Type or Credential Hint the initiation named,
// while one it omitted may be named. This Server adds the registration entry
// of the Workload and its Agent: the exchange belongs to the Workload the
// Agent attested at initiation. A present-nonce Handle is taken once.
func (s *sessions) take(handle []byte, kind, target, credentialType, hint, entryID, agentID string) (session, error) {
	key := hex.EncodeToString(handle)
	s.mu.Lock()
	defer s.mu.Unlock()
	now, live, match := s.now(), 0, -1
	for i, ss := range s.byID[key] {
		if now.After(ss.expires) {
			continue
		}
		live++
		if ss.target != target || ss.kind != kind || ss.entryID != entryID || ss.agentID != agentID {
			continue
		}
		if (ss.credentialType != "" && ss.credentialType != credentialType) || (ss.hint != "" && ss.hint != hint) {
			continue
		}
		match = i
	}
	if live == 0 {
		return session{}, ErrUnknownHandle
	}
	if match < 0 {
		return session{}, ErrNotCorrelated
	}
	ss := s.byID[key][match]
	list := s.byID[key]
	s.byID[key] = append(list[:match:match], list[match+1:]...)
	if len(s.byID[key]) == 0 {
		delete(s.byID, key)
	}
	return ss, nil
}
