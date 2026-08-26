package auth

import (
	"testing"
	"time"

	"github.com/iden3/iden3comm/v2/protocol"
)

// RD-1242: a rejected wallet proof must be recorded on the session, otherwise
// the browser (a different HTTP client from the wallet) polls a session that
// stays pending forever and eventually reports a misleading timeout.

func TestSessionStore_FailSession(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	id := store.CreateSession(&protocol.AuthorizationRequestMessage{ID: "req"})
	if id == "" {
		t.Fatal("CreateSession() returned empty ID")
	}

	if err := store.FailSession(id, "verification_failed"); err != nil {
		t.Fatalf("FailSession() error = %v", err)
	}

	session := store.GetSession(id)
	if session == nil {
		t.Fatal("GetSession() = nil after FailSession; a failed session must stay readable so the poller can see why")
	}
	if !session.Failed {
		t.Error("session.Failed = false, want true")
	}
	if session.FailureReason != "verification_failed" {
		t.Errorf("session.FailureReason = %q, want %q", session.FailureReason, "verification_failed")
	}
	if session.Completed {
		t.Error("session.Completed = true on a failed session, want false")
	}
	if session.FailedAt.IsZero() {
		t.Error("session.FailedAt is zero, want a timestamp")
	}
}

func TestSessionStore_FailSession_NotFound(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	if err := store.FailSession("no-such-session", "verification_failed"); err == nil {
		t.Error("FailSession() on an unknown session = nil error, want an error")
	}
}

// A wallet may retry after a transient failure (e.g. a 500 while persisting the
// refresh token). Recording a failure must not wedge the session permanently.
func TestSessionStore_CompleteAfterFailClearsFailure(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	id := store.CreateSession(&protocol.AuthorizationRequestMessage{ID: "req"})
	if err := store.FailSession(id, "internal_error"); err != nil {
		t.Fatalf("FailSession() error = %v", err)
	}
	if err := store.CompleteSession(id, "access", "refresh"); err != nil {
		t.Fatalf("CompleteSession() error = %v", err)
	}

	session := store.GetSession(id)
	if session == nil {
		t.Fatal("GetSession() = nil")
	}
	if !session.Completed {
		t.Error("session.Completed = false after a retry succeeded, want true")
	}
	if session.Failed {
		t.Error("session.Failed = true after a successful retry, want false")
	}
	if session.FailureReason != "" {
		t.Errorf("session.FailureReason = %q after a successful retry, want empty", session.FailureReason)
	}
	if session.AccessToken != "access" {
		t.Errorf("session.AccessToken = %q, want %q", session.AccessToken, "access")
	}
}

func TestSessionStore_ListSessions_ReportsFailure(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	id := store.CreateSession(&protocol.AuthorizationRequestMessage{ID: "req"})
	if err := store.FailSession(id, "verification_failed"); err != nil {
		t.Fatalf("FailSession() error = %v", err)
	}

	infos := store.ListSessions()
	if len(infos) != 1 {
		t.Fatalf("ListSessions() returned %d sessions, want 1", len(infos))
	}
	if !infos[0].Failed {
		t.Error("SessionInfo.Failed = false, want true")
	}
	if infos[0].FailureReason != "verification_failed" {
		t.Errorf("SessionInfo.FailureReason = %q, want %q", infos[0].FailureReason, "verification_failed")
	}
}

// A late failure must never erase an already-completed login. Two callbacks can
// race for the same session (a wallet retry against the original attempt).
func TestSessionStore_FailAfterCompleteIsIgnored(t *testing.T) {
	store := NewSessionStore(10*time.Minute, 1*time.Hour)
	defer store.Stop()

	id := store.CreateSession(&protocol.AuthorizationRequestMessage{ID: "req"})
	if err := store.CompleteSession(id, "access", "refresh"); err != nil {
		t.Fatalf("CompleteSession() error = %v", err)
	}
	if err := store.FailSession(id, "verification_failed"); err != nil {
		t.Fatalf("FailSession() error = %v", err)
	}

	session := store.GetSession(id)
	if session == nil {
		t.Fatal("GetSession() = nil")
	}
	if !session.Completed {
		t.Error("session.Completed = false; a late failure erased a successful login")
	}
	if session.Failed {
		t.Error("session.Failed = true on a completed session, want false")
	}
	if session.AccessToken != "access" {
		t.Errorf("session.AccessToken = %q, want %q; tokens were lost", session.AccessToken, "access")
	}
}
