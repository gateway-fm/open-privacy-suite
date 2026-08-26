package redis

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"privacy-proxy/internal/auth"

	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RD-1242: the Redis store is the one used in multi-replica deployments, so the
// failure state has to round-trip through JSON here exactly as it does in the
// in-memory store. Missing this path would leave the bug live precisely where
// it matters most.

func TestSessionStore_FailSession(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, sessionID)

	require.NoError(t, store.FailSession(sessionID, "verification_failed"))

	session := store.GetSession(sessionID)
	require.NotNil(t, session, "a failed session must stay readable so the poller can see why")
	assert.True(t, session.Failed)
	assert.Equal(t, "verification_failed", session.FailureReason)
	assert.False(t, session.Completed)
	assert.False(t, session.FailedAt.IsZero())
	assert.Empty(t, session.AccessToken)
}

func TestSessionStore_FailSession_NotFound(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	assert.Error(t, store.FailSession("no-such-session", "verification_failed"))
}

// Failing a session must not extend its lifetime: a session with no tokens
// should expire on its original schedule.
func TestSessionStore_FailSession_PreservesTTL(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, sessionID)

	ctx := context.Background()
	before, err := client.TTL(ctx, sessionKeyPrefix+sessionID).Result()
	require.NoError(t, err)

	require.NoError(t, store.FailSession(sessionID, "verification_failed"))

	after, err := client.TTL(ctx, sessionKeyPrefix+sessionID).Result()
	require.NoError(t, err)
	assert.InDelta(t, before.Seconds(), after.Seconds(), 5.0,
		"FailSession must keep the original TTL, not extend or reset it")
}

// A wallet retry after a transient failure must still be able to complete.
func TestSessionStore_CompleteAfterFailClearsFailure(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, sessionID)

	require.NoError(t, store.FailSession(sessionID, "internal_error"))
	require.NoError(t, store.CompleteSession(sessionID, "access-token-123", "refresh-token-456"))

	session := store.GetSession(sessionID)
	require.NotNil(t, session)
	assert.True(t, session.Completed)
	assert.False(t, session.Failed, "a successful retry must clear the recorded failure")
	assert.Empty(t, session.FailureReason)
	assert.Equal(t, "access-token-123", session.AccessToken)
}

func TestSessionStore_ListSessions_ReportsFailure(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, sessionID)
	require.NoError(t, store.FailSession(sessionID, "verification_failed"))

	infos := store.ListSessions()
	require.Len(t, infos, 1)
	assert.True(t, infos[0].Failed)
	assert.Equal(t, "verification_failed", infos[0].FailureReason)
}

// A late failure must never erase an already-completed login.
func TestSessionStore_FailAfterCompleteIsIgnored(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, sessionID)

	require.NoError(t, store.CompleteSession(sessionID, "access-token-123", "refresh-token-456"))
	require.NoError(t, store.FailSession(sessionID, "verification_failed"))

	session := store.GetSession(sessionID)
	require.NotNil(t, session)
	assert.True(t, session.Completed, "a late failure erased a successful login")
	assert.False(t, session.Failed)
	assert.Equal(t, "access-token-123", session.AccessToken, "tokens were lost")
}

// The CAS must drop a failure whose read is stale, which is the lost-update the
// pre-write Go check alone cannot close: simulate it by completing the session
// after the failure path has already read the pending JSON.
func TestSessionStore_FailSession_CASDropsStaleWrite(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)
	ctx := context.Background()

	sessionID := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, sessionID)
	key := sessionKeyPrefix + sessionID

	// What a concurrent FailSession would have read before the completion.
	stale, err := client.Get(ctx, key).Bytes()
	require.NoError(t, err)

	require.NoError(t, store.CompleteSession(sessionID, "access-token-123", "refresh-token-456"))

	// Replay the stale write directly against the script, as a racing
	// FailSession would: it must be refused rather than clobber the tokens.
	var session auth.Session
	require.NoError(t, json.Unmarshal(stale, &session))
	session.Failed = true
	session.FailureReason = "verification_failed"
	session.FailedAt = time.Now()
	updated, err := json.Marshal(&session)
	require.NoError(t, err)

	result, err := failSessionScript.Run(ctx, client, []string{key},
		string(stale), string(updated),
	).Int()
	require.NoError(t, err)
	assert.Equal(t, -1, result, "a stale CAS write must be refused")

	after := store.GetSession(sessionID)
	require.NotNil(t, after)
	assert.True(t, after.Completed, "the completed login survived")
	assert.Equal(t, "access-token-123", after.AccessToken)
	assert.False(t, after.Failed)
}
