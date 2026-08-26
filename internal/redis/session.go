package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"privacy-proxy/internal/auth"

	"github.com/google/uuid"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/redis/go-redis/v9"
)

const (
	// sessionKeyPrefix is the Redis key prefix for auth sessions.
	sessionKeyPrefix = "pp:session:"

	// sessionCountKey is the Redis key for the atomic session counter.
	sessionCountKey = "pp:session:_count"

	// defaultSessionScanCount is the COUNT hint for SCAN operations.
	defaultSessionScanCount = 100
)

// reserveSessionScript atomically increments the session counter and checks
// whether the new value exceeds the capacity limit. If over limit, it
// decrements back and returns 0. Otherwise it returns 1, reserving a slot.
//
// KEYS[1] = counter key (pp:session:_count)
// ARGV[1] = max sessions
//
// Returns 1 if a slot was reserved, 0 if at capacity.
var reserveSessionScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count > tonumber(ARGV[1]) then
	redis.call('DECR', KEYS[1])
	return 0
end
return 1
`)

// updateSessionScript atomically checks that a session exists and replaces it
// with the full JSON prepared by Go. This avoids using cjson.decode/encode in
// Lua, which corrupts empty JSON arrays (e.g. scope: [] becomes scope: {}).
//
// KEYS[1] = session key (pp:session:{id})
// ARGV[1] = full session JSON (prepared by Go)
//
// Returns 1 on success, 0 if the key doesn't exist.
var updateSessionScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL')
return 1
`)

// completeSessionScript atomically checks that a session exists and replaces
// it with the full JSON prepared by Go. This avoids using cjson.decode/encode
// in Lua, which corrupts empty JSON arrays (e.g. scope: [] becomes scope: {}).
//
// SECURITY: Tokens are stored in plaintext in Redis for a maximum of 2 minutes
// (the completed-session TTL). This window is required because the frontend polls
// GET /auth/status/{id} to retrieve tokens after wallet callback completion.
// Stripping tokens before storage would break the polling flow. The 2-minute
// exposure window is acceptable for MVP; a future improvement could encrypt the
// session payload with a per-instance key.
//
// KEYS[1] = session key (pp:session:{id})
// ARGV[1] = full session JSON (prepared by Go)
// ARGV[2] = new TTL in seconds
//
// Returns 1 on success, 0 if the key doesn't exist.
var completeSessionScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'EX', tonumber(ARGV[2]))
return 1
`)

// failSessionScript records a failure only if the stored value is byte-for-byte
// the one the caller read. This is an optimistic compare-and-set: without it a
// failure that read the pending session before a concurrent CompleteSession
// wrote would clobber the tokens and revert Completed, losing a successful
// login. Comparing the raw string avoids cjson entirely (it corrupts empty
// arrays — see updateSessionScript), so no JSON is decoded in Lua.
//
// KEYS[1] = session key (pp:session:{id})
// ARGV[1] = the exact JSON the caller read
// ARGV[2] = the new JSON to store
//
// Returns 1 on success, 0 if the key doesn't exist, -1 if it changed under us.
var failSessionScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return 0 end
if data ~= ARGV[1] then return -1 end
redis.call('SET', KEYS[1], ARGV[2], 'KEEPTTL')
return 1
`)

// SessionStore is a Redis-backed implementation of the SessionManager interface.
// It stores auth sessions as JSON values with Redis TTL for automatic expiry,
// replacing the in-memory sync.Map-based store.
type SessionStore struct {
	client      *redis.Client
	ttl         time.Duration
	maxSessions int
}

// NewSessionStore creates a new Redis-backed session store.
func NewSessionStore(client *redis.Client, sessionTTL time.Duration, maxSessions int) *SessionStore {
	return &SessionStore{
		client:      client,
		ttl:         sessionTTL,
		maxSessions: maxSessions,
	}
}

// CreateSession creates a new session and returns the session ID.
// Returns empty string if the store is at capacity.
// Uses an atomic Lua script to reserve a slot in the counter, preventing
// race conditions across multiple proxy instances.
func (s *SessionStore) CreateSession(authRequest *protocol.AuthorizationRequestMessage) string {
	ctx := context.Background()

	// Atomically reserve a session slot via the counter.
	if s.maxSessions > 0 {
		reserved, err := reserveSessionScript.Run(ctx, s.client, []string{sessionCountKey}, s.maxSessions).Int()
		if err != nil {
			slog.Error("redis session store: failed to reserve session slot", "error", err)
			return ""
		}
		if reserved == 0 {
			return ""
		}
	}

	sessionID := uuid.New().String()
	now := time.Now()

	session := &auth.Session{
		ID:          sessionID,
		AuthRequest: authRequest,
		CreatedAt:   now,
		ExpiresAt:   now.Add(s.ttl),
	}

	data, err := json.Marshal(session)
	if err != nil {
		slog.Error("redis session store: failed to marshal session", "error", err)
		// Release the reserved slot since we failed to create the session.
		if s.maxSessions > 0 {
			s.decrCount(ctx)
		}
		return ""
	}

	key := sessionKeyPrefix + sessionID
	if err := s.client.Set(ctx, key, data, s.ttl).Err(); err != nil {
		slog.Error("redis session store: failed to store session", "error", err)
		// Release the reserved slot since we failed to store the session.
		if s.maxSessions > 0 {
			s.decrCount(ctx)
		}
		return ""
	}

	return sessionID
}

// GetSession retrieves a session by ID.
// Returns nil if session doesn't exist or has expired.
func (s *SessionStore) GetSession(sessionID string) *auth.Session {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID

	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			slog.Error("redis session store: failed to get session", "error", err)
		}
		return nil
	}

	var session auth.Session
	if err := json.Unmarshal(data, &session); err != nil {
		slog.Error("redis session store: failed to unmarshal session", "error", err)
		return nil
	}

	return &session
}

// DeleteSession removes a session and decrements the atomic session counter.
func (s *SessionStore) DeleteSession(sessionID string) {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID

	deleted, err := s.client.Del(ctx, key).Result()
	if err != nil {
		slog.Error("redis session store: failed to delete session", "error", err)
		return
	}

	// Only decrement the counter if a key was actually deleted, to avoid
	// the counter drifting negative from double-deletes.
	if deleted > 0 && s.maxSessions > 0 {
		s.decrCount(ctx)
	}
}

// UpdateSession atomically updates an existing session's auth request.
// Reads the session in Go, updates the auth_request field, marshals the
// complete session, and uses a Lua script to check-and-SET atomically.
// All JSON encoding happens in Go to avoid Redis Lua's cjson library,
// which corrupts empty arrays ([] -> {}).
func (s *SessionStore) UpdateSession(sessionID string, authRequest *protocol.AuthorizationRequestMessage) error {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID

	session := s.GetSession(sessionID)
	if session == nil {
		return fmt.Errorf("session not found")
	}

	session.AuthRequest = authRequest

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	result, err := updateSessionScript.Run(ctx, s.client, []string{key}, string(data)).Int()
	if err != nil {
		return fmt.Errorf("redis update session script: %w", err)
	}
	if result == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// CompleteSession atomically marks a session as completed with tokens.
// Extends the TTL to 2 minutes so the frontend can poll for completion.
// Reads the session in Go, sets completion fields, marshals the complete
// session, and uses a Lua script to check-and-SET atomically.
// All JSON encoding happens in Go to avoid Redis Lua's cjson library,
// which corrupts empty arrays ([] -> {}).
func (s *SessionStore) CompleteSession(sessionID, accessToken, refreshToken string) error {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID

	session := s.GetSession(sessionID)
	if session == nil {
		return fmt.Errorf("session not found")
	}

	now := time.Now()
	session.Completed = true
	session.AccessToken = accessToken
	session.RefreshToken = refreshToken
	session.CompletedAt = now
	// A wallet may retry after a transient failure, so a success supersedes any
	// recorded failure rather than being blocked by it (RD-1242).
	session.Failed = false
	session.FailureReason = ""
	session.FailedAt = time.Time{}
	session.ExpiresAt = now.Add(2 * time.Minute)

	ttlSeconds := 120

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	result, err := completeSessionScript.Run(ctx, s.client, []string{key},
		string(data), ttlSeconds,
	).Int()
	if err != nil {
		return fmt.Errorf("redis complete session script: %w", err)
	}
	if result == 0 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// FailSession records that the wallet callback for this session was rejected,
// so the polling browser can be told why instead of waiting out its poll budget
// and reporting a timeout that never happened (RD-1242).
//
// reason must be a curated code (see internal/server/auth_failure_reasons.go),
// never raw error text: the value is returned to an unauthenticated poller.
//
// A success always wins over a failure. The write is an optimistic
// compare-and-set against the exact bytes read (failSessionScript), so a
// failure racing a concurrent CompleteSession is dropped rather than clobbering
// the tokens. TTL is preserved via KEEPTTL: a session that failed carries no
// tokens, so it must expire on its original schedule rather than being handed
// the 2-minute completed-session window.
//
// Recording a failure is not terminal - a wallet that retries after a transient
// error still completes via CompleteSession, which clears these fields.
func (s *SessionStore) FailSession(sessionID, reason string) error {
	ctx := context.Background()
	key := sessionKeyPrefix + sessionID

	// Read the raw bytes, not via GetSession: the CAS compares against exactly
	// what is stored, and a re-marshal is not guaranteed to reproduce it.
	current, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return fmt.Errorf("session not found")
		}
		return fmt.Errorf("redis get session: %w", err)
	}

	var session auth.Session
	if err := json.Unmarshal(current, &session); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}

	// Already completed: a success outranks a late failure.
	if session.Completed {
		return nil
	}

	session.Failed = true
	session.FailureReason = reason
	session.FailedAt = time.Now()

	updated, err := json.Marshal(&session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	result, err := failSessionScript.Run(ctx, s.client, []string{key},
		string(current), string(updated),
	).Int()
	if err != nil {
		return fmt.Errorf("redis fail session script: %w", err)
	}
	switch result {
	case 0:
		return fmt.Errorf("session not found")
	case -1:
		// Changed under us — a concurrent CompleteSession (or another failure)
		// won. Dropping this write is the point of the CAS.
		return nil
	}

	return nil
}

// ListSessions returns information about all active sessions.
// Uses SCAN to iterate over session keys without blocking.
func (s *SessionStore) ListSessions() []*auth.SessionInfo {
	ctx := context.Background()
	var sessions []*auth.SessionInfo

	iter := s.client.Scan(ctx, 0, sessionKeyPrefix+"*", defaultSessionScanCount).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		data, err := s.client.Get(ctx, key).Bytes()
		if err != nil {
			continue
		}

		var session auth.Session
		if err := json.Unmarshal(data, &session); err != nil {
			continue
		}

		info := &auth.SessionInfo{
			ID:        session.ID,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
			Completed: session.Completed,
		}
		if session.Completed {
			info.CompletedAt = session.CompletedAt
		}
		if session.Failed {
			info.Failed = true
			info.FailureReason = session.FailureReason
			info.FailedAt = session.FailedAt
		}
		sessions = append(sessions, info)
	}

	return sessions
}

// Count returns the current number of sessions from the atomic counter.
func (s *SessionStore) Count() int64 {
	ctx := context.Background()
	count, err := s.client.Get(ctx, sessionCountKey).Int64()
	if err != nil {
		if err != redis.Nil {
			slog.Error("redis session store: failed to read session count", "error", err)
		}
		return 0
	}
	if count < 0 {
		return 0
	}
	return count
}

// Stop is a no-op for the Redis store. Redis handles TTL expiry natively,
// so there is no cleanup goroutine to stop.
func (s *SessionStore) Stop() {}

// decrCount decrements the session counter, clamping at zero to prevent
// negative drift from TTL-expired sessions that were never explicitly deleted.
func (s *SessionStore) decrCount(ctx context.Context) {
	val, err := s.client.Decr(ctx, sessionCountKey).Result()
	if err != nil {
		slog.Error("redis session store: failed to decrement session count", "error", err)
		return
	}
	// If the counter went negative (e.g. Redis restart lost the counter but
	// sessions expired naturally), reset it to zero.
	if val < 0 {
		s.client.Set(ctx, sessionCountKey, 0, 0)
	}
}
