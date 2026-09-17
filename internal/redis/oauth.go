package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"privacy-proxy/internal/types"

	"github.com/redis/go-redis/v9"
)

const (
	// oauthSessionKeyPrefix is the Redis key prefix for OAuth sessions.
	oauthSessionKeyPrefix = "pp:oauth:sess:"

	// oauthCodeKeyPrefix is the Redis key prefix for the code->sessionID index.
	oauthCodeKeyPrefix = "pp:oauth:code:"

	// oauthSessionCountKey is the Redis key for the atomic OAuth session counter.
	oauthSessionCountKey = "pp:oauth:sess:_count"

	// oauthCodeTTL is how long authorization codes are valid.
	oauthCodeTTL = 5 * time.Minute
)

// reserveOAuthSessionScript atomically increments the OAuth session counter and
// checks whether the new value exceeds the capacity limit. If over limit, it
// decrements back and returns 0. Otherwise it returns 1, reserving a slot.
//
// KEYS[1] = counter key (pp:oauth:sess:_count)
// ARGV[1] = max sessions
//
// Returns 1 if a slot was reserved, 0 if at capacity.
var reserveOAuthSessionScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count > tonumber(ARGV[1]) then
	redis.call('DECR', KEYS[1])
	return 0
end
return 1
`)

// setCodeScript atomically checks that a session exists, replaces it with the
// full JSON prepared by Go, and creates the code index key. This avoids using
// cjson.decode/encode in Lua, which corrupts empty JSON arrays.
//
// KEYS[1] = session key     (pp:oauth:sess:{id})
// KEYS[2] = code index key  (pp:oauth:code:{code})
// ARGV[1] = full session JSON (prepared by Go)
// ARGV[2] = session ID      (value stored in the code index key)
// ARGV[3] = code TTL        (seconds)
//
// Returns {1} on success, {0} if the session does not exist.
var setCodeScript = redis.NewScript(`
local data = redis.call('GET', KEYS[1])
if not data then return {0} end
redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL')
redis.call('SET', KEYS[2], ARGV[2], 'EX', tonumber(ARGV[3]))
return {1}
`)

// markCodeUsedReadScript is phase 1 of the two-phase mark-code-used flow.
// It reads the code index and session data and returns them to Go for
// JSON manipulation, avoiding cjson.decode/encode which corrupts empty arrays.
//
// KEYS[1] = code index key (pp:oauth:code:{code})
// ARGV[1] = session key prefix (pp:oauth:sess:)
//
// Returns {1, sessionID, sessionData} on success, {0, "", ""} on failure.
var markCodeUsedReadScript = redis.NewScript(`
local sess_id = redis.call('GET', KEYS[1])
if not sess_id then return {0, '', ''} end
local sess_key = ARGV[1] .. sess_id
local data = redis.call('GET', sess_key)
if not data then return {0, '', ''} end
return {1, sess_id, data}
`)

// markCodeUsedWriteScript is phase 2 of the two-phase mark-code-used flow.
// It persists the updated session JSON (prepared by Go) and deletes the
// code index entry.
//
// KEYS[1] = session key   (pp:oauth:sess:{id})
// KEYS[2] = code index key (pp:oauth:code:{code})
// ARGV[1] = full session JSON (prepared by Go)
//
// Returns 1 on success.
var markCodeUsedWriteScript = redis.NewScript(`
redis.call('SET', KEYS[1], ARGV[1], 'KEEPTTL')
redis.call('DEL', KEYS[2])
return 1
`)

// OAuthSessionStore is a Redis-backed implementation of the OAuthSessionManager interface.
// It maintains a dual index: session ID -> session data, and authorization code -> session ID.
type OAuthSessionStore struct {
	client      *redis.Client
	ttl         time.Duration
	maxSessions int
}

// NewOAuthSessionStore creates a new Redis-backed OAuth session store.
func NewOAuthSessionStore(client *redis.Client, sessionTTL time.Duration, maxSessions int) *OAuthSessionStore {
	return &OAuthSessionStore{
		client:      client,
		ttl:         sessionTTL,
		maxSessions: maxSessions,
	}
}

// CreateSession creates a new OAuth session.
// initiatorDID is the JWT-subject DID of the caller that triggered /authorize
// (empty for anonymous callers). RD-993: the silent-SSO endpoint refuses to
// complete unless the completing user matches this field.
// Returns the session ID or empty string if at capacity.
// Uses an atomic Lua script to reserve a slot in the counter, preventing
// race conditions across multiple proxy instances.
func (s *OAuthSessionStore) CreateSession(clientID, redirectURI, state, authSessionID, initiatorDID string) string {
	ctx := context.Background()

	// Atomically reserve a session slot via the counter.
	if s.maxSessions > 0 {
		reserved, err := reserveOAuthSessionScript.Run(ctx, s.client, []string{oauthSessionCountKey}, s.maxSessions).Int()
		if err != nil {
			slog.Error("redis oauth store: failed to reserve session slot", "error", err)
			return ""
		}
		if reserved == 0 {
			return ""
		}
	}

	sessionID := generateSecureCode()
	now := time.Now()

	session := &types.OAuthSession{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		State:         state,
		AuthSessionID: authSessionID,
		InitiatorDID:  initiatorDID,
		CreatedAt:     now,
		ExpiresAt:     now.Add(s.ttl),
	}

	data, err := json.Marshal(session)
	if err != nil {
		slog.Error("redis oauth store: failed to marshal session", "error", err)
		// Release the reserved slot since we failed to create the session.
		if s.maxSessions > 0 {
			s.decrCount(ctx)
		}
		return ""
	}

	key := oauthSessionKeyPrefix + sessionID
	if err := s.client.Set(ctx, key, data, s.ttl).Err(); err != nil {
		slog.Error("redis oauth store: failed to store session", "error", err)
		// Release the reserved slot since we failed to store the session.
		if s.maxSessions > 0 {
			s.decrCount(ctx)
		}
		return ""
	}

	return sessionID
}

// GetSession retrieves an OAuth session by ID.
func (s *OAuthSessionStore) GetSession(sessionID string) *types.OAuthSession {
	ctx := context.Background()
	key := oauthSessionKeyPrefix + sessionID

	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err != redis.Nil {
			slog.Error("redis oauth store: failed to get session", "error", err)
		}
		return nil
	}

	var session types.OAuthSession
	if err := json.Unmarshal(data, &session); err != nil {
		slog.Error("redis oauth store: failed to unmarshal session", "error", err)
		return nil
	}

	return &session
}

// GetSessionByCode retrieves an OAuth session by authorization code.
func (s *OAuthSessionStore) GetSessionByCode(code string) *types.OAuthSession {
	ctx := context.Background()
	codeKey := oauthCodeKeyPrefix + code

	sessionID, err := s.client.Get(ctx, codeKey).Result()
	if err != nil {
		if err != redis.Nil {
			slog.Error("redis oauth store: failed to get code index", "error", err)
		}
		return nil
	}

	return s.GetSession(sessionID)
}

// SetCode atomically sets the authorization code for a session.
// Reads the session in Go, updates fields, marshals the complete session,
// and uses a Lua script to check-and-SET atomically. All JSON encoding
// happens in Go to avoid Redis Lua's cjson library, which corrupts empty
// arrays ([] -> {}).
func (s *OAuthSessionStore) SetCode(sessionID, code, userDID string, kyc bool, principalKind ...string) error {
	kind := ""
	if len(principalKind) > 1 {
		return fmt.Errorf("invalid principal kind")
	}
	if len(principalKind) == 1 {
		kind = principalKind[0]
	}
	if kind != "" && kind != "human" && kind != "service" {
		return fmt.Errorf("invalid principal kind")
	}
	ctx := context.Background()
	sessKey := oauthSessionKeyPrefix + sessionID
	codeKey := oauthCodeKeyPrefix + code

	session := s.GetSession(sessionID)
	if session == nil {
		return fmt.Errorf("session not found")
	}

	session.Code = code
	session.CodeExpires = time.Now().Add(oauthCodeTTL)
	session.UserDID = userDID
	session.KYC = kyc
	session.PrincipalKind = kind

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	codeTTLSeconds := int64(oauthCodeTTL.Seconds())

	result, err := setCodeScript.Run(ctx, s.client,
		[]string{sessKey, codeKey},
		string(data),
		sessionID,
		codeTTLSeconds,
	).Slice()
	if err != nil {
		return fmt.Errorf("redis setCode script: %w", err)
	}

	if len(result) < 1 {
		return fmt.Errorf("session not found")
	}

	success, ok := result[0].(int64)
	if !ok || success != 1 {
		return fmt.Errorf("session not found")
	}

	return nil
}

// MarkCodeUsed atomically marks the authorization code as used (single-use).
// Returns true if the code was valid and successfully marked, false otherwise.
// Uses a two-phase Lua approach: phase 1 reads code index + session data,
// Go checks code_used and prepares updated JSON, phase 2 persists and cleans up.
// All JSON encoding happens in Go to avoid Redis Lua's cjson library,
// which corrupts empty arrays ([] -> {}).
func (s *OAuthSessionStore) MarkCodeUsed(code string) bool {
	ctx := context.Background()
	codeKey := oauthCodeKeyPrefix + code

	// Phase 1: Read code index and session data.
	result, err := markCodeUsedReadScript.Run(ctx, s.client, []string{codeKey}, oauthSessionKeyPrefix).Slice()
	if err != nil {
		slog.Error("redis oauth store: markCodeUsedRead script failed", "error", err)
		return false
	}

	if len(result) < 3 {
		return false
	}

	success, ok := result[0].(int64)
	if !ok || success != 1 {
		return false
	}

	sessID, ok := result[1].(string)
	if !ok || sessID == "" {
		return false
	}

	sessData, ok := result[2].(string)
	if !ok || sessData == "" {
		return false
	}

	// Decode in Go, check code_used, update.
	var session types.OAuthSession
	if err := json.Unmarshal([]byte(sessData), &session); err != nil {
		slog.Error("redis oauth store: failed to unmarshal session in markCodeUsed", "error", err)
		return false
	}

	if session.CodeUsed {
		return false
	}

	session.CodeUsed = true

	data, err := json.Marshal(&session)
	if err != nil {
		slog.Error("redis oauth store: failed to marshal session in markCodeUsed", "error", err)
		return false
	}

	// Phase 2: Persist updated session and delete code index.
	sessKey := oauthSessionKeyPrefix + sessID
	_, err = markCodeUsedWriteScript.Run(ctx, s.client, []string{sessKey, codeKey}, string(data)).Int()
	if err != nil {
		slog.Error("redis oauth store: markCodeUsedWrite script failed", "error", err)
		return false
	}

	return true
}

// DeleteSession removes an OAuth session, its code index entry, and decrements
// the atomic session counter.
func (s *OAuthSessionStore) DeleteSession(sessionID string) {
	ctx := context.Background()
	sessKey := oauthSessionKeyPrefix + sessionID

	// Read session first to find the code for index cleanup.
	data, err := s.client.Get(ctx, sessKey).Bytes()
	if err != nil {
		if err != redis.Nil {
			slog.Error("redis oauth store: failed to get session for deletion", "error", err)
		}
		// Even if we can't read the session, try to delete the key.
		deleted, delErr := s.client.Del(ctx, sessKey).Result()
		if delErr != nil {
			slog.Error("redis oauth store: failed to delete session key", "error", delErr)
		}
		if deleted > 0 && s.maxSessions > 0 {
			s.decrCount(ctx)
		}
		return
	}

	var session types.OAuthSession
	keys := []string{sessKey}
	if err := json.Unmarshal(data, &session); err == nil && session.Code != "" {
		keys = append(keys, oauthCodeKeyPrefix+session.Code)
	}

	deleted, err := s.client.Del(ctx, keys...).Result()
	if err != nil {
		slog.Error("redis oauth store: failed to delete session", "error", err)
		return
	}

	// The session key is always first in the keys slice. If at least one key
	// was deleted and we know the session key existed (we read it above),
	// decrement the counter.
	if deleted > 0 && s.maxSessions > 0 {
		s.decrCount(ctx)
	}
}

// Stop is a no-op for the Redis store. Redis handles TTL expiry natively.
func (s *OAuthSessionStore) Stop() {}

// decrCount decrements the OAuth session counter, clamping at zero to prevent
// negative drift from TTL-expired sessions that were never explicitly deleted.
func (s *OAuthSessionStore) decrCount(ctx context.Context) {
	val, err := s.client.Decr(ctx, oauthSessionCountKey).Result()
	if err != nil {
		slog.Error("redis oauth store: failed to decrement session count", "error", err)
		return
	}
	// If the counter went negative (e.g. Redis restart lost the counter but
	// sessions expired naturally), reset it to zero.
	if val < 0 {
		s.client.Set(ctx, oauthSessionCountKey, 0, 0)
	}
}

// generateSecureCode generates a cryptographically secure random hex string.
func generateSecureCode() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}
