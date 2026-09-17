package redis

import (
	"context"
	"fmt"
	"testing"
	"time"

	"privacy-proxy/internal/auth"
	"privacy-proxy/internal/rbac"
	"privacy-proxy/internal/types"

	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// setupRedis starts a Redis testcontainer and returns a connected Client.
func setupRedis(t *testing.T) *Client {
	t.Helper()
	ctx := context.Background()

	const testPassword = "testpass123"
	req := testcontainers.ContainerRequest{
		Image:        "redis:7-alpine",
		ExposedPorts: []string{"6379/tcp"},
		Cmd:          []string{"redis-server", "--requirepass", testPassword},
		WaitingFor:   wait.ForLog("Ready to accept connections"),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { container.Terminate(ctx) })

	host, err := container.Host(ctx)
	require.NoError(t, err)

	port, err := container.MappedPort(ctx, "6379")
	require.NoError(t, err)

	client, err := NewClient(fmt.Sprintf("redis://:%s@%s:%s/0", testPassword, host, port.Port()))
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	return client
}

// ---------------------------------------------------------------------------
// Session Store Tests
// ---------------------------------------------------------------------------

func TestSessionStore_CreateAndGet(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	authReq := &protocol.AuthorizationRequestMessage{
		Body: protocol.AuthorizationRequestMessageBody{
			Reason: "test session",
		},
	}

	sessionID := store.CreateSession(authReq)
	require.NotEmpty(t, sessionID)

	session := store.GetSession(sessionID)
	require.NotNil(t, session)
	assert.Equal(t, sessionID, session.ID)
	assert.False(t, session.Completed)
	assert.NotZero(t, session.CreatedAt)
	assert.NotZero(t, session.ExpiresAt)
}

func TestSessionStore_CapacityEnforcement(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 3)

	authReq := &protocol.AuthorizationRequestMessage{}

	// Fill to capacity
	for i := 0; i < 3; i++ {
		id := store.CreateSession(authReq)
		require.NotEmpty(t, id, "session %d should be created", i)
	}

	// Should fail at capacity
	id := store.CreateSession(authReq)
	assert.Empty(t, id, "should fail when at capacity")
}

func TestSessionStore_UpdateSession(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	authReq := &protocol.AuthorizationRequestMessage{
		Body: protocol.AuthorizationRequestMessageBody{
			Reason: "initial",
		},
	}

	sessionID := store.CreateSession(authReq)
	require.NotEmpty(t, sessionID)

	// Update with a new auth request
	updatedReq := &protocol.AuthorizationRequestMessage{
		Body: protocol.AuthorizationRequestMessageBody{
			Reason: "updated",
		},
	}
	err := store.UpdateSession(sessionID, updatedReq)
	require.NoError(t, err)

	session := store.GetSession(sessionID)
	require.NotNil(t, session)
	assert.Equal(t, "updated", session.AuthRequest.Body.Reason)
}

func TestSessionStore_CompleteSession(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, sessionID)

	err := store.CompleteSession(sessionID, "access-token-123", "refresh-token-456")
	require.NoError(t, err)

	session := store.GetSession(sessionID)
	require.NotNil(t, session)
	assert.True(t, session.Completed)
	assert.Equal(t, "access-token-123", session.AccessToken)
	assert.Equal(t, "refresh-token-456", session.RefreshToken)

	// TTL should have been shortened to ~2 minutes
	ctx := context.Background()
	ttl, err := client.TTL(ctx, sessionKeyPrefix+sessionID).Result()
	require.NoError(t, err)
	assert.LessOrEqual(t, ttl.Seconds(), 120.0)
	assert.Greater(t, ttl.Seconds(), 0.0)
}

func TestSessionStore_DeleteSession(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, sessionID)
	assert.Equal(t, int64(1), store.Count())

	store.DeleteSession(sessionID)

	session := store.GetSession(sessionID)
	assert.Nil(t, session)
	assert.Equal(t, int64(0), store.Count())
}

func TestSessionStore_ExpiredSession(t *testing.T) {
	client := setupRedis(t)
	// Use a very short TTL so it expires quickly
	store := NewSessionStore(client, 1*time.Second, 100)

	sessionID := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, sessionID)

	// Wait for expiry
	time.Sleep(2 * time.Second)

	session := store.GetSession(sessionID)
	assert.Nil(t, session, "session should have expired")
}

func TestSessionStore_ListSessions(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	store.CreateSession(&protocol.AuthorizationRequestMessage{})
	store.CreateSession(&protocol.AuthorizationRequestMessage{})

	sessions := store.ListSessions()
	assert.Len(t, sessions, 2)
}

func TestSessionStore_UpdateNonexistent(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	err := store.UpdateSession("nonexistent", &protocol.AuthorizationRequestMessage{})
	assert.Error(t, err)
}

func TestSessionStore_CompleteNonexistent(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	err := store.CompleteSession("nonexistent", "tok", "ref")
	assert.Error(t, err)
}

func TestSessionStore_DeleteCounterDecrement(t *testing.T) {
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 3)

	id1 := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	id2 := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	id3 := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	require.NotEmpty(t, id3)
	assert.Equal(t, int64(3), store.Count())

	// At capacity
	assert.Empty(t, store.CreateSession(&protocol.AuthorizationRequestMessage{}))

	// Delete one, should free a slot
	store.DeleteSession(id1)
	assert.Equal(t, int64(2), store.Count())

	id4 := store.CreateSession(&protocol.AuthorizationRequestMessage{})
	assert.NotEmpty(t, id4, "should succeed after freeing a slot")

	// Double-delete should not decrement below
	store.DeleteSession(id2)
	store.DeleteSession(id2) // second delete is a no-op
	assert.Equal(t, int64(2), store.Count())
}

// ---------------------------------------------------------------------------
// OAuth Session Store Tests
// ---------------------------------------------------------------------------

func TestOAuthStore_CreateAndGet(t *testing.T) {
	client := setupRedis(t)
	store := NewOAuthSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession("client1", "https://example.com/callback", "state123", "auth-sess-1", "")
	require.NotEmpty(t, sessionID)

	session := store.GetSession(sessionID)
	require.NotNil(t, session)
	assert.Equal(t, "client1", session.ClientID)
	assert.Equal(t, "https://example.com/callback", session.RedirectURI)
	assert.Equal(t, "state123", session.State)
	assert.Equal(t, "auth-sess-1", session.AuthSessionID)
}

func TestOAuthStore_SetCodeAndGetByCode(t *testing.T) {
	client := setupRedis(t)
	store := NewOAuthSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession("client1", "https://example.com/callback", "state123", "auth-sess-1", "")
	require.NotEmpty(t, sessionID)

	err := store.SetCode(sessionID, "code-abc", "did:test:user1", true, "service")
	require.NoError(t, err)

	// Retrieve by code
	session := store.GetSessionByCode("code-abc")
	require.NotNil(t, session)
	assert.Equal(t, "code-abc", session.Code)
	assert.Equal(t, "did:test:user1", session.UserDID)
	assert.True(t, session.KYC)
	assert.Equal(t, "service", session.PrincipalKind)
}

func TestOAuthStore_MarkCodeUsedSingleUse(t *testing.T) {
	client := setupRedis(t)
	store := NewOAuthSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession("client1", "https://example.com/callback", "state123", "auth-sess-1", "")
	require.NotEmpty(t, sessionID)

	err := store.SetCode(sessionID, "code-xyz", "did:test:user1", false)
	require.NoError(t, err)

	// First use succeeds
	ok := store.MarkCodeUsed("code-xyz")
	assert.True(t, ok)

	// Second use fails (single-use)
	ok = store.MarkCodeUsed("code-xyz")
	assert.False(t, ok)
}

func TestOAuthStore_CapacityEnforcement(t *testing.T) {
	client := setupRedis(t)
	store := NewOAuthSessionStore(client, 10*time.Minute, 2)

	id1 := store.CreateSession("c1", "https://a.com", "s1", "a1", "")
	require.NotEmpty(t, id1)
	id2 := store.CreateSession("c2", "https://b.com", "s2", "a2", "")
	require.NotEmpty(t, id2)

	// At capacity
	id3 := store.CreateSession("c3", "https://c.com", "s3", "a3", "")
	assert.Empty(t, id3)
}

func TestOAuthStore_DeleteSession(t *testing.T) {
	client := setupRedis(t)
	store := NewOAuthSessionStore(client, 10*time.Minute, 100)

	sessionID := store.CreateSession("client1", "https://example.com/callback", "state123", "auth-sess-1", "")
	require.NotEmpty(t, sessionID)

	// Set a code so we can verify code index cleanup
	err := store.SetCode(sessionID, "code-del", "did:test:user1", false)
	require.NoError(t, err)

	store.DeleteSession(sessionID)

	assert.Nil(t, store.GetSession(sessionID))
	assert.Nil(t, store.GetSessionByCode("code-del"))
}

func TestOAuthStore_MarkCodeUsedNonexistent(t *testing.T) {
	client := setupRedis(t)
	store := NewOAuthSessionStore(client, 10*time.Minute, 100)

	ok := store.MarkCodeUsed("nonexistent-code")
	assert.False(t, ok)
}

func TestOAuthStore_SetCodeNonexistentSession(t *testing.T) {
	client := setupRedis(t)
	store := NewOAuthSessionStore(client, 10*time.Minute, 100)

	err := store.SetCode("nonexistent-session", "code", "did", false)
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Permission Cache Tests
// ---------------------------------------------------------------------------

func TestPermissionCache_SetGetRoundtrip(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 5*time.Minute)

	perms := &rbac.EffectivePermissions{
		ID:             "perm-1",
		UserID:         "user-1",
		OrgID:          "org-1",
		AllowedMethods: []string{"eth_call", "eth_sendTransaction"},
		Claims:         []rbac.Claim{rbac.ClaimDeploy},
		RPCAPIKey:      "secret-api-key-12345",
		ComputedAt:     time.Now().Truncate(time.Millisecond),
		ExpiresAt:      time.Now().Add(5 * time.Minute).Truncate(time.Millisecond),
	}

	cache.Set(perms)

	got := cache.Get("user-1", "org-1")
	require.NotNil(t, got)
	assert.Equal(t, "perm-1", got.ID)
	assert.Equal(t, "user-1", got.UserID)
	assert.Equal(t, "org-1", got.OrgID)
	assert.Equal(t, []string{"eth_call", "eth_sendTransaction"}, got.AllowedMethods)
	assert.Equal(t, []rbac.Claim{rbac.ClaimDeploy}, got.Claims)
	assert.Equal(t, "secret-api-key-12345", got.RPCAPIKey, "RPCAPIKey must survive cache roundtrip")
}

func TestPermissionCache_RPCAPIKeyPreserved(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 5*time.Minute)

	perms := &rbac.EffectivePermissions{
		UserID:    "user-key-test",
		OrgID:     "org-key-test",
		RPCAPIKey: "my-secret-upstream-key",
	}

	cache.Set(perms)

	got := cache.Get("user-key-test", "org-key-test")
	require.NotNil(t, got)
	assert.Equal(t, "my-secret-upstream-key", got.RPCAPIKey,
		"RPCAPIKey with json:\"-\" tag must be preserved through Redis cache")
}

func TestPermissionCache_RPCAPIKeyEmpty(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 5*time.Minute)

	perms := &rbac.EffectivePermissions{
		UserID:    "user-no-key",
		OrgID:     "org-no-key",
		RPCAPIKey: "",
	}

	cache.Set(perms)

	got := cache.Get("user-no-key", "org-no-key")
	require.NotNil(t, got)
	assert.Empty(t, got.RPCAPIKey)
}

func TestPermissionCache_TTLExpiry(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 1*time.Second)

	perms := &rbac.EffectivePermissions{
		UserID: "user-ttl",
		OrgID:  "org-ttl",
	}

	cache.Set(perms)
	got := cache.Get("user-ttl", "org-ttl")
	require.NotNil(t, got)

	time.Sleep(2 * time.Second)

	got = cache.Get("user-ttl", "org-ttl")
	assert.Nil(t, got, "cached entry should have expired")
}

func TestPermissionCache_InvalidateUser(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 5*time.Minute)

	cache.Set(&rbac.EffectivePermissions{UserID: "user-inv", OrgID: "org-a"})
	cache.Set(&rbac.EffectivePermissions{UserID: "user-inv", OrgID: "org-b"})
	cache.Set(&rbac.EffectivePermissions{UserID: "user-other", OrgID: "org-a"})

	cache.InvalidateUser("user-inv")

	assert.Nil(t, cache.Get("user-inv", "org-a"))
	assert.Nil(t, cache.Get("user-inv", "org-b"))
	assert.NotNil(t, cache.Get("user-other", "org-a"), "other user's cache should not be affected")
}

func TestPermissionCache_InvalidateOrg(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 5*time.Minute)

	cache.Set(&rbac.EffectivePermissions{UserID: "user-a", OrgID: "org-inv"})
	cache.Set(&rbac.EffectivePermissions{UserID: "user-b", OrgID: "org-inv"})
	cache.Set(&rbac.EffectivePermissions{UserID: "user-a", OrgID: "org-keep"})

	cache.InvalidateOrg("org-inv")

	assert.Nil(t, cache.Get("user-a", "org-inv"))
	assert.Nil(t, cache.Get("user-b", "org-inv"))
	assert.NotNil(t, cache.Get("user-a", "org-keep"), "other org's cache should not be affected")
}

func TestPermissionCache_InvalidateSpecific(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 5*time.Minute)

	cache.Set(&rbac.EffectivePermissions{UserID: "user-x", OrgID: "org-x"})
	cache.Set(&rbac.EffectivePermissions{UserID: "user-x", OrgID: "org-y"})

	cache.Invalidate("user-x", "org-x")

	assert.Nil(t, cache.Get("user-x", "org-x"))
	assert.NotNil(t, cache.Get("user-x", "org-y"), "other entries should survive")
}

func TestPermissionCache_ClearAndSize(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 5*time.Minute)

	cache.Set(&rbac.EffectivePermissions{UserID: "u1", OrgID: "o1"})
	cache.Set(&rbac.EffectivePermissions{UserID: "u2", OrgID: "o2"})
	assert.Equal(t, 2, cache.Size())

	cache.Clear()
	assert.Equal(t, 0, cache.Size())
}

func TestPermissionCache_SetWithTTL(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 5*time.Minute)

	perms := &rbac.EffectivePermissions{
		UserID:    "user-custom-ttl",
		OrgID:     "org-custom-ttl",
		RPCAPIKey: "custom-key",
	}

	cache.SetWithTTL(perms, 1*time.Second)

	got := cache.Get("user-custom-ttl", "org-custom-ttl")
	require.NotNil(t, got)
	assert.Equal(t, "custom-key", got.RPCAPIKey)

	time.Sleep(2 * time.Second)
	got = cache.Get("user-custom-ttl", "org-custom-ttl")
	assert.Nil(t, got, "entry with custom TTL should have expired")
}

func TestPermissionCache_ContractAccess(t *testing.T) {
	client := setupRedis(t)
	cache := NewPermissionCache(client, 5*time.Minute)

	perms := &rbac.EffectivePermissions{
		UserID: "user-ca",
		OrgID:  "org-ca",
		ContractAccess: map[string]rbac.ContractAccess{
			"0x1234": {
				Claims: []rbac.Claim{rbac.ClaimDeploy},
			},
		},
	}

	cache.Set(perms)

	got := cache.Get("user-ca", "org-ca")
	require.NotNil(t, got)
	require.Contains(t, got.ContractAccess, "0x1234")
	assert.Equal(t, []rbac.Claim{rbac.ClaimDeploy}, got.ContractAccess["0x1234"].Claims)
}

// ---------------------------------------------------------------------------
// Challenge Store Tests
// ---------------------------------------------------------------------------

func TestChallengeStore_CreateAndConsume(t *testing.T) {
	client := setupRedis(t)
	store := NewChallengeStore(client, 5*time.Minute)

	challenge, err := store.CreateChallenge("did:test:user1")
	require.NoError(t, err)
	require.NotNil(t, challenge)
	assert.Equal(t, "did:test:user1", challenge.DID)
	assert.NotEmpty(t, challenge.Nonce)
	assert.NotEmpty(t, challenge.Message)

	// Consume (get + delete)
	got := store.GetChallenge(challenge.Nonce)
	require.NotNil(t, got)
	assert.Equal(t, challenge.DID, got.DID)
	assert.Equal(t, challenge.Nonce, got.Nonce)
}

func TestChallengeStore_SingleUse(t *testing.T) {
	client := setupRedis(t)
	store := NewChallengeStore(client, 5*time.Minute)

	challenge, err := store.CreateChallenge("did:test:user1")
	require.NoError(t, err)

	// First consume succeeds
	got := store.GetChallenge(challenge.Nonce)
	require.NotNil(t, got)

	// Second consume returns nil (already consumed)
	got = store.GetChallenge(challenge.Nonce)
	assert.Nil(t, got, "challenge should be single-use")
}

func TestChallengeStore_Expiry(t *testing.T) {
	client := setupRedis(t)
	store := NewChallengeStore(client, 1*time.Second)

	challenge, err := store.CreateChallenge("did:test:user1")
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	got := store.GetChallenge(challenge.Nonce)
	assert.Nil(t, got, "expired challenge should return nil")
}

func TestChallengeStore_NonexistentNonce(t *testing.T) {
	client := setupRedis(t)
	store := NewChallengeStore(client, 5*time.Minute)

	got := store.GetChallenge("nonexistent-nonce")
	assert.Nil(t, got)
}

// ---------------------------------------------------------------------------
// Azure State Store Tests
// ---------------------------------------------------------------------------

func TestAzureStateStore_CreateAndConsume(t *testing.T) {
	client := setupRedis(t)
	store := NewAzureStateStore(client, 5*time.Minute)

	state, nonce := store.Create()
	assert.NotEmpty(t, state)
	assert.NotEmpty(t, nonce)

	// Consume
	gotNonce, ok := store.Consume(state)
	assert.True(t, ok)
	assert.Equal(t, nonce, gotNonce)
}

func TestAzureStateStore_SingleUse(t *testing.T) {
	client := setupRedis(t)
	store := NewAzureStateStore(client, 5*time.Minute)

	state, _ := store.Create()

	// First consume succeeds
	_, ok := store.Consume(state)
	assert.True(t, ok)

	// Second consume fails
	_, ok = store.Consume(state)
	assert.False(t, ok, "state should be single-use")
}

func TestAzureStateStore_Expiry(t *testing.T) {
	client := setupRedis(t)
	store := NewAzureStateStore(client, 1*time.Second)

	state, _ := store.Create()

	time.Sleep(2 * time.Second)

	_, ok := store.Consume(state)
	assert.False(t, ok, "expired state should not be consumable")
}

func TestAzureStateStore_NonexistentState(t *testing.T) {
	client := setupRedis(t)
	store := NewAzureStateStore(client, 5*time.Minute)

	_, ok := store.Consume("nonexistent-state")
	assert.False(t, ok)
}

// ---------------------------------------------------------------------------
// Regression: cjson corruption of empty arrays
// ---------------------------------------------------------------------------

func TestSessionStore_Iden3ScopeRoundtrip(t *testing.T) {
	// This test catches the cjson corruption bug:
	// Redis Lua cjson converts [] to {} on roundtrip, breaking iden3 scope field.
	client := setupRedis(t)
	store := NewSessionStore(client, 10*time.Minute, 100)

	// Create a session with iden3 AuthRequest containing scope: []
	authReq := &protocol.AuthorizationRequestMessage{
		ID:   "test-id",
		Typ:  "application/iden3comm-plain-json",
		Type: "https://iden3-communication.io/authorization/1.0/request",
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: "http://localhost/callback",
			Scope:       []protocol.ZeroKnowledgeProofRequest{},
		},
		From: "did:test:verifier",
	}

	sessionID := store.CreateSession(authReq)
	require.NotEmpty(t, sessionID)

	// Update the session (this triggers the Lua script roundtrip)
	err := store.UpdateSession(sessionID, authReq)
	require.NoError(t, err)

	// Read back — this is where the cjson bug would strike
	session := store.GetSession(sessionID)
	require.NotNil(t, session)
	require.NotNil(t, session.AuthRequest)

	// The critical assertion: scope must be an empty slice, not nil or corrupted
	assert.NotNil(t, session.AuthRequest.Body.Scope, "scope must not be nil after roundtrip")
	assert.Len(t, session.AuthRequest.Body.Scope, 0, "scope must be empty after roundtrip")

	// Also test CompleteSession roundtrip
	err = store.CompleteSession(sessionID, "access-token", "refresh-token")
	require.NoError(t, err)

	completed := store.GetSession(sessionID)
	require.NotNil(t, completed)
	assert.True(t, completed.Completed)
	assert.NotNil(t, completed.AuthRequest.Body.Scope, "scope must survive CompleteSession roundtrip")
}

// Ensure types are used to avoid unused import errors.
var _ *types.LinkChallenge
var _ *auth.Session
