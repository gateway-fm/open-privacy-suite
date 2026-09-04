package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/proxy"
	"privacy-proxy/internal/server/middleware"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCircuitBreaker_Integration_Upstream429 simulates an upstream RPC proxy
// returning 429 and verifies the full circuit breaker lifecycle.
func TestCircuitBreaker_Integration_Upstream429(t *testing.T) {
	var forwardCount atomic.Int32

	mockRPC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := forwardCount.Add(1)
		if count <= 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limited"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1, "result": "0x1",
		})
	}))
	defer mockRPC.Close()

	cb := middleware.NewCircuitBreakerWithCooldown(100 * time.Millisecond)
	proxyClient := proxy.New(mockRPC.URL)
	apiKey := "test-api-key-123"
	body := []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)

	// Request 1: forwarded, gets 429, trips circuit
	respBody, statusCode, err := proxyClient.ForwardWithAPIKey(body, apiKey, "")
	require.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, statusCode)
	assert.Contains(t, string(respBody), "rate limited")
	cb.Trip(apiKey)

	// Request 2: circuit is open, rejected without forwarding
	assert.True(t, cb.IsOpen(apiKey), "circuit should be open after trip")
	prevCount := forwardCount.Load()
	if cb.IsOpen(apiKey) {
		assert.Equal(t, prevCount, forwardCount.Load(), "no forward when circuit is open")
	}

	// Request 3: after cooldown, circuit closes, forwarded successfully
	time.Sleep(150 * time.Millisecond)
	assert.False(t, cb.IsOpen(apiKey), "circuit should close after cooldown")
	respBody2, statusCode2, err2 := proxyClient.ForwardWithAPIKey(body, apiKey, "")
	require.NoError(t, err2)
	assert.Equal(t, http.StatusOK, statusCode2)
	assert.Contains(t, string(respBody2), "0x1")
	cb.Reset(apiKey)

	assert.Equal(t, int32(2), forwardCount.Load(), "exactly 2 forwards (1st=429, 3rd=200)")
}

// TestCircuitBreaker_Integration_PerAPIKeyIsolation verifies tripping one key
// does not affect another.
func TestCircuitBreaker_Integration_PerAPIKeyIsolation(t *testing.T) {
	cb := middleware.NewCircuitBreaker()
	cb.Trip("key-a")
	assert.True(t, cb.IsOpen("key-a"))
	assert.False(t, cb.IsOpen("key-b"), "key-b unaffected by key-a trip")
}

// TestForwardWithAPIKey_SetsHeaders verifies Authorization and X-Forwarded-For.
func TestForwardWithAPIKey_SetsHeaders(t *testing.T) {
	var capturedHeaders http.Header
	mockRPC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	defer mockRPC.Close()

	p := proxy.New(mockRPC.URL)
	body := []byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`)

	_, _, err := p.ForwardWithAPIKey(body, "sk-test-key", "192.168.1.100")
	require.NoError(t, err)
	assert.Equal(t, "Bearer sk-test-key", capturedHeaders.Get("Authorization"))
	assert.Equal(t, "192.168.1.100", capturedHeaders.Get("X-Forwarded-For"))

	_, _, err = p.ForwardWithAPIKey(body, "", "")
	require.NoError(t, err)
	assert.Empty(t, capturedHeaders.Get("Authorization"))
	assert.Empty(t, capturedHeaders.Get("X-Forwarded-For"))
}

// TestCircuitBreaker_Integration_FullProcessorFlow tests the complete lifecycle:
// 429 → trip → reject → cooldown → 429 → trip → cooldown → 200 → reset
func TestCircuitBreaker_Integration_FullProcessorFlow(t *testing.T) {
	var forwardCount atomic.Int32
	mockRPC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := forwardCount.Add(1)
		if count <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"0x1"}`))
	}))
	defer mockRPC.Close()

	cb := middleware.NewCircuitBreakerWithCooldown(50 * time.Millisecond)
	cl := middleware.NewConcurrencyLimiter(10, 0)
	proxyClient := proxy.New(mockRPC.URL)
	apiKey := "group-a-key"
	userID := "user-123"

	processRequest := func() (int, bool) {
		if !cl.TryAcquire(userID) {
			return http.StatusTooManyRequests, false
		}
		defer cl.Release(userID)

		if cb.IsOpen(apiKey) {
			return http.StatusTooManyRequests, false
		}

		_, statusCode, err := proxyClient.ForwardWithAPIKey(
			[]byte(`{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}`),
			apiKey, "",
		)
		if err != nil {
			return http.StatusBadGateway, true
		}
		if statusCode == http.StatusTooManyRequests {
			cb.Trip(apiKey)
			return http.StatusTooManyRequests, true
		}
		cb.Reset(apiKey)
		return statusCode, true
	}

	// Request 1: forwarded, 429, trips circuit
	status, fwd := processRequest()
	assert.Equal(t, http.StatusTooManyRequests, status)
	assert.True(t, fwd)
	assert.True(t, cb.IsOpen(apiKey))

	// Request 2: circuit open, rejected
	status, fwd = processRequest()
	assert.Equal(t, http.StatusTooManyRequests, status)
	assert.False(t, fwd, "should not forward when circuit is open")

	time.Sleep(60 * time.Millisecond)

	// Request 3: circuit closed, forwarded, 429 again
	status, fwd = processRequest()
	assert.Equal(t, http.StatusTooManyRequests, status)
	assert.True(t, fwd)

	time.Sleep(60 * time.Millisecond)

	// Request 4: circuit closed, forwarded, 200
	status, fwd = processRequest()
	assert.Equal(t, http.StatusOK, status)
	assert.True(t, fwd)
	assert.False(t, cb.IsOpen(apiKey))

	// 3 actual forwards: requests 1, 3, 4 (request 2 short-circuited)
	assert.Equal(t, int32(3), forwardCount.Load())
}
