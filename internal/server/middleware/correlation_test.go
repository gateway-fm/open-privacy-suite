package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func setupCorrelationRouter() *gin.Engine {
	r := gin.New()
	r.Use(CorrelationID())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"correlation_id": GetCorrelationID(c)})
	})
	return r
}

func isValidUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

func TestCorrelationIDMiddleware_NoHeader(t *testing.T) {
	router := setupCorrelationRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	respID := w.Header().Get(CorrelationIDHeader)
	require.NotEmpty(t, respID, "should generate a correlation ID when none supplied")
	assert.True(t, isValidUUID(respID), "generated correlation ID should be a valid UUID, got: %s", respID)
}

func TestCorrelationIDMiddleware_ValidCorrelationID(t *testing.T) {
	router := setupCorrelationRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(CorrelationIDHeader, "my-trace-id-123")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "my-trace-id-123", w.Header().Get(CorrelationIDHeader))
}

func TestCorrelationIDMiddleware_FallbackToRequestID(t *testing.T) {
	router := setupCorrelationRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(RequestIDHeader, "request-id-456")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "request-id-456", w.Header().Get(CorrelationIDHeader))
}

func TestCorrelationIDMiddleware_TooLong(t *testing.T) {
	router := setupCorrelationRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)

	longID := strings.Repeat("a", 129)
	req.Header.Set(CorrelationIDHeader, longID)

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	respID := w.Header().Get(CorrelationIDHeader)
	assert.NotEqual(t, longID, respID, "should not use a too-long client value")
	assert.True(t, isValidUUID(respID), "should generate a valid UUID when client value is too long, got: %s", respID)
}

func TestCorrelationIDMiddleware_CRLFInjection(t *testing.T) {
	router := setupCorrelationRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(CorrelationIDHeader, "evil\r\nX-Injected: true")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	respID := w.Header().Get(CorrelationIDHeader)
	assert.NotContains(t, respID, "\r", "response must not contain carriage return")
	assert.NotContains(t, respID, "\n", "response must not contain newline")
	assert.True(t, isValidUUID(respID), "should generate a valid UUID when control chars detected, got: %s", respID)
}

func TestCorrelationIDMiddleware_TabCharacter(t *testing.T) {
	router := setupCorrelationRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(CorrelationIDHeader, "trace\tid")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	respID := w.Header().Get(CorrelationIDHeader)
	assert.NotContains(t, respID, "\t", "response must not contain tab character")
	assert.True(t, isValidUUID(respID), "should generate a valid UUID when control chars detected, got: %s", respID)
}

func TestCorrelationIDMiddleware_ResponseHeader(t *testing.T) {
	router := setupCorrelationRouter()
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(CorrelationIDHeader, "echo-me-back")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "echo-me-back", w.Header().Get(CorrelationIDHeader),
		"correlation ID should be echoed back in response header")
}

func TestCorrelationIDMiddleware_ContextSet(t *testing.T) {
	r := gin.New()
	r.Use(CorrelationID())

	var ctxID string
	r.GET("/test", func(c *gin.Context) {
		ctxID = GetCorrelationID(c)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(CorrelationIDHeader, "ctx-test-id")

	r.ServeHTTP(w, req)

	assert.Equal(t, "ctx-test-id", ctxID, "correlation ID should be available in gin context")
}

func TestSanitizeCorrelationID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "valid simple", input: "abc-123", want: "abc-123"},
		{name: "valid UUID", input: "550e8400-e29b-41d4-a716-446655440000", want: "550e8400-e29b-41d4-a716-446655440000"},
		{name: "empty", input: "", want: ""},
		{name: "whitespace only", input: "   ", want: ""},
		{name: "with leading/trailing spaces", input: "  hello  ", want: "hello"},
		{name: "exactly 128 chars", input: strings.Repeat("x", 128), want: strings.Repeat("x", 128)},
		{name: "129 chars", input: strings.Repeat("x", 129), want: ""},
		{name: "contains newline", input: "abc\ndef", want: ""},
		{name: "contains carriage return", input: "abc\rdef", want: ""},
		{name: "contains tab", input: "abc\tdef", want: ""},
		{name: "contains null byte", input: "abc\x00def", want: ""},
		{name: "contains DEL", input: "abc\x7fdef", want: ""},
		{name: "CRLF injection", input: "evil\r\nX-Header: injected", want: ""},
		{name: "printable special chars", input: "trace/id@host:8080#ref", want: "trace/id@host:8080#ref"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeCorrelationID(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}
