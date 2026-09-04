package middleware

import (
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	CorrelationIDHeader = "X-Correlation-ID"
	RequestIDHeader     = "X-Request-ID"
	correlationIDKey    = "correlation_id"
	maxCorrelationIDLen = 128
)

// CorrelationID extracts or generates a correlation ID for each request.
// It checks X-Correlation-ID first, then X-Request-ID, then generates a UUIDv4.
// Client-supplied values are sanitized: capped at 128 chars, non-printable ASCII stripped.
// If the value is invalid after sanitization, a fresh UUID is generated.
func CorrelationID() gin.HandlerFunc {
	return func(c *gin.Context) {
		var correlationID string

		// Try X-Correlation-ID first, then X-Request-ID
		if raw := c.GetHeader(CorrelationIDHeader); raw != "" {
			correlationID = sanitizeCorrelationID(raw)
		}
		if correlationID == "" {
			if raw := c.GetHeader(RequestIDHeader); raw != "" {
				correlationID = sanitizeCorrelationID(raw)
			}
		}

		// Generate a fresh UUID if no valid client-supplied value
		if correlationID == "" {
			correlationID = uuid.New().String()
		}

		// Store in context and echo back in response
		c.Set(correlationIDKey, correlationID)
		c.Header(CorrelationIDHeader, correlationID)

		c.Next()
	}
}

// sanitizeCorrelationID validates and sanitizes a client-supplied correlation ID.
// Returns the sanitized value, or empty string if invalid (triggering UUID generation).
func sanitizeCorrelationID(id string) string {
	id = strings.TrimSpace(id)

	// Strip control characters (ASCII < 32 or == 127)
	var b strings.Builder
	b.Grow(len(id))
	for i := 0; i < len(id); i++ {
		ch := id[i]
		if ch < 32 || ch == 127 {
			continue
		}
		b.WriteByte(ch)
	}
	sanitized := b.String()

	// If stripping changed the string length, the original contained control chars.
	// Reject entirely to avoid partial injection attempts.
	if len(sanitized) != len(strings.TrimSpace(id)) {
		return ""
	}

	if sanitized == "" || len(sanitized) > maxCorrelationIDLen {
		return ""
	}

	return sanitized
}

// GetCorrelationID retrieves the correlation ID from the gin context.
func GetCorrelationID(c *gin.Context) string {
	if id, exists := c.Get(correlationIDKey); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}
