package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// RD-1179: a global body-size middleware bounds request memory on the admin
// and explorer groups (the 1MB cap was previously hand-applied in only a few
// handlers). A declared Content-Length over the limit is rejected with 413
// before the handler runs; an under-declared/chunked oversize body is bounded
// by MaxBytesReader and surfaces as a downstream read error.
func TestBodyLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	const max = 1024

	newRouter := func() *gin.Engine {
		r := gin.New()
		r.Use(BodyLimit(max))
		r.POST("/x", func(c *gin.Context) {
			// Handler reads the body so the MaxBytesReader backstop can fire.
			b, err := io.ReadAll(c.Request.Body)
			if err != nil {
				c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "read cap"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"n": len(b)})
		})
		return r
	}

	t.Run("declared Content-Length over limit → 413 before handler", func(t *testing.T) {
		body := strings.NewReader(strings.Repeat("a", max+1))
		req := httptest.NewRequest(http.MethodPost, "/x", body)
		// httptest sets ContentLength from the reader length.
		w := httptest.NewRecorder()
		newRouter().ServeHTTP(w, req)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected 413 for over-limit Content-Length, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("body under limit → handler runs", func(t *testing.T) {
		body := strings.NewReader(strings.Repeat("a", max-1))
		req := httptest.NewRequest(http.MethodPost, "/x", body)
		w := httptest.NewRecorder()
		newRouter().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("expected 200 for under-limit body, got %d (%s)", w.Code, w.Body.String())
		}
	})

	t.Run("under-declared Content-Length but oversize stream → capped (not 200 with full read)", func(t *testing.T) {
		// Lie about Content-Length: declare small, send large. The
		// Content-Length gate passes, but MaxBytesReader caps the read so the
		// handler cannot read the full oversize payload.
		payload := bytes.Repeat([]byte("b"), max+512)
		req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(payload))
		req.ContentLength = 10 // understated
		w := httptest.NewRecorder()
		newRouter().ServeHTTP(w, req)
		if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "n\":") {
			// If it's 200, the handler must NOT have read more than max bytes.
			if strings.Contains(w.Body.String(), "\"n\":"+itoa(len(payload))) {
				t.Fatalf("handler read the full oversize payload despite the cap: %s", w.Body.String())
			}
		}
		// Acceptable outcomes: 413 (read cap error) — the point is the full
		// oversize body is never fully delivered to the handler.
	})
}

func itoa(n int) string {
	// tiny helper to avoid importing strconv just for the assertion
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
