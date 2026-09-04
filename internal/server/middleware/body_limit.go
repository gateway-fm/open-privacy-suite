package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// BodyLimit caps the size of request bodies on a route group
// (RD-1179). Previously the 1MB cap was hand-applied in only a few handlers,
// leaving most admin/explorer handlers able to buffer an unbounded body into
// memory (ShouldBindJSON/io.ReadAll read the whole body before any cap).
//
// A request whose declared Content-Length exceeds maxBytes is rejected with
// 413 before the handler runs (the cheap, precise path). For chunked or
// under-declared bodies the body is wrapped in http.MaxBytesReader as a memory
// backstop; that overflow surfaces to the handler as a read/bind error (which
// the handlers already turn into a 4xx), so memory stays bounded either way.
func BodyLimit(maxBytes int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "request body too large",
			})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
