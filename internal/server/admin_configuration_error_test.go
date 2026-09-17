package server

import (
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestConfigurationUnexpectedErrorsAreOpaque(t *testing.T) {
	response := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(response)
	configurationError(c, errors.New("database password=secret SELECT internal_table"))
	require.Equal(t, 500, response.Code)
	require.NotContains(t, response.Body.String(), "secret")
}
