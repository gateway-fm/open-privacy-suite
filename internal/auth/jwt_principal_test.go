package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestJWTPrincipalKindIsSignedAndPreserved(t *testing.T) {
	service, err := NewJWTService("access-secret", "refresh-secret", time.Hour, time.Hour)
	require.NoError(t, err)
	for _, kind := range []PrincipalKind{PrincipalHuman, PrincipalService, ""} {
		t.Run(string(kind), func(t *testing.T) {
			access, err := service.IssueAccessTokenForPrincipal("did:test:principal", true, kind, nil)
			require.NoError(t, err)
			claims, err := service.ValidateAccessToken(access)
			require.NoError(t, err)
			require.Equal(t, kind, claims.PrincipalKind)
			refresh, err := service.IssueRefreshTokenForPrincipal(claims.Subject, claims.PrincipalKind)
			require.NoError(t, err)
			rotated, err := service.ValidateRefreshToken(refresh)
			require.NoError(t, err)
			require.Equal(t, kind, rotated.PrincipalKind)
		})
	}
	_, err = service.IssueAccessTokenForPrincipal("did:test:principal", true, "admin", nil)
	require.Error(t, err)
	_, err = service.IssueRefreshTokenForPrincipal("did:test:principal", "admin")
	require.Error(t, err)
	legacy, err := service.IssueAccessToken("azure:machine-looking-subject", true)
	require.NoError(t, err)
	claims, err := service.ValidateAccessToken(legacy)
	require.NoError(t, err)
	require.Empty(t, claims.PrincipalKind, "legacy helpers cannot infer a human from a subject name")
}
