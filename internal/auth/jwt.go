package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

type PrincipalKind string

const (
	PrincipalHuman   PrincipalKind = "human"
	PrincipalService PrincipalKind = "service"
)

// JWTService handles JWT token issuance and validation
type JWTService struct {
	accessSecret  []byte
	refreshSecret []byte
	accessTTL     time.Duration
	refreshTTL    time.Duration

	// Previous secrets accepted for VALIDATION only, never signing (RD-1164
	// #15). Rotating a leaked/expiring signing secret otherwise invalidates
	// every outstanding token at once (mass logout). With a rotation window the
	// new secret signs, while tokens still bearing the old secret keep
	// validating until they naturally expire. Empty by default (no window).
	accessSecretsPrev  [][]byte
	refreshSecretsPrev [][]byte
}

// TokenClaims represents the claims in our JWT tokens
type TokenClaims struct {
	PrincipalKind PrincipalKind `json:"principal_kind,omitempty"`
	Subject       string        `json:"sub"`                // User DID from Privado ID
	KYC           bool          `json:"kyc"`                // KYC status (from verified proof)
	ZKRoleClaims  *ZKRoleClaims `json:"zk_roles,omitempty"` // Optional ZK-attested role claims
	jwt.RegisteredClaims
}

// ZKRoleClaims contains claims extracted from ZK credentials.
// Note: In the simplified RBAC model, role names are replaced by claims (read, write, admin, upgrade).
type ZKRoleClaims struct {
	Groups         []string `json:"groups,omitempty"`          // Group paths (e.g., "gateway:engineering:devops")
	Claims         []string `json:"claims,omitempty"`          // Claims (e.g., "read", "write", "admin")
	CredentialRefs []string `json:"credential_refs,omitempty"` // References to ZK credentials for audit
	ProofTimestamp int64    `json:"proof_ts,omitempty"`        // When the proof was generated
}

// NewJWTService creates a new JWT service
// For production, secrets should be loaded from secure configuration
func NewJWTService(accessSecret, refreshSecret string, accessTTL, refreshTTL time.Duration) (*JWTService, error) {
	if accessSecret == "" {
		// Generate a random secret if not provided (for development only)
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate secret: %w", err)
		}
		accessSecret = base64.URLEncoding.EncodeToString(secret)
	}

	if refreshSecret == "" {
		// Generate a random secret if not provided (for development only)
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate refresh secret: %w", err)
		}
		refreshSecret = base64.URLEncoding.EncodeToString(secret)
	}

	return &JWTService{
		accessSecret:  []byte(accessSecret),
		refreshSecret: []byte(refreshSecret),
		accessTTL:     accessTTL,
		refreshTTL:    refreshTTL,
	}, nil
}

// SetValidationSecrets registers additional secrets that are accepted when
// VALIDATING tokens but never used to sign new ones (RD-1164 #15). This is the
// rotation window: to rotate a signing secret without logging everyone out,
// promote the new secret to the primary (JWT_SECRET / JWT_REFRESH_SECRET) and
// pass the outgoing secret here (JWT_SECRET_PREVIOUS / JWT_REFRESH_SECRET_PREVIOUS).
// Tokens already issued under the old secret keep validating until they expire;
// once the longest TTL has elapsed the previous secret can be dropped. Empty or
// blank entries are ignored. Safe to call once at startup.
func (j *JWTService) SetValidationSecrets(accessPrevious, refreshPrevious []string) {
	j.accessSecretsPrev = toSecretBytes(accessPrevious)
	j.refreshSecretsPrev = toSecretBytes(refreshPrevious)
}

// toSecretBytes converts non-blank secret strings to byte slices, dropping
// empty entries (a trailing comma or unset var must not create an all-zero key).
func toSecretBytes(secrets []string) [][]byte {
	out := make([][]byte, 0, len(secrets))
	for _, s := range secrets {
		if s == "" {
			continue
		}
		out = append(out, []byte(s))
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// IssueAccessToken issues a new access token (short-lived)
func (j *JWTService) IssueAccessToken(subject string, kyc bool) (string, error) {
	return j.IssueAccessTokenWithZKClaims(subject, kyc, nil)
}

// IssueAccessTokenWithZKClaims issues a new access token with optional ZK role claims.
func (j *JWTService) IssueAccessTokenWithZKClaims(subject string, kyc bool, zkClaims *ZKRoleClaims) (string, error) {
	// Legacy issuers carry no approval authority. Login flows must explicitly
	// supply the principal kind established by their verified authentication.
	return j.IssueAccessTokenForPrincipal(subject, kyc, "", zkClaims)
}

func (j *JWTService) IssueAccessTokenForPrincipal(subject string, kyc bool, kind PrincipalKind, zkClaims *ZKRoleClaims) (string, error) {
	if kind != "" && kind != PrincipalHuman && kind != PrincipalService {
		return "", fmt.Errorf("invalid principal kind")
	}
	now := time.Now()
	claims := TokenClaims{
		PrincipalKind: kind,
		Subject:       subject,
		KYC:           kyc,
		ZKRoleClaims:  zkClaims,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(), // Unique token ID
			ExpiresAt: jwt.NewNumericDate(now.Add(j.accessTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.accessSecret)
}

// IssueRefreshToken issues a new refresh token (long-lived, stored in DB)
func (j *JWTService) IssueRefreshToken(subject string) (string, error) {
	return j.IssueRefreshTokenForPrincipal(subject, "")
}

func (j *JWTService) IssueRefreshTokenForPrincipal(subject string, kind PrincipalKind) (string, error) {
	if kind != "" && kind != PrincipalHuman && kind != PrincipalService {
		return "", fmt.Errorf("invalid principal kind")
	}
	now := time.Now()
	claims := TokenClaims{
		PrincipalKind: kind,
		Subject:       subject,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uuid.New().String(), // Unique token ID for refresh token rotation
			ExpiresAt: jwt.NewNumericDate(now.Add(j.refreshTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.refreshSecret)
}

// HashToken creates a hash of a token for storage (for refresh tokens)
func HashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

// ValidateAccessToken validates an access token and returns the claims
func (j *JWTService) ValidateAccessToken(tokenString string) (*TokenClaims, error) {
	return j.validateToken(tokenString, j.accessSecret, j.accessSecretsPrev)
}

// ValidateRefreshToken validates a refresh token and returns the claims
func (j *JWTService) ValidateRefreshToken(tokenString string) (*TokenClaims, error) {
	return j.validateToken(tokenString, j.refreshSecret, j.refreshSecretsPrev)
}

// validateToken validates against the primary secret first, then each previous
// (validation-only) secret. Expiry is terminal: an expired token is denied
// without trying other secrets, so the rotation window (RD-1164 #15) only ever
// accepts a still-valid token signed under a secret we've rotated away from —
// it never extends a token's lifetime.
func (j *JWTService) validateToken(tokenString string, primary []byte, previous [][]byte) (*TokenClaims, error) {
	claims, err := j.parseWithSecret(tokenString, primary)
	if err == nil {
		return claims, nil
	}
	if errors.Is(err, ErrExpiredToken) {
		return nil, err
	}
	// Primary failed on signature/parse (not expiry): the token may have been
	// signed under a secret we've since rotated away from. Try each previous.
	for _, secret := range previous {
		c, e := j.parseWithSecret(tokenString, secret)
		if e == nil {
			return c, nil
		}
		if errors.Is(e, ErrExpiredToken) {
			return nil, e
		}
	}
	return nil, err
}

// parseWithSecret parses and validates a token against a single secret,
// mapping library errors onto the package's ErrExpiredToken / ErrInvalidToken.
func (j *JWTService) parseWithSecret(tokenString string, secret []byte) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		// Wrap ErrInvalidToken so errors.Is works correctly
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
