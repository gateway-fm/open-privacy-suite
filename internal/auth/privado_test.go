package auth

import (
	"context"
	"testing"

	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivadoVerifier_NewPrivadoVerifier(t *testing.T) {
	// Test with Privado mainnet RPC
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "https://ipfs-proxy-cache.privado.id", "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896")
	require.NoError(t, err)
	assert.NotNil(t, verifier)
	assert.NotNil(t, verifier.verifier)
}

func TestNewPrivadoVerifier_RegistersBillionsNetwork(t *testing.T) {
	// RD-943: a wallet created in the Billions app produces a DID anchored on
	// the Billions chain (e.g. did:iden3:billions:main:...). The iden3 library
	// looks up a "<blockchain>:<network>" resolver during FullVerify, so without
	// a billions:main resolver every Billions sign-up is rejected with
	// "billions:main resolver not found" while Privado succeeds. Assert both
	// networks are wired.
	verifier, err := NewPrivadoVerifier(
		"https://rpc-mainnet.privado.id", "https://ipfs-proxy-cache.privado.id",
		PrivadoMainnetStateContract,
		NetworkResolver{Key: "billions:main", RPCURL: "https://billions.example/rpc", StateContract: BillionsMainnetStateContract},
	)
	require.NoError(t, err)
	require.NotNil(t, verifier)
	assert.Equal(t, []string{"billions:main", "privado:main"}, verifier.RegisteredNetworks())
}

func TestNewPrivadoVerifier_DefaultsToPrivadoOnly(t *testing.T) {
	// With no extra networks, only privado:main is registered.
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{"privado:main"}, verifier.RegisteredNetworks())
}

func TestNewPrivadoVerifier_SkipsIncompleteNetworks(t *testing.T) {
	// An extra entry missing any field is ignored rather than registering a
	// half-configured resolver that would fail opaquely at verification time.
	verifier, err := NewPrivadoVerifier(
		"https://rpc-mainnet.privado.id", "", PrivadoMainnetStateContract,
		NetworkResolver{Key: "billions:main", RPCURL: "", StateContract: BillionsMainnetStateContract}, // missing RPC
		NetworkResolver{Key: "", RPCURL: "https://x", StateContract: "0xabc"},                          // missing key
	)
	require.NoError(t, err)
	assert.Equal(t, []string{"privado:main"}, verifier.RegisteredNetworks())
}

func TestPrivadoVerifier_NewPrivadoVerifier_InvalidRPC(t *testing.T) {
	// Test with invalid RPC URL (should still create verifier, but verification will fail)
	verifier, err := NewPrivadoVerifier("http://invalid-rpc-url:8545", "https://ipfs-proxy-cache.privado.id", "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896")
	// This might succeed or fail depending on validation
	// The actual verification will fail when we try to verify a token
	if err == nil {
		assert.NotNil(t, verifier)
	}
}

func TestPrivadoVerifier_VerifyJWZ_InvalidToken(t *testing.T) {
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "https://ipfs-proxy-cache.privado.id", "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896")
	require.NoError(t, err)

	// Create a minimal authorization request for testing
	authRequest := &protocol.AuthorizationRequestMessage{
		ID:   "test-request-id",
		Type: "https://iden3-communication.io/authorization/1.0/request",
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: "http://localhost:8080/auth/callback",
			Reason:      "Test verification",
		},
	}

	// Try to verify an invalid JWZ token
	ctx := context.Background()
	_, err = verifier.VerifyJWZ(ctx, "invalid.jwz.token", authRequest, "did:privado:verifier:test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestPrivadoVerifier_VerifyJWZWithProofData_InvalidToken(t *testing.T) {
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "https://ipfs-proxy-cache.privado.id", "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896")
	require.NoError(t, err)

	// Create a minimal authorization request for testing
	authRequest := &protocol.AuthorizationRequestMessage{
		ID:   "test-request-id",
		Type: "https://iden3-communication.io/authorization/1.0/request",
		Body: protocol.AuthorizationRequestMessageBody{
			CallbackURL: "http://localhost:8080/auth/callback",
			Reason:      "Test verification",
		},
	}

	// Try to verify an invalid JWZ token with the new method
	ctx := context.Background()
	result, err := verifier.VerifyJWZWithProofData(ctx, "invalid.jwz.token", authRequest, "did:privado:verifier:test")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "verification failed")
}

func TestPrivadoVerifier_VerifyJWZWithProofData_NilAuthRequest(t *testing.T) {
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "https://ipfs-proxy-cache.privado.id", "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896")
	require.NoError(t, err)

	// Try to verify without auth request
	ctx := context.Background()
	result, err := verifier.VerifyJWZWithProofData(ctx, "some.token", nil, "did:privado:verifier:test")
	assert.Error(t, err)
	assert.Nil(t, result)
	assert.Contains(t, err.Error(), "authorization request is required")
}

func TestVerificationResult_Structure(t *testing.T) {
	// Test that VerificationResult struct has expected fields
	result := &VerificationResult{
		UserDID: "did:privado:test123",
		ProofData: []map[string]any{
			{
				"id":        uint32(1),
				"circuitID": "credentialAtomicQueryMTPV2",
				"credentialSubject": map[string]any{
					"rbac_groups": []string{"org:admin"},
				},
			},
		},
	}

	assert.Equal(t, "did:privado:test123", result.UserDID)
	assert.Len(t, result.ProofData, 1)
	assert.Equal(t, uint32(1), result.ProofData[0]["id"])
	assert.Equal(t, "credentialAtomicQueryMTPV2", result.ProofData[0]["circuitID"])
}

func TestPrivadoVerifier_NewPrivadoVerifier_EmptyStateContractFallsBackToMainnet(t *testing.T) {
	// An empty state contract must fall back to the Privado mainnet default
	// so that callers who construct *config.Config literally in tests (and
	// don't go through config.Load) still get a working verifier.
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "", "")
	require.NoError(t, err)
	assert.NotNil(t, verifier)
}

func TestCreateHumanityAuthRequest_UsesInjectedConfig(t *testing.T) {
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "https://ipfs-proxy-cache.privado.id", "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896")
	require.NoError(t, err)

	hc := HumanityRequestConfig{
		CircuitID:      "credentialAtomicQuerySigV2",
		SchemaURL:      "https://example.com/kyc.jsonld",
		CredentialType: "KYCCredential",
		Query: map[string]any{
			"credentialSubject": map[string]any{
				"kycStatus": map[string]any{"$eq": "verified"},
			},
		},
	}

	req, err := verifier.CreateHumanityAuthRequest(
		"did:privado:verifier",
		"http://localhost/cb",
		"reason",
		"did:privado:issuer",
		hc,
	)
	require.NoError(t, err)
	require.Len(t, req.Body.Scope, 1)

	zk := req.Body.Scope[0]
	assert.Equal(t, "credentialAtomicQuerySigV2", zk.CircuitID)
	assert.Equal(t, "https://example.com/kyc.jsonld", zk.Query["context"])
	assert.Equal(t, "KYCCredential", zk.Query["type"])

	cs, ok := zk.Query["credentialSubject"].(map[string]any)
	require.True(t, ok, "credentialSubject must be injected from hc.Query")
	assert.Contains(t, cs, "kycStatus")

	allowed, ok := zk.Query["allowedIssuers"].([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"did:privado:issuer"}, allowed)
}

func TestCreateHumanityAuthRequest_MissingCredentialSubjectErrors(t *testing.T) {
	verifier, err := NewPrivadoVerifier("https://rpc-mainnet.privado.id", "https://ipfs-proxy-cache.privado.id", "0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896")
	require.NoError(t, err)

	hc := HumanityRequestConfig{
		CircuitID:      "credentialAtomicQueryMTPV2",
		SchemaURL:      "https://example.com/schema.jsonld",
		CredentialType: "ProofOfHumanity",
		Query:          map[string]any{}, // missing credentialSubject
	}

	_, err = verifier.CreateHumanityAuthRequest(
		"did:privado:verifier",
		"http://localhost/cb",
		"reason",
		"did:privado:issuer",
		hc,
	)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credentialSubject")
}

// Note: Testing with real JWZ tokens would require actual Privado ID proofs
// For now, we test the structure and error handling
// In production, you'd want to add integration tests with real proofs
