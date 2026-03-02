package auth

import (
	"context"
	"errors"
	"fmt"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// AzureADAuthenticator performs Azure AD / Microsoft Entra ID OIDC authentication.
type AzureADAuthenticator struct {
	clientID     string
	clientSecret string
	tenantID     string
	provider     *gooidc.Provider
}

// AzureIdentity holds the verified identity extracted from an Azure AD id_token.
type AzureIdentity struct {
	OID               string // Object ID — stable, immutable identifier
	Email             string
	Name              string
	PreferredUsername string
}

// NewAzureADAuthenticator creates an authenticator by fetching the OIDC discovery document.
// Uses "common" as tenantID for multi-tenant / personal Microsoft accounts.
func NewAzureADAuthenticator(clientID, clientSecret, tenantID string) (*AzureADAuthenticator, error) {
	issuerURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID)

	// Multi-tenant endpoints ("common", "organizations") return tokens whose issuer
	// contains the actual tenant ID, which differs from "common". Skip issuer check.
	ctx := context.Background()
	if tenantID == "common" || tenantID == "organizations" {
		ctx = gooidc.InsecureIssuerURLContext(ctx, issuerURL)
	}

	provider, err := gooidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover Azure AD OIDC configuration: %w", err)
	}

	return &AzureADAuthenticator{
		clientID:     clientID,
		clientSecret: clientSecret,
		tenantID:     tenantID,
		provider:     provider,
	}, nil
}

// GetAuthorizationURL returns the Microsoft login URL to redirect the user to.
// state is the CSRF token; nonce prevents id_token replay attacks.
func (a *AzureADAuthenticator) GetAuthorizationURL(redirectURI, state, nonce string) string {
	return a.oauthConfig(redirectURI).AuthCodeURL(state, oauth2.SetAuthURLParam("nonce", nonce))
}

// ExchangeCode exchanges an authorization code for a verified AzureIdentity.
// Validates id_token signature, expiry, audience, and nonce.
func (a *AzureADAuthenticator) ExchangeCode(ctx context.Context, code, redirectURI, nonce string) (*AzureIdentity, error) {
	token, err := a.oauthConfig(redirectURI).Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("id_token missing from token response")
	}

	skipIssuer := a.tenantID == "common" || a.tenantID == "organizations"
	verifier := a.provider.Verifier(&gooidc.Config{
		ClientID:        a.clientID,
		SkipIssuerCheck: skipIssuer,
	})

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("id_token verification failed: %w", err)
	}

	// Verify nonce to prevent replay attacks
	if idToken.Nonce != nonce {
		return nil, errors.New("nonce mismatch in id_token")
	}

	var claims struct {
		OID               string `json:"oid"`
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract id_token claims: %w", err)
	}
	if claims.OID == "" {
		return nil, errors.New("oid claim missing from id_token")
	}

	return &AzureIdentity{
		OID:               claims.OID,
		Email:             claims.Email,
		Name:              claims.Name,
		PreferredUsername: claims.PreferredUsername,
	}, nil
}

// AzureSubject returns the canonical subject for an Azure AD user.
// Format: "azuread:{oid}" — consistent with DID format used elsewhere.
func AzureSubject(oid string) string {
	return "azuread:" + oid
}

func (a *AzureADAuthenticator) oauthConfig(redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		RedirectURL:  redirectURI,
		Endpoint:     a.provider.Endpoint(),
		Scopes:       []string{gooidc.ScopeOpenID, "profile", "email"},
	}
}
