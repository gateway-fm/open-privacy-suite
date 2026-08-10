package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ProxyClient is a client for the Open Privacy Suite API.
type ProxyClient struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewProxyClient creates a new proxy client. The base URL must parse and use
// http or https — this guards against typos in privacy.toml/--api-url/$PRIVACY_PROXY_API_URL
// and prevents schemes like file:// or gopher:// from being used as request targets.
func NewProxyClient(baseURL, token string) (*ProxyClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid api_url %q: %w", baseURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("api_url must use http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("api_url %q is missing a host", baseURL)
	}
	return &ProxyClient{
		baseURL: strings.TrimSuffix(baseURL, "/"),
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// validatePathSegment rejects what escaping cannot fix. url.PathEscape leaves "." and
// ".." untouched - both are unreserved path characters - so escaping alone does not stop
// "/orgs/../deployments/prepare" being normalised to a different endpoint by a proxy or
// server. These identifiers are documented as UUIDs, so validate them.
//
// Validation only, deliberately: the url.PathEscape call stays inline at each call site.
// Returning a pre-escaped string from here instead hid the sanitiser from static
// analysis, which re-rated those call sites as high-severity SSRF even though the
// behaviour was identical. Keeping the escape visible next to the fmt.Sprintf costs
// nothing and keeps both the scanner and a human reader able to see it.
func validatePathSegment(kind, value string) error {
	switch {
	case value == "":
		return fmt.Errorf("%s must not be empty", kind)
	case value == "." || value == "..":
		return fmt.Errorf("invalid %s %q: dot segments are not allowed", kind, value)
	case strings.ContainsAny(value, "/\\"):
		return fmt.Errorf("invalid %s %q: must not contain a path separator", kind, value)
	}
	return nil
}

// PrepareDeployment registers a deployment plan with the proxy.
func (c *ProxyClient) PrepareDeployment(orgID string, req *PrepareRequest) (*PrepareResponse, error) {
	if err := validatePathSegment("org_id", orgID); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/orgs/%s/deployments/prepare", c.baseURL, url.PathEscape(orgID))

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result PrepareResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// Deployment represents a deployment record.
type Deployment struct {
	ID         string            `json:"id"`
	OrgID      string            `json:"org_id"`
	Status     string            `json:"status"`
	Addresses  map[string]string `json:"addresses"`
	CreatedAt  string            `json:"created_at"`
	ExpiresAt  string            `json:"expires_at"`
	VerifiedAt string            `json:"verified_at,omitempty"`
}

// GetDeployment retrieves a deployment by ID.
func (c *ProxyClient) GetDeployment(deploymentID string) (*Deployment, error) {
	if err := validatePathSegment("deployment_id", deploymentID); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/deployments/%s", c.baseURL, url.PathEscape(deploymentID))

	httpReq, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result Deployment
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// ListDeploymentsResponse represents the response from listing deployments.
type ListDeploymentsResponse struct {
	Deployments []Deployment `json:"deployments"`
	Total       int          `json:"total"`
}

// ListDeployments lists deployments for an organization.
func (c *ProxyClient) ListDeployments(orgID string, status string) (*ListDeploymentsResponse, error) {
	if err := validatePathSegment("org_id", orgID); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/orgs/%s/deployments", c.baseURL, url.PathEscape(orgID))
	if status != "" {
		endpoint += "?status=" + url.QueryEscape(status)
	}

	httpReq, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result ListDeploymentsResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// VerifyDeploymentRequest represents a request to verify a deployment.
type VerifyDeploymentRequest struct {
	DeploymentID string `json:"deployment_id"`
}

// VerifyDeploymentResponse represents the response from verifying a deployment.
type VerifyDeploymentResponse struct {
	Verified  bool                         `json:"verified"`
	Contracts []ContractVerificationResult `json:"contracts"`
	Errors    []string                     `json:"errors,omitempty"`
}

// ContractVerificationResult represents the verification result for a single contract.
type ContractVerificationResult struct {
	Name            string `json:"name"`
	ExpectedAddress string `json:"expected_address"`
	ActualAddress   string `json:"actual_address,omitempty"`
	Verified        bool   `json:"verified"`
	BytecodeMatch   bool   `json:"bytecode_match"`
	Error           string `json:"error,omitempty"`
}

// VerifyDeployment verifies that a deployment matches its registration.
func (c *ProxyClient) VerifyDeployment(deploymentID string) (*VerifyDeploymentResponse, error) {
	if err := validatePathSegment("deployment_id", deploymentID); err != nil {
		return nil, err
	}
	endpoint := fmt.Sprintf("%s/deployments/%s/verify", c.baseURL, url.PathEscape(deploymentID))

	httpReq, err := http.NewRequest("POST", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	c.setHeaders(httpReq)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result VerifyDeploymentResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &result, nil
}

// setHeaders sets common HTTP headers for API requests.
func (c *ProxyClient) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
}
