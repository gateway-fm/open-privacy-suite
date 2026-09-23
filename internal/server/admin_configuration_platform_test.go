package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/configuration"
)

func TestConfigurationPlatformRequiresNamedAllowlistedHumans(t *testing.T) {
	f := configurationAPI(t)
	base := "/api/v1/admin/configuration/platform"
	response := f.request(t, f.admin, http.MethodGet, base+"/context", nil)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	for _, token := range []string{f.admin, f.reviewer} {
		claims, err := f.server.jwtService.ValidateAccessToken(token)
		require.NoError(t, err)
		f.server.config.PlatformAdminSubjects = append(f.server.config.PlatformAdminSubjects, claims.Subject)
	}
	response = f.request(t, f.admin, http.MethodGet, base+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var context apimodels.ConfigurationContext
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &context))
	require.True(t, context.Viewer.CanActivate)
	doc, err := configuration.Parse(context.Source)
	require.NoError(t, err)
	require.Equal(t, "platform", doc.Scope.Kind)
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	response = f.request(t, f.reviewer, http.MethodPost, base+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	// Allowlist privilege is deliberately local to configuration routes.
	response = f.request(t, f.admin, http.MethodPost, "/api/v1/admin/azure-tenants", map[string]any{"tenant_id": "invalid"})
	require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
	doc.BaseRevision = draft.Revision
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions/"+draft.ID+"/withdraw", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
}

// allowlistPlatform makes the fixture's admin and reviewer named platform
// operators, the way TestConfigurationPlatformRequiresNamedAllowlistedHumans
// does, and returns the platform stream's base path.
func allowlistPlatform(t *testing.T, f configurationAPIFixture) string {
	t.Helper()
	for _, token := range []string{f.admin, f.reviewer} {
		claims, err := f.server.jwtService.ValidateAccessToken(token)
		require.NoError(t, err)
		f.server.config.PlatformAdminSubjects = append(f.server.config.PlatformAdminSubjects, claims.Subject)
	}
	return "/api/v1/admin/configuration/platform"
}

func platformDocumentWithFeed(t *testing.T, f configurationAPIFixture, base string, feed *configuration.PriceFeed) *configuration.Document {
	t.Helper()
	response := f.request(t, f.admin, http.MethodGet, base+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var view apimodels.ConfigurationContext
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &view))
	doc, err := configuration.Parse(view.Source)
	require.NoError(t, err)
	spec := doc.Spec.(configuration.PlatformSpec)
	spec.PriceFeed = feed
	doc.Spec = spec
	return doc
}

// A refresh interval close to the price staleness threshold would let one
// missed fetch make every fed price stale and deny every valued transfer, so
// the interval must be at most half the threshold. The pure validator cannot
// see the deployment's threshold, so the server checks it when the document
// is submitted and again when a different person activates it, because the
// environment may have changed in between.
func TestPlatformPriceFeedRefusesIntervalAboveHalfStaleness(t *testing.T) {
	f := configurationAPI(t)
	base := allowlistPlatform(t, f)
	f.server.config.Environment = "development"
	f.server.config.PriceStalenessThreshold = 15 * time.Minute

	feed := &configuration.PriceFeed{URI: "https://prices.example.test/api/v3/simple/price", RefreshIntervalSeconds: 451, Format: configuration.PriceFeedFormatCoinGeckoSimple}
	doc := platformDocumentWithFeed(t, f, base, feed)
	response := f.request(t, f.admin, http.MethodPost, base+"/revisions", doc)
	require.Equal(t, http.StatusBadRequest, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "refreshIntervalSeconds")
	require.Contains(t, response.Body.String(), "15m")

	// Exactly half is the most the deployment admits.
	feed.RefreshIntervalSeconds = 450
	doc = platformDocumentWithFeed(t, f, base, feed)
	response = f.request(t, f.admin, http.MethodPost, base+"/revisions", doc)
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	var draft apimodels.ConfigurationRevision
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &draft))

	f.server.config.PriceStalenessThreshold = 5 * time.Minute
	response = f.request(t, f.reviewer, http.MethodPost, base+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusConflict, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), "refreshIntervalSeconds")

	f.server.config.PriceStalenessThreshold = 15 * time.Minute
	response = f.request(t, f.reviewer, http.MethodPost, base+"/revisions/"+draft.ID+"/activate", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	response = f.request(t, f.admin, http.MethodGet, base+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	require.Contains(t, response.Body.String(), `"refreshIntervalSeconds":450`)
}

// The feed URI is fetched from inside the deployment, so it gets the same
// destination guard as every other operator-supplied URL: in production only
// https to a public host; in development a cleartext loopback or private
// destination is admitted for local stacks. Either way the check happens
// before anything is stored.
func TestPlatformPriceFeedRefusesPrivateHostInProduction(t *testing.T) {
	f := configurationAPI(t)
	base := allowlistPlatform(t, f)
	f.server.config.PriceStalenessThreshold = 15 * time.Minute
	f.server.config.Environment = "production"
	submit := func(uri string) *httptest.ResponseRecorder {
		t.Helper()
		doc := platformDocumentWithFeed(t, f, base, &configuration.PriceFeed{URI: uri, RefreshIntervalSeconds: 300, Format: configuration.PriceFeedFormatCoinGeckoSimple})
		return f.request(t, f.admin, http.MethodPost, base+"/revisions", doc)
	}
	for _, uri := range []string{"https://10.0.0.5/api/v3/simple/price", "https://127.0.0.1:8545/prices", "https://localhost/prices", "http://prices.example.test/api/v3/simple/price"} {
		response := submit(uri)
		require.Equal(t, http.StatusBadRequest, response.Code, "%s: %s", uri, response.Body.String())
		require.Contains(t, response.Body.String(), "priceFeed.uri")
	}
	response := submit("https://prices.example.test/api/v3/simple/price")
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())

	f.server.config.Environment = "development"
	response = submit("http://127.0.0.1:8545/prices")
	require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
	response = submit("http://prices.example.test/api/v3/simple/price")
	require.Equal(t, http.StatusBadRequest, response.Code, "cleartext to a public host is refused everywhere: %s", response.Body.String())
}

// A headless client learns from the capabilities whether a declared feed
// would do anything here: the test server runs without the pricing service
// (travel rule off), so the answer is no, with the reason.
func TestConfigurationCapabilitiesReportPriceFeedAvailability(t *testing.T) {
	f := configurationAPI(t)
	base := allowlistPlatform(t, f)
	response := f.request(t, f.admin, http.MethodGet, base+"/context", nil)
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var view apimodels.ConfigurationContext
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &view))
	require.False(t, view.Capabilities.PriceFeed.Available)
	require.Contains(t, view.Capabilities.PriceFeed.Reason, "ENABLE_TRAVEL_RULE")
}
