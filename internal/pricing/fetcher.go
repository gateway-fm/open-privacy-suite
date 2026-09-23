package pricing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	coingeckoBaseURL = "https://api.coingecko.com/api/v3/simple/price"
	fetchTimeout     = 10 * time.Second
)

// Fetcher retrieves token prices from an endpoint that answers in CoinGecko's
// /simple/price shape — CoinGecko itself by default, or the feed the platform
// document declares.
type Fetcher struct {
	client  *http.Client
	baseURL string
}

// NewFetcher creates a fetcher pointed at the public CoinGecko endpoint.
func NewFetcher() *Fetcher {
	return &Fetcher{
		client:  newFeedClient(nil),
		baseURL: coingeckoBaseURL,
	}
}

// newFeedClient builds the HTTP client every fetch goes through. Redirects
// are refused, as every other client for an operator-supplied destination
// does: a reviewed https endpoint must not be able to send the fetch on to a
// host, or a scheme, that never passed review.
func newFeedClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Timeout:   fetchTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// FetchResult holds prices for a single CoinGecko token across all requested currencies.
type FetchResult struct {
	Prices map[string]float64 // currency code -> price
}

// FetchAll retrieves fiat prices for the given CoinGecko IDs in all specified currencies.
// Returns a map of coingecko_id -> currency -> price.
func (f *Fetcher) FetchAll(ctx context.Context, ids []string, currencies []string) (map[string]map[string]float64, error) {
	if len(ids) == 0 || len(currencies) == 0 {
		return nil, nil
	}

	// A declared endpoint may carry its own query (a precision setting, say);
	// the fetch parameters are merged into it rather than appended.
	endpoint, err := url.Parse(f.baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid price feed URL: %w", err)
	}
	params := endpoint.Query()
	params.Set("ids", strings.Join(ids, ","))
	params.Set("vs_currencies", strings.Join(currencies, ","))
	endpoint.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := f.client.Do(req)
	if err != nil {
		// The client's error carries the full URL; a declared endpoint may
		// carry a query the operator would not want in every log line, so
		// report the host and the underlying cause only.
		var urlErr *url.Error
		if errors.As(err, &urlErr) {
			err = urlErr.Err
		}
		return nil, fmt.Errorf("price feed request to %s failed: %w", endpoint.Host, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("price feed returned status %d: %s", resp.StatusCode, string(body))
	}

	// Response format: {"ethereum":{"usd":2500.42,"eur":2300.10},"tether":{"usd":1.0,"eur":0.92}}
	var result map[string]map[string]float64
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode price feed response: %w", err)
	}

	return result, nil
}
