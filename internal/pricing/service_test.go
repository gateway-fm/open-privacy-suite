package pricing

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"privacy-proxy/internal/compliance"
	"privacy-proxy/internal/configuration"
)

// mockSystemPriceStore implements SystemPriceStore for testing.
type mockSystemPriceStore struct {
	mu        sync.Mutex
	prices    []*compliance.SystemTokenPrice
	upserted  []*compliance.SystemTokenPrice
	listCalls atomic.Int32
}

func (m *mockSystemPriceStore) ListSystemTokenPrices(_ context.Context) ([]*compliance.SystemTokenPrice, error) {
	m.listCalls.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prices, nil
}

func (m *mockSystemPriceStore) UpsertSystemTokenPrice(_ context.Context, price *compliance.SystemTokenPrice) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upserted = append(m.upserted, price)
	return nil
}

func (m *mockSystemPriceStore) getUpserted() []*compliance.SystemTokenPrice {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]*compliance.SystemTokenPrice, len(m.upserted))
	copy(result, m.upserted)
	return result
}

// mockSettingsStore implements SettingsStore for testing.
type mockSettingsStore struct {
	settings map[string]string
}

func (m *mockSettingsStore) GetSystemSetting(_ context.Context, key string) (string, error) {
	return m.settings[key], nil
}

// fakeRoundTripper intercepts HTTP requests and returns canned CoinGecko responses.
type fakeRoundTripper struct {
	calls atomic.Int32
	delay time.Duration
	// redirectTo, when set, answers every request with a 302 to that URL.
	redirectTo string

	mu   sync.Mutex
	urls []*url.URL
}

// lastURL is the URL of the most recent request, so a test can see where the
// fetcher went and with which query.
func (f *fakeRoundTripper) lastURL() *url.URL {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.urls) == 0 {
		return nil
	}
	return f.urls[len(f.urls)-1]
}

func (f *fakeRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls.Add(1)
	f.mu.Lock()
	f.urls = append(f.urls, req.URL)
	f.mu.Unlock()
	if f.redirectTo != "" {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{f.redirectTo}},
			Body:       io.NopCloser(newBytesReader(nil)),
		}, nil
	}

	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	currencies := strings.Split(req.URL.Query().Get("vs_currencies"), ",")
	if len(currencies) == 0 {
		currencies = []string{"usd"}
	}

	// Return a price for each requested currency
	ethPrices := map[string]float64{}
	for _, c := range currencies {
		ethPrices[c] = 3500.0
	}
	resp := map[string]map[string]float64{
		"ethereum": ethPrices,
	}
	body, _ := json.Marshal(resp)

	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(newBytesReader(body)),
	}, nil
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{data: b} }

type bytesReader struct {
	data []byte
	pos  int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}

func newTestService(store SystemPriceStore, settings SettingsStore, interval time.Duration, rt *fakeRoundTripper) *Service {
	svc := NewService(store, settings, interval)
	svc.fetcher.client = &http.Client{Transport: rt}
	return svc
}

func TestRefreshNow_TriggersImmediateFetch(t *testing.T) {
	cgID := "ethereum"
	store := &mockSystemPriceStore{
		prices: []*compliance.SystemTokenPrice{
			{
				ID:          1,
				CoingeckoID: &cgID,
				Symbol:      "ETH",
				Decimals:    18,
				PriceFiat:   0,
				Source:      "coingecko",
			},
		},
	}
	settings := &mockSettingsStore{settings: map[string]string{"base_currency": "usd"}}
	rt := &fakeRoundTripper{}

	// Long interval so ticker won't fire during test.
	svc := newTestService(store, settings, 1*time.Hour, rt)
	svc.Start()
	defer svc.Stop()

	// Start() does an initial fetch — wait for it.
	waitForCalls(t, &rt.calls, 1, 2*time.Second)
	initialCalls := rt.calls.Load()

	// Signal a refresh.
	svc.RefreshNow()

	// Wait for the refresh fetch.
	waitForCalls(t, &rt.calls, initialCalls+1, 2*time.Second)

	// Verify upserts happened (initial + refresh = 2).
	time.Sleep(50 * time.Millisecond)
	upserted := store.getUpserted()
	if len(upserted) < 2 {
		t.Fatalf("expected at least 2 upserts (initial + refresh), got %d", len(upserted))
	}
	if upserted[len(upserted)-1].PriceFiat != 3500.0 {
		t.Errorf("expected price 3500.0, got %f", upserted[len(upserted)-1].PriceFiat)
	}
}

func TestRefreshNow_DoesNotBlockCaller(t *testing.T) {
	cgID := "ethereum"
	store := &mockSystemPriceStore{
		prices: []*compliance.SystemTokenPrice{
			{
				ID:          1,
				CoingeckoID: &cgID,
				Symbol:      "ETH",
				Decimals:    18,
				PriceFiat:   0,
				Source:      "coingecko",
			},
		},
	}
	settings := &mockSettingsStore{settings: map[string]string{"base_currency": "usd"}}
	rt := &fakeRoundTripper{delay: 500 * time.Millisecond}

	svc := newTestService(store, settings, 1*time.Hour, rt)
	svc.Start()
	defer svc.Stop()

	// Wait for initial fetch to complete so the goroutine is idle.
	waitForCalls(t, &rt.calls, 1, 3*time.Second)

	// RefreshNow must return immediately (it just sends on the channel).
	start := time.Now()
	svc.RefreshNow()
	elapsed := time.Since(start)

	if elapsed > 50*time.Millisecond {
		t.Errorf("RefreshNow blocked for %s, expected it to return immediately", elapsed)
	}
}

func TestRefreshNow_CoalescesMultipleCalls(t *testing.T) {
	cgID := "ethereum"
	store := &mockSystemPriceStore{
		prices: []*compliance.SystemTokenPrice{
			{
				ID:          1,
				CoingeckoID: &cgID,
				Symbol:      "ETH",
				Decimals:    18,
				PriceFiat:   0,
				Source:      "coingecko",
			},
		},
	}
	settings := &mockSettingsStore{settings: map[string]string{"base_currency": "usd"}}
	rt := &fakeRoundTripper{delay: 100 * time.Millisecond}

	svc := newTestService(store, settings, 1*time.Hour, rt)
	svc.Start()
	defer svc.Stop()

	// Wait for initial fetch.
	waitForCalls(t, &rt.calls, 1, 3*time.Second)
	afterInitial := rt.calls.Load()

	// Fire multiple RefreshNow calls — channel is buffered(1), so at most 1 pending.
	for i := 0; i < 10; i++ {
		svc.RefreshNow()
	}

	// Wait for the coalesced fetch.
	waitForCalls(t, &rt.calls, afterInitial+1, 2*time.Second)
	time.Sleep(200 * time.Millisecond) // let any additional fetches complete

	// Should have at most 2 extra calls (1 pending + 1 that might sneak in), not 10.
	totalExtra := rt.calls.Load() - afterInitial
	if totalExtra > 2 {
		t.Errorf("expected at most 2 extra fetches after 10 RefreshNow calls, got %d", totalExtra)
	}
}

func waitForCalls(t *testing.T, calls *atomic.Int32, target int32, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		if calls.Load() >= target {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %d calls (got %d)", target, calls.Load())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// fakeFeedStore stands in for the platform document's projected price feed.
type fakeFeedStore struct {
	mu   sync.Mutex
	feed *configuration.PriceFeed
	err  error
}

func (f *fakeFeedStore) GetPlatformPriceFeed(context.Context) (*configuration.PriceFeed, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.feed, f.err
}

func (f *fakeFeedStore) set(feed *configuration.PriceFeed, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.feed, f.err = feed, err
}

func ethereumStore() *mockSystemPriceStore {
	cgID := "ethereum"
	return &mockSystemPriceStore{prices: []*compliance.SystemTokenPrice{{ID: 1, CoingeckoID: &cgID, Symbol: "ETH", Decimals: 18, Source: "coingecko"}}}
}

// The feed a reviewed platform document declares is read before every fetch:
// its URI replaces the built-in endpoint (keeping any query it carries) and
// its interval drives the next tick. No declaration means the environment
// defaults, and a failed read keeps whatever was applied last rather than
// guessing.
func TestServiceAppliesActiveFeedEachTick(t *testing.T) {
	rt := &fakeRoundTripper{}
	svc := newTestService(ethereumStore(), &mockSettingsStore{settings: map[string]string{"base_currency": "usd"}}, time.Hour, rt)
	declared := &configuration.PriceFeed{URI: "http://feed.test/api/v3/simple/price?precision=full", RefreshIntervalSeconds: 120, Format: configuration.PriceFeedFormatCoinGeckoSimple}
	feeds := &fakeFeedStore{feed: declared}
	svc.SetFeedStore(feeds)
	ctx := context.Background()

	if next := svc.fetchAndUpdate(ctx); next != 120*time.Second {
		t.Fatalf("declared interval not applied: next tick in %s", next)
	}
	u := rt.lastURL()
	if u == nil || u.Host != "feed.test" || u.Path != "/api/v3/simple/price" {
		t.Fatalf("fetch did not go to the declared feed: %v", u)
	}
	if q := u.Query(); q.Get("precision") != "full" || q.Get("ids") != "ethereum" || !strings.Contains(q.Get("vs_currencies"), "usd") {
		t.Fatalf("declared query not merged with the fetch parameters: %s", u.RawQuery)
	}

	feeds.set(nil, nil)
	if next := svc.fetchAndUpdate(ctx); next != time.Hour {
		t.Fatalf("without a declaration the environment interval applies, got %s", next)
	}
	if u := rt.lastURL(); u.Host != "api.coingecko.com" {
		t.Fatalf("without a declaration the built-in endpoint applies, got %v", u)
	}

	feeds.set(declared, nil)
	svc.fetchAndUpdate(ctx)
	feeds.set(nil, errors.New("database unavailable"))
	if next := svc.fetchAndUpdate(ctx); next != 120*time.Second {
		t.Fatalf("a failed feed read must keep the last applied interval, got %s", next)
	}
	if u := rt.lastURL(); u.Host != "feed.test" {
		t.Fatalf("a failed feed read must keep the last applied endpoint, got %v", u)
	}
	if got := rt.calls.Load(); got != 4 {
		t.Fatalf("every tick still fetches prices, got %d fetches", got)
	}
}

// A running loop follows an interval change: it starts on the hour-long
// environment default, a feed declaring one second is applied by the next
// fetch (forced here with RefreshNow), and the fetch after that arrives on
// the new pace — which only happens if the ticker was reset. (The document
// refuses intervals under a minute; the service takes the store's word for
// it, which is what lets this test run in seconds.)
func TestServiceResetsTickerWhenFeedIntervalChanges(t *testing.T) {
	rt := &fakeRoundTripper{}
	svc := newTestService(ethereumStore(), &mockSettingsStore{settings: map[string]string{"base_currency": "usd"}}, time.Hour, rt)
	feeds := &fakeFeedStore{}
	svc.SetFeedStore(feeds)
	svc.Start()
	defer svc.Stop()
	waitForCalls(t, &rt.calls, 1, 5*time.Second)

	feeds.set(&configuration.PriceFeed{URI: "http://feed.test/price", RefreshIntervalSeconds: 1, Format: configuration.PriceFeedFormatCoinGeckoSimple}, nil)
	svc.RefreshNow()
	waitForCalls(t, &rt.calls, 2, 5*time.Second)
	// The third fetch is the ticker's, on the declared one-second pace.
	waitForCalls(t, &rt.calls, 3, 5*time.Second)
}

// A redirect is not followed: the reviewed destination answers or the fetch
// fails, so an endpoint cannot hand the request to a host or scheme that
// never passed review. The error names the host, never the full URL.
func TestFetcherRefusesRedirectsAndKeepsURLOutOfErrors(t *testing.T) {
	rt := &fakeRoundTripper{redirectTo: "http://other.example/prices"}
	f := NewFetcher()
	f.client = newFeedClient(rt)
	f.baseURL = "https://feed.test/v3/simple/price?x_cg_pro_api_key=should-stay-out-of-logs"
	_, err := f.FetchAll(context.Background(), []string{"ethereum"}, []string{"usd"})
	if err == nil {
		t.Fatal("a redirect must fail the fetch")
	}
	if got := rt.calls.Load(); got != 1 {
		t.Fatalf("redirect was followed: %d requests", got)
	}
	if !strings.Contains(err.Error(), "302") || strings.Contains(err.Error(), "should-stay-out-of-logs") {
		t.Fatalf("unexpected error text: %v", err)
	}

	// A transport failure is reported by host and cause only.
	f.client = newFeedClient(failingRoundTripper{})
	_, err = f.FetchAll(context.Background(), []string{"ethereum"}, []string{"usd"})
	if err == nil || !strings.Contains(err.Error(), "feed.test") || strings.Contains(err.Error(), "should-stay-out-of-logs") {
		t.Fatalf("unexpected error text: %v", err)
	}
}

type failingRoundTripper struct{}

func (failingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

// A configured endpoint may carry its own query; the fetch parameters are
// merged into it instead of appended after a second question mark.
func TestFetcherMergesConfiguredQuery(t *testing.T) {
	rt := &fakeRoundTripper{}
	f := NewFetcher()
	f.client = &http.Client{Transport: rt}
	f.baseURL = "https://feed.test/v3/simple/price?precision=full"
	if _, err := f.FetchAll(context.Background(), []string{"ethereum"}, []string{"usd", "eur"}); err != nil {
		t.Fatal(err)
	}
	u := rt.lastURL()
	if strings.Count(u.String(), "?") != 1 {
		t.Fatalf("query appended instead of merged: %s", u)
	}
	if q := u.Query(); q.Get("precision") != "full" || q.Get("ids") != "ethereum" || q.Get("vs_currencies") != "usd,eur" {
		t.Fatalf("unexpected query: %s", u.RawQuery)
	}
}
