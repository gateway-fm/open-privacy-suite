package configuration

import (
	"strings"
	"testing"
)

const platformSource = `{"apiVersion":"ops.configuration/v1","kind":"platform","scope":{"kind":"platform"},"baseRevision":0,"dependencies":{},"deletions":[],"spec":{"sharedInfrastructure":[],"tenants":[]}}`

func TestPlatformDocumentScopeAndPinnedInfrastructure(t *testing.T) {
	if _, err := Parse([]byte(platformSource)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(platformSource, `"kind":"platform"}`, `"kind":"organization","id":"11111111-1111-1111-1111-111111111111"}`, 1), strings.Replace(platformSource, `"tenants":[]`, `"tenants":null`, 1), strings.Replace(platformSource, `"dependencies":{}`, `"dependencies":{"groups":"sha256:`+strings.Repeat("1", 64)+`"}`, 1)} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted invalid platform source %s", bad)
		}
	}
}

const platformFeedObject = `{"uri":"https://prices.example.test/api/v3/simple/price?precision=full","refreshIntervalSeconds":300,"format":"coingecko-simple"}`

var platformFeedSource = strings.Replace(platformSource, `"tenants":[]`, `"tenants":[],"priceFeed":`+platformFeedObject, 1)

// A platform document may name the price feed the deployment polls. The field
// is optional and strict: absent means environment defaults, and anything
// that is not exactly {uri, refreshIntervalSeconds, format} is refused, as is
// a URI carrying user information. The URI is reviewed text stored in clear,
// so the document is not a place for a key; a query string is not inspected.
func TestPlatformPriceFeedOptionalStrictAndCanonical(t *testing.T) {
	plain, err := Parse([]byte(platformSource))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Spec.(PlatformSpec).PriceFeed != nil {
		t.Fatal("an absent feed must stay absent")
	}
	canonical, _, err := plain.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(canonical), "priceFeed") {
		t.Fatalf("an absent feed must not appear in the canonical text (existing digests would change): %s", canonical)
	}

	doc, err := Parse([]byte(platformFeedSource))
	if err != nil {
		t.Fatal(err)
	}
	feed := doc.Spec.(PlatformSpec).PriceFeed
	want := PriceFeed{URI: "https://prices.example.test/api/v3/simple/price?precision=full", RefreshIntervalSeconds: 300, Format: PriceFeedFormatCoinGeckoSimple}
	if feed == nil || *feed != want {
		t.Fatalf("feed parsed as %+v, want %+v", feed, want)
	}
	_, digest, err := doc.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	_, again, err := doc.Canonical()
	if err != nil || again != digest {
		t.Fatalf("digest must be stable: %s vs %s (%v)", digest, again, err)
	}

	for name, bad := range map[string]string{
		"null":              strings.Replace(platformFeedSource, platformFeedObject, `null`, 1),
		"unknown format":    strings.Replace(platformFeedSource, `"coingecko-simple"`, `"custom"`, 1),
		"unknown field":     strings.Replace(platformFeedSource, `"format"`, `"apiKey":"k","format"`, 1),
		"missing format":    strings.Replace(platformFeedSource, `,"format":"coingecko-simple"`, ``, 1),
		"interval too low":  strings.Replace(platformFeedSource, `300`, `59`, 1),
		"interval too high": strings.Replace(platformFeedSource, `300`, `86401`, 1),
		"interval float":    strings.Replace(platformFeedSource, `300`, `300.0`, 1),
		"interval string":   strings.Replace(platformFeedSource, `300`, `"300"`, 1),
		"userinfo":          strings.Replace(platformFeedSource, `https://prices`, `https://user:secret@prices`, 1),
		"fragment":          strings.Replace(platformFeedSource, `precision=full`, `precision=full#top`, 1),
		"scheme":            strings.Replace(platformFeedSource, `https://`, `ftp://`, 1),
		"no host":           strings.Replace(platformFeedSource, `https://prices.example.test`, `https://`, 1),
		"relative":          strings.Replace(platformFeedSource, `https://prices.example.test`, ``, 1),
		"empty uri":         strings.Replace(platformFeedSource, `"https://prices.example.test/api/v3/simple/price?precision=full"`, `""`, 1),
	} {
		if bad == platformFeedSource {
			t.Fatalf("case %q did not change the source", name)
		}
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted invalid price feed (%s): %s", name, bad)
		}
	}

	// The diff treats the feed as one resource: created, updated, deleted, or
	// left alone, and the projection carries exactly what the document says.
	snapshot := PlatformSnapshot{Spec: PlatformSpec{SharedInfrastructure: []SharedInfrastructure{}, Tenants: []Tenant{}}, ManagedIDs: []string{}}
	diff, err := DiffPlatform(doc, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff.Changes) != 1 || diff.Changes[0] != (ResourceChange{Action: "create", Resource: "priceFeed", ID: "priceFeed"}) || diff.Projection.PriceFeed == nil || *diff.Projection.PriceFeed != want {
		t.Fatalf("unexpected create diff: %+v", diff)
	}
	current := want
	snapshot.Spec.PriceFeed = &current
	diff, err = DiffPlatform(doc, snapshot)
	if err != nil || len(diff.Changes) != 0 {
		t.Fatalf("an unchanged feed must not report a change: %+v (%v)", diff.Changes, err)
	}
	changed, err := Parse([]byte(strings.Replace(platformFeedSource, `300`, `600`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	diff, err = DiffPlatform(changed, snapshot)
	if err != nil || len(diff.Changes) != 1 || diff.Changes[0].Action != "update" || diff.Projection.PriceFeed.RefreshIntervalSeconds != 600 {
		t.Fatalf("unexpected update diff: %+v (%v)", diff, err)
	}
	diff, err = DiffPlatform(plain, snapshot)
	if err != nil || len(diff.Changes) != 1 || diff.Changes[0] != (ResourceChange{Action: "delete", Resource: "priceFeed", ID: "priceFeed"}) || diff.Projection.PriceFeed != nil {
		t.Fatalf("unexpected delete diff: %+v (%v)", diff, err)
	}
}
