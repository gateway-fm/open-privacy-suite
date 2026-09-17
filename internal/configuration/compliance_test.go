package configuration

import (
	"strings"
	"testing"
)

const complianceSource = `{"apiVersion":"ops.configuration/v1","kind":"compliance","scope":{"kind":"organization","id":"11111111-1111-1111-1111-111111111111"},"baseRevision":0,"dependencies":{},"deletions":[],"spec":{"settings":{"enabled":true,"thresholdFiat":1000,"currency":"usd","unknownPricePolicy":"forbidden","enforcementMode":"enforce"},"addressThresholds":[],"tokenPrices":[]}}`

func TestComplianceDocumentRejectsOperationalAndAmbiguousSettings(t *testing.T) {
	if _, err := Parse([]byte(complianceSource)); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{
		strings.Replace(complianceSource, `"enforce"`, `"allow"`, 1),
		strings.Replace(complianceSource, `"thresholdFiat":1000`, `"thresholdFiat":-1`, 1),
		strings.Replace(complianceSource, `"currency":"usd"`, `"currency":"USD"`, 1),
		strings.Replace(complianceSource, `"tokenPrices":[]`, `"tokenPrices":[],"sanctions":[]`, 1),
		strings.Replace(complianceSource, `"addressThresholds":[]`, `"addressThresholds":null`, 1),
	} {
		if _, err := Parse([]byte(source)); err == nil {
			t.Fatalf("accepted invalid source %s", source)
		}
	}
}

func TestComplianceDocumentCanonicalResources(t *testing.T) {
	row := `{"id":"22222222-2222-2222-2222-222222222222","tokenAddress":"native","symbol":"ETH","decimals":18,"pricesByCurrency":{"usd":2500},"coingeckoId":""}`
	source := strings.Replace(complianceSource, `"tokenPrices":[]`, `"tokenPrices":[`+row+`]`, 1)
	if _, err := Parse([]byte(source)); err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []string{`"decimals":256`, `"decimals":-1`} {
		if _, err := Parse([]byte(strings.Replace(source, `"decimals":18`, replacement, 1))); err == nil {
			t.Fatal("invalid decimals accepted")
		}
	}
	if _, err := Parse([]byte(strings.Replace(source, `"usd":2500`, `"usd":-1`, 1))); err == nil {
		t.Fatal("negative price accepted")
	}
	if _, err := Parse([]byte(strings.Replace(source, `"tokenPrices":[`+row+`]`, `"tokenPrices":[`+row+`,`+row+`]`, 1))); err == nil {
		t.Fatal("duplicate token accepted")
	}
}

func TestComplianceDocumentRejectsThresholdProjectionRounding(t *testing.T) {
	for _, number := range []string{"1.234", "0.001", "1000000000000000000", "1.00000000000000001", "100000000000000000.01", "1e-999999999"} {
		source := strings.Replace(complianceSource, `"thresholdFiat":1000`, `"thresholdFiat":`+number, 1)
		if _, err := Parse([]byte(source)); err == nil {
			t.Fatalf("accepted threshold %s that PostgreSQL rounds or overflows", number)
		}
		row := `{"id":"22222222-2222-2222-2222-222222222222","address":"0x1111111111111111111111111111111111111111","thresholdFiat":` + number + `,"note":""}`
		if _, err := Parse([]byte(strings.Replace(complianceSource, `"addressThresholds":[]`, `"addressThresholds":[`+row+`]`, 1))); err == nil {
			t.Fatalf("accepted address threshold %s that PostgreSQL rounds or overflows", number)
		}
	}
	for _, number := range []string{"0", "0.29", "1.01", "999999999999999900"} {
		if _, err := Parse([]byte(strings.Replace(complianceSource, `"thresholdFiat":1000`, `"thresholdFiat":`+number, 1))); err != nil {
			t.Fatalf("valid exact threshold %s rejected: %v", number, err)
		}
	}
}

func TestComplianceDocumentPriceRangePreservesJSONPrecision(t *testing.T) {
	for _, tc := range []struct {
		number string
		valid  bool
	}{{"0.000000000001", true}, {"999999999999", true}, {"1000000000000", false}} {
		row := `{"id":"22222222-2222-2222-2222-222222222222","tokenAddress":"native","symbol":"ETH","decimals":18,"pricesByCurrency":{"usd":` + tc.number + `},"coingeckoId":""}`
		_, err := Parse([]byte(strings.Replace(complianceSource, `"tokenPrices":[]`, `"tokenPrices":[`+row+`]`, 1)))
		if (err == nil) != tc.valid {
			t.Fatalf("price %s valid=%v: %v", tc.number, tc.valid, err)
		}
	}
}
