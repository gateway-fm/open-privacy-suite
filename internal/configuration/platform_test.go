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
