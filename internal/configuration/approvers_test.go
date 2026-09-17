package configuration

import (
	"strings"
	"testing"
)

func TestApproversDocumentRequiresExistingAuthorityReferences(t *testing.T) {
	source := strings.Replace(complianceSource, `"kind":"compliance"`, `"kind":"approvers"`, 1)
	source = source[:strings.Index(source, `"spec":`)] + `"spec":{"groupIds":["22222222-2222-2222-2222-222222222222"],"trustedCI":[]}}`
	if _, err := Parse([]byte(source)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.Replace(source, `"trustedCI":[]`, `"trustedCI":null`, 1), strings.Replace(source, `"trustedCI":[]`, `"trustedCI":[],"quorum":2`, 1), strings.Replace(source, `"groupIds":["22222222-2222-2222-2222-222222222222"]`, `"groupIds":[]`, 1)} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted invalid approvers %s", bad)
		}
	}
}
