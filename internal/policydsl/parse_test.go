package policydsl

import (
	"strings"
	"testing"
)

func TestParse_AcceptsAWellFormedDocument(t *testing.T) {
	doc := `{
	  "apiVersion": "` + APIVersion + `",
	  "kind": "` + Kind + `",
	  "org": "org_acme",
	  "nestedCalls": "` + NestedCallsRequireOwnRule + `",
	  "bindings": [
	    {"group": "grp_traders", "allow": [
	      {"storageAddress": "` + vaultAddr + `", "selector": "` + selTransfer + `", "abiDigest": "aa"}
	    ]}
	  ]
	}`

	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("well-formed document rejected: %v", err)
	}
	if p.Org != "org_acme" || len(p.Bindings) != 1 || len(p.Bindings[0].Allow) != 1 {
		t.Fatalf("document did not decode into the expected shape: %+v", p)
	}
	if got := p.Bindings[0].Allow[0].Selector; got != selTransfer {
		t.Errorf("selector = %q, want %q", got, selTransfer)
	}
}

func TestParse_Rejects(t *testing.T) {
	tests := []struct {
		name    string
		doc     string
		wantErr string
	}{
		{
			name: "unknown top-level field",
			// A typo or a field from a newer schema must fail loudly. Ignoring it
			// would approve a document whose author believed it did something.
			doc:     `{"apiVersion":"x","kind":"y","org":"z","nestedCalls":"n","bindings":[],"enforcement":"warn"}`,
			wantErr: "malformed",
		},
		{
			name:    "unknown nested field",
			doc:     `{"apiVersion":"x","bindings":[{"group":"g","allow":[{"selector":"0x11223344","onDeny":"log"}]}]}`,
			wantErr: "malformed",
		},
		{
			name:    "trailing content after the document",
			doc:     `{"apiVersion":"x"} {"apiVersion":"y"}`,
			wantErr: "trailing",
		},
		{
			name:    "not an object",
			doc:     `["a"]`,
			wantErr: "malformed",
		},
		{
			name:    "truncated json",
			doc:     `{"apiVersion":"x"`,
			wantErr: "malformed",
		},
		{
			name:    "empty input",
			doc:     ``,
			wantErr: "malformed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatalf("expected rejection, got %+v", p)
			}
			if p != nil {
				t.Errorf("Parse returned a document alongside an error")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}
