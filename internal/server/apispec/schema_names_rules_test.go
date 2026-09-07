package apispec

import (
	"reflect"
	"testing"
)

func names(in ...string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, n := range in {
		out[n] = true
	}
	return out
}

// TestLaunderedRenameIsCaught is the regression test for the defect this gate
// was rewritten to close: renaming a schema *and* editing the baseline to match,
// in one commit, with no allowlist entry. The two working-tree rules are
// satisfied by that edit — which is exactly why the append-only rule against the
// base revision has to be the thing that fails.
func TestLaunderedRenameIsCaught(t *testing.T) {
	const (
		oldName = "internal_server.PolicyResponse"
		newName = "privacy-proxy_internal_apimodels.PolicyResponse"
	)

	base := names("big.Int", oldName)
	// The laundered commit: document and baseline both moved to the new name.
	spec := names("big.Int", newName)
	baseline := names("big.Int", newName)
	allowed := names()

	if got := missingFromSpec(baseline, spec, allowed); len(got) != 0 {
		t.Fatalf("premise broken: the working-tree rule should be satisfied by the laundered edit, got %v", got)
	}
	if got := unrecordedAdditions(spec, baseline); len(got) != 0 {
		t.Fatalf("premise broken: the additive rule should be satisfied by the laundered edit, got %v", got)
	}

	got := droppedFromBaseline(base, baseline, allowed)
	if !reflect.DeepEqual(got, []string{oldName}) {
		t.Errorf("laundered rename not caught: droppedFromBaseline = %v, want [%s]", got, oldName)
	}

	// Declaring the rename is what clears it.
	if got := droppedFromBaseline(base, baseline, names(oldName)); len(got) != 0 {
		t.Errorf("allowlisted rename should pass, got %v", got)
	}
}

func TestMissingFromSpec(t *testing.T) {
	tests := []struct {
		name                      string
		baseline, spec, allowlist map[string]bool
		want                      []string
	}{
		{
			name:     "document matches baseline",
			baseline: names("A", "B"),
			spec:     names("A", "B"),
			want:     nil,
		},
		{
			name:     "accidental rename with an untouched baseline",
			baseline: names("A", "B"),
			spec:     names("A", "C"),
			want:     []string{"B"},
		},
		{
			name:      "declared removal passes",
			baseline:  names("A", "B"),
			spec:      names("A"),
			allowlist: names("B"),
			want:      nil,
		},
		{
			name:     "additions alone are not a drift",
			baseline: names("A"),
			spec:     names("A", "B"),
			want:     nil,
		},
		{
			name:     "reports every missing name, sorted",
			baseline: names("C", "A", "B"),
			spec:     names(),
			want:     []string{"A", "B", "C"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := missingFromSpec(tc.baseline, tc.spec, tc.allowlist)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("missingFromSpec = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDroppedFromBaseline(t *testing.T) {
	tests := []struct {
		name                  string
		base, baseline, allow map[string]bool
		want                  []string
	}{
		{
			name:     "baseline unchanged",
			base:     names("A", "B"),
			baseline: names("A", "B"),
			want:     nil,
		},
		{
			name:     "baseline grew",
			base:     names("A"),
			baseline: names("A", "B"),
			want:     nil,
		},
		{
			name:     "name silently deleted from the baseline",
			base:     names("A", "B"),
			baseline: names("A"),
			want:     []string{"B"},
		},
		{
			name:     "declared removal passes",
			base:     names("A", "B"),
			baseline: names("A"),
			allow:    names("B"),
			want:     nil,
		},
		{
			name:     "bootstrap: nothing published at the base revision",
			base:     names(),
			baseline: names("A", "B"),
			want:     nil,
		},
		{
			name:     "reports every dropped name, sorted",
			base:     names("A", "B", "C"),
			baseline: names(),
			want:     []string{"A", "B", "C"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := droppedFromBaseline(tc.base, tc.baseline, tc.allow)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("droppedFromBaseline = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestUnrecordedAdditions(t *testing.T) {
	tests := []struct {
		name           string
		spec, baseline map[string]bool
		want           []string
	}{
		{
			name:     "recorded addition",
			spec:     names("A", "B"),
			baseline: names("A", "B"),
			want:     nil,
		},
		{
			name:     "new schema not recorded",
			spec:     names("A", "B"),
			baseline: names("A"),
			want:     []string{"B"},
		},
		{
			name:     "baseline may hold retired names",
			spec:     names("A"),
			baseline: names("A", "B"),
			want:     nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := unrecordedAdditions(tc.spec, tc.baseline)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("unrecordedAdditions = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestStaleAllowlistEntries pins the case the previous implementation got
// wrong: it required an entry to be in the working baseline, which every
// legitimate entry is not — a retired name is removed from the baseline. That
// would have failed on the allowlist's first real use.
func TestStaleAllowlistEntries(t *testing.T) {
	tests := []struct {
		name                              string
		allow, spec, baseline, base       map[string]bool
		wantPresent, wantPointlessEntries []string
	}{
		{
			name:     "legitimate retirement: gone from spec and working baseline, still at base",
			allow:    names("B"),
			spec:     names("A"),
			baseline: names("A"),
			base:     names("A", "B"),
		},
		{
			name:     "entry for a name still in the baseline is legitimate too",
			allow:    names("B"),
			spec:     names("A"),
			baseline: names("A", "B"),
			base:     names("A", "B"),
		},
		{
			name:        "schema came back",
			allow:       names("B"),
			spec:        names("A", "B"),
			baseline:    names("A", "B"),
			base:        names("A", "B"),
			wantPresent: []string{"B"},
		},
		{
			name:                 "entry for a name that was never published",
			allow:                names("Z"),
			spec:                 names("A"),
			baseline:             names("A"),
			base:                 names("A"),
			wantPointlessEntries: []string{"Z"},
		},
		{
			name:     "empty allowlist is the healthy state",
			allow:    names(),
			spec:     names("A"),
			baseline: names("A"),
			base:     names("A"),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			present, pointless := staleAllowlistEntries(tc.allow, tc.spec, tc.baseline, tc.base)
			if !reflect.DeepEqual(present, tc.wantPresent) {
				t.Errorf("present = %v, want %v", present, tc.wantPresent)
			}
			if !reflect.DeepEqual(pointless, tc.wantPointlessEntries) {
				t.Errorf("pointless = %v, want %v", pointless, tc.wantPointlessEntries)
			}
		})
	}
}

func TestParseNameList(t *testing.T) {
	raw := []byte("# comment\n\nA\n  B  \nC # renamed by RD-1265\n\n")
	got := parseNameList(raw)
	want := names("A", "B", "C")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseNameList = %v, want %v", got, want)
	}
}
