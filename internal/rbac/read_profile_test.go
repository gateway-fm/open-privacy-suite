package rbac

import "testing"

func TestParseReadProfile(t *testing.T) {
	tests := []struct {
		in      string
		want    ReadProfile
		wantErr bool
	}{
		{"standard", ReadProfileStandard, false},
		{"strict", ReadProfileStrict, false},
		{" Strict ", ReadProfileStrict, false},
		{"STANDARD", ReadProfileStandard, false},
		{"", ReadProfileUnset, true},
		{"permissive", ReadProfileUnset, true},
		{"stric", ReadProfileUnset, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseReadProfile(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseReadProfile(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ParseReadProfile(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// The zero value must enforce strict: a component whose profile was never
// wired fails closed.
func TestReadProfile_UnsetIsStrict(t *testing.T) {
	var p ReadProfile
	if p != ReadProfileUnset {
		t.Fatalf("zero value = %v, want ReadProfileUnset", p)
	}
	if !p.Strict() {
		t.Fatal("unset profile must be treated as strict")
	}
	if p.String() != "strict" {
		t.Fatalf("unset String() = %q, want strict", p.String())
	}
	if !ReadProfile(99).Strict() {
		t.Fatal("unknown profile value must be treated as strict")
	}
	if !ReadProfileStrict.Strict() || ReadProfileStandard.Strict() {
		t.Fatal("Strict() mismatch for explicit values")
	}
	if ReadProfileStandard.String() != "standard" || ReadProfileStrict.String() != "strict" {
		t.Fatal("String() mismatch for explicit values")
	}
}
