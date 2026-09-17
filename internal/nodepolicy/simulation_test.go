package nodepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func TestCandidateSimulationBindsAndValidatesArtifact(t *testing.T) {
	r := SimulationRequest{Method: "eth_call", Params: json.RawMessage(`[{"from":"0x1111111111111111111111111111111111111111"},"latest"]`)}
	ordinary, err := EncodeSimulation(r)
	if err != nil {
		t.Fatal(err)
	}
	code := []byte{0x60, 0x00}
	digest := sha256.Sum256(code)
	h := hex.EncodeToString(digest[:])
	r.CandidatePolicy = &PolicyArtifact{OrgID: "org-a", Revision: 1, PolicyDigest: h, RuntimeDigest: h, Bytecode: code}
	wire, err := EncodeSimulation(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSimulation(wire, SimulationHash(ordinary)); err == nil {
		t.Fatal("unsigned candidate substitution accepted")
	}
	r.CandidatePolicy.Bytecode[0] ^= 1
	if _, err := EncodeSimulation(r); err == nil {
		t.Fatal("candidate bytecode digest mismatch accepted")
	}
}

func TestSimulationBindingIncludesExactRequestAndDryRun(t *testing.T) {
	r := SimulationRequest{Method: "eth_call", Params: json.RawMessage(`[{"from":"0x1111111111111111111111111111111111111111","to":"0x1111111111111111111111111111111111111111","data":"0x"},"latest"]`)}
	b, err := EncodeSimulation(r)
	if err != nil {
		t.Fatal(err)
	}
	h := SimulationHash(b)
	if h == "" {
		t.Fatal("empty hash")
	}
	parsed, err := ParseSimulation(b, h)
	if err != nil || parsed.Method != r.Method {
		t.Fatalf("roundtrip: %+v %v", parsed, err)
	}
	r.DryRun = true
	changed, err := EncodeSimulation(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSimulation(changed, h); err == nil {
		t.Fatal("dry-run changed without breaking binding")
	}
	if _, err := ParseSimulation(append([]byte(" "), b...), h); err == nil {
		t.Fatal("byte substitution changed without breaking binding")
	}
	r.Method = "eth_sendRawTransaction"
	if _, err := EncodeSimulation(r); err == nil {
		t.Fatal("non-simulation method accepted")
	}
}

func TestIdenticalSimulationsHaveIndependentPrincipalContexts(t *testing.T) {
	r := NewIdentityRegistry(4)
	i := identityFixture()
	i.Scope = "simulation"
	a, _ := testSigner().Seal("identity", i)
	if err := r.Accept(testVerifier(), a); err != nil {
		t.Fatal(err)
	}
	j := i
	j.PrincipalID = "user-b"
	j.ContextID = "simulation-b"
	b, _ := testSigner().Seal("identity", j)
	if err := r.Accept(testVerifier(), b); err != nil {
		t.Fatalf("same call from independent principal was rejected: %v", err)
	}
	got, err := r.LookupSimulation(j.ContextID, j.BindingHash, time.Unix(1020, 0))
	if err != nil || got.PrincipalID != "user-b" {
		t.Fatalf("wrong simulation identity: %+v %v", got, err)
	}
	if _, err := r.LookupSimulation(j.ContextID, "0x00", time.Unix(1020, 0)); err == nil {
		t.Fatal("context accepted for another request")
	}
}

func TestSimulationRejectsStateAndBlockOverrides(t *testing.T) {
	call := `{"from":"0x1111111111111111111111111111111111111111","to":"0x2222222222222222222222222222222222222222","data":"0x12345678"}`
	for _, test := range []struct{ method, options string }{
		{"eth_call", `{"0x2222222222222222222222222222222222222222":{"code":"0x60005460005260206000f3"}}`},
		{"eth_estimateGas", `{"0x2222222222222222222222222222222222222222":{"balance":"0xff"}}`},
		{"debug_traceCall", `{"stateOverrides":{"0x2222222222222222222222222222222222222222":{"code":"0x60005460005260206000f3"}}}`},
		{"debug_traceCall", `{"blockOverrides":{"time":"0x0"}}`},
	} {
		for _, dry := range []bool{false, true} {
			_, err := EncodeSimulation(SimulationRequest{Method: test.method, Params: json.RawMessage(`[` + call + `,"latest",` + test.options + `]`), DryRun: dry})
			if err == nil {
				t.Errorf("state substitution accepted: %s dry=%v", test.method, dry)
			}
		}
	}
}
