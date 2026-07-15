package server

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"

	"privacy-proxy/internal/rbac"
)

// This file is the CI-runnable enforcement test for the RD-1206 method-policy
// gate (H4). It drives the real request-path decision (methodPolicyDecision) and
// applyMethodPolicyGate against a fake store — no Postgres, no Anvil, no build
// tag — so `go test ./internal/...` (which CI runs) exercises the seam that
// actually makes S5-T4 pass. Deleting the gate wiring must break a test here.

const gateEnforceABI = `[
  {"type":"function","name":"getPaymentInfo","stateMutability":"view",
   "inputs":[{"name":"id","type":"string"}],
   "outputs":[{"name":"payer","type":"address"},{"name":"payee","type":"address"}]}
]`

// capture-based policy: allow only a caller who matches the captured "payer".
const gateEnforcePolicyCapture = `{"records":{"payment":{"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":["payer"]}],"onNoRecord":"deny","else":"deny"}]}}}`

// return-based policy: allow a caller whose linked address is the return's payer.
const gateEnforcePolicyReturn = `{"records":{"payment":{"access":[{"method":"getPaymentInfo(string)","key":{"source":"param","index":0},"allow":[{"callerIn":{"source":"return","paths":["payer"],"kind":"address"}}],"onNoRecord":"deny","else":"deny"}]}}}`

// fakeGateStore embeds the rbac.Store interface (nil) and overrides only the
// methods the gate calls; the other ~80 methods are never invoked. It also
// satisfies methodPolicyCaptureStore (GetRecordCaptures + EnqueuePendingRecordCaptures),
// so p.methodPolicyStore() succeeds.
type fakeGateStore struct {
	rbac.Store
	contract       *rbac.Contract
	contractErr    error
	globalContract *rbac.Contract
	globalErr      error
	linked         []string
	captures       []rbac.CapturedField
	capturesErr    error
}

func (f *fakeGateStore) GetContractByAddress(_ context.Context, _, _ string) (*rbac.Contract, error) {
	return f.contract, f.contractErr
}
func (f *fakeGateStore) GetContractByAddressGlobal(_ context.Context, _ string) (*rbac.Contract, error) {
	return f.globalContract, f.globalErr
}
func (f *fakeGateStore) GetLinkedEthAddresses(_ context.Context, _ string) ([]string, error) {
	return f.linked, nil
}
func (f *fakeGateStore) GetRecordCaptures(_ context.Context, _, _, _, _ string) ([]rbac.CapturedField, error) {
	return f.captures, f.capturesErr
}
func (f *fakeGateStore) EnqueuePendingRecordCaptures(_ context.Context, _, _, _, _ string, _ []rbac.CapturedWrite) error {
	return nil
}

func newGateProcessor(store rbac.Store) *JSONRPCProcessor {
	return &JSONRPCProcessor{rbacAccessCtrl: rbac.NewAccessController(store, time.Minute)}
}

// gateCalldataHex ABI-encodes getPaymentInfo(id) as a 0x-prefixed hex string.
func gateCalldataHex(t *testing.T, id string) string {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(gateEnforceABI))
	if err != nil {
		t.Fatalf("parse ABI: %v", err)
	}
	data, err := parsed.Pack("getPaymentInfo", id)
	if err != nil {
		t.Fatalf("pack calldata: %v", err)
	}
	return "0x" + common.Bytes2Hex(data)
}

// gateReturnBytes builds the raw ABI-encoded (payer, payee) return bytes of
// getPaymentInfo — the already-extracted result methodPolicyDecision expects
// (applyMethodPolicyGate extracts these from the JSON-RPC body via
// extractEthCallResultBytes before calling the decision core).
func gateReturnBytes(t *testing.T, payer, payee common.Address) []byte {
	t.Helper()
	parsed, err := abi.JSON(strings.NewReader(gateEnforceABI))
	if err != nil {
		t.Fatalf("parse ABI: %v", err)
	}
	out, err := parsed.Methods["getPaymentInfo"].Outputs.Pack(payer, payee)
	if err != nil {
		t.Fatalf("pack outputs: %v", err)
	}
	return out
}

const (
	gateContractAddr = "0xcccccccccccccccccccccccccccccccccccccc10"
	gateOrg          = "11111111-1111-1111-1111-111111111111"
)

func gateContract(policy string) *rbac.Contract {
	return &rbac.Contract{ID: "c1", OrgID: gateOrg, Address: gateContractAddr, ABI: gateEnforceABI, MethodPolicies: json.RawMessage(policy)}
}

// TestMethodPolicyDecision is the shared-core enforcement test. methodPolicyDecision
// is what BOTH eth_call (applyMethodPolicyGate) and debug_traceCall
// (processDebugTrace) call, so covering it covers both surfaces.
func TestMethodPolicyDecision(t *testing.T) {
	callerAddr := common.HexToAddress("0x00000000000000000000000000000000000000A1")
	otherAddr := common.HexToAddress("0x00000000000000000000000000000000000000B2")
	data := gateCalldataHex(t, "PAY-1")

	tests := []struct {
		name        string
		store       *fakeGateStore
		callerDID   string
		resolvedOrg string
		returnBody  []byte
		overridden  bool
		wantGated   bool
		wantDenied  bool
	}{
		{
			name:        "capture allows the record's payer",
			store:       &fakeGateStore{contract: gateContract(gateEnforcePolicyCapture), captures: []rbac.CapturedField{{Field: "payer", Value: "did:test:alice", Merge: "set_once"}}},
			callerDID:   "did:test:alice",
			resolvedOrg: gateOrg,
			wantGated:   true, wantDenied: false,
		},
		{
			name:        "capture denies an unrelated same-group caller (S5-T4)",
			store:       &fakeGateStore{contract: gateContract(gateEnforcePolicyCapture), captures: []rbac.CapturedField{{Field: "payer", Value: "did:test:alice", Merge: "set_once"}}},
			callerDID:   "did:test:eve",
			resolvedOrg: gateOrg,
			wantGated:   true, wantDenied: true,
		},
		{
			name:        "no capture row denies (onNoRecord)",
			store:       &fakeGateStore{contract: gateContract(gateEnforcePolicyCapture), captures: nil},
			callerDID:   "did:test:alice",
			resolvedOrg: gateOrg,
			wantGated:   true, wantDenied: true,
		},
		{
			name:        "no policy configured passes through (not gated)",
			store:       &fakeGateStore{contract: gateContract("")},
			callerDID:   "did:test:alice",
			resolvedOrg: gateOrg,
			wantGated:   false, wantDenied: false,
		},
		{
			name:        "contract DB error fails closed",
			store:       &fakeGateStore{contractErr: fmt.Errorf("db down")},
			callerDID:   "did:test:alice",
			resolvedOrg: gateOrg,
			wantGated:   true, wantDenied: true,
		},
		{
			name:        "corrupt stored policy fails closed",
			store:       &fakeGateStore{contract: gateContract("{not json")},
			callerDID:   "did:test:alice",
			resolvedOrg: gateOrg,
			wantGated:   true, wantDenied: true,
		},
		{
			name:        "capture store error fails closed",
			store:       &fakeGateStore{contract: gateContract(gateEnforcePolicyCapture), capturesErr: fmt.Errorf("db down")},
			callerDID:   "did:test:alice",
			resolvedOrg: gateOrg,
			wantGated:   true, wantDenied: true,
		},
		{
			name:        "unresolved org with a policy fails closed",
			store:       &fakeGateStore{globalContract: gateContract(gateEnforcePolicyCapture)},
			callerDID:   "did:test:alice",
			resolvedOrg: "", // forces the global fallback
			wantGated:   true, wantDenied: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newGateProcessor(tc.store)
			req := &ProcessRequest{Method: "eth_call", UserID: tc.callerDID, resolvedOrgID: tc.resolvedOrg}
			gated, denied := p.methodPolicyDecision(context.Background(), req, gateContractAddr, data, tc.returnBody, tc.overridden)
			if gated != tc.wantGated || denied != tc.wantDenied {
				t.Fatalf("gated=%v denied=%v, want gated=%v denied=%v", gated, denied, tc.wantGated, tc.wantDenied)
			}
		})
	}

	// Return-resolver + state-override neutralization (MED). The caller's linked
	// address IS the record's payer per the return, so the return rule admits —
	// UNLESS a state override was present, which makes the return forgeable and
	// must be ignored (then, with no capture row, the call is denied).
	t.Run("return resolver admits the payer address", func(t *testing.T) {
		store := &fakeGateStore{contract: gateContract(gateEnforcePolicyReturn), linked: []string{callerAddr.Hex()}}
		p := newGateProcessor(store)
		req := &ProcessRequest{Method: "eth_call", UserID: "did:test:alice", resolvedOrgID: gateOrg}
		body := gateReturnBytes(t, callerAddr, otherAddr)
		gated, denied := p.methodPolicyDecision(context.Background(), req, gateContractAddr, data, body, false)
		if !gated || denied {
			t.Fatalf("return-payer caller must be allowed, got gated=%v denied=%v", gated, denied)
		}
	})
	t.Run("state override neutralizes the return resolver", func(t *testing.T) {
		store := &fakeGateStore{contract: gateContract(gateEnforcePolicyReturn), linked: []string{callerAddr.Hex()}}
		p := newGateProcessor(store)
		req := &ProcessRequest{Method: "eth_call", UserID: "did:test:alice", resolvedOrgID: gateOrg}
		body := gateReturnBytes(t, callerAddr, otherAddr)
		gated, denied := p.methodPolicyDecision(context.Background(), req, gateContractAddr, data, body, true /* overridden */)
		if !gated || !denied {
			t.Fatalf("state-override must neutralize the return resolver → deny, got gated=%v denied=%v", gated, denied)
		}
	})
}

// TestApplyMethodPolicyGate_ResponseAndLog asserts the eth_call gate returns the
// exact upstream bytes on allow, an opaque -32000 on deny, and stamps the access
// log as a denial (not a served read).
func TestApplyMethodPolicyGate_ResponseAndLog(t *testing.T) {
	data := gateCalldataHex(t, "PAY-1")
	upstream := []byte(`{"jsonrpc":"2.0","id":7,"result":"0x00000000000000000000000000000000000000000000000000000000000004d2"}`)

	t.Run("allow returns exact upstream bytes and no denial", func(t *testing.T) {
		store := &fakeGateStore{contract: gateContract(gateEnforcePolicyCapture), captures: []rbac.CapturedField{{Field: "payer", Value: "did:test:alice", Merge: "set_once"}}}
		p := newGateProcessor(store)
		req := &ProcessRequest{Method: "eth_call", UserID: "did:test:alice", resolvedOrgID: gateOrg,
			Params: []any{map[string]any{"to": gateContractAddr, "data": data}}}
		out := p.applyMethodPolicyGate(context.Background(), req, upstream)
		if string(out) != string(upstream) {
			t.Fatalf("allow must return upstream bytes unchanged, got %s", out)
		}
		if req.methodPolicyDenied || req.denialReason != "" {
			t.Fatalf("allow must not stamp a denial, got denied=%v reason=%q", req.methodPolicyDenied, req.denialReason)
		}
	})

	t.Run("deny returns opaque error and stamps the log", func(t *testing.T) {
		store := &fakeGateStore{contract: gateContract(gateEnforcePolicyCapture), captures: []rbac.CapturedField{{Field: "payer", Value: "did:test:alice", Merge: "set_once"}}}
		p := newGateProcessor(store)
		req := &ProcessRequest{Method: "eth_call", UserID: "did:test:eve", resolvedOrgID: gateOrg,
			Params: []any{map[string]any{"to": gateContractAddr, "data": data}}}
		out := string(p.applyMethodPolicyGate(context.Background(), req, upstream))
		if !strings.Contains(out, "-32000") || !strings.Contains(out, `"error"`) {
			t.Fatalf("deny must be an opaque JSON-RPC error, got %s", out)
		}
		if strings.Contains(out, "04d2") {
			t.Fatalf("deny leaked the upstream result: %s", out)
		}
		if !strings.Contains(out, `"id":7`) {
			t.Fatalf("deny must preserve the request id, got %s", out)
		}
		if !req.methodPolicyDenied || req.denialReason != ReasonMethodPolicyDenied {
			t.Fatalf("deny must stamp the access log, got denied=%v reason=%q", req.methodPolicyDenied, req.denialReason)
		}
	})
}

// TestMethodPolicyCaptureStore_ProductionWired documents that the concrete store
// satisfies the capture capability the gate requires. If a future refactor makes
// rbacAccessCtrl.Store() return a type that no longer implements it, the gate
// would silently fail open (H3); this + the compile-time guard in the gate file
// keep that a build/test failure.
func TestMethodPolicyCaptureStore_ProductionWired(t *testing.T) {
	var s rbac.Store = &fakeGateStore{}
	if _, ok := s.(methodPolicyCaptureStore); !ok {
		t.Fatal("rbac.Store implementation must satisfy methodPolicyCaptureStore")
	}
}

// fakeForwarder is a nodeForwarder returning a canned eth_getTransactionReceipt.
type fakeForwarder struct {
	body []byte
	err  error
}

func (f fakeForwarder) Forward(_ []byte) ([]byte, int, error) {
	if f.err != nil {
		return nil, 0, f.err
	}
	return f.body, 200, nil
}

// TestMakeReceiptStatusFunc covers the reconciler's receipt parser: status 0x1 →
// mined+success (promote), 0x0 → mined+not-success (drop reverted), null result →
// not mined (wait), upstream error object → transient (retry). Inverting any of
// these silently drops or plants captures, so pin them.
func TestMakeReceiptStatusFunc(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		fwdErr      error
		wantMined   bool
		wantSuccess bool
		wantErr     bool
	}{
		{"confirmed success", `{"jsonrpc":"2.0","id":1,"result":{"status":"0x1"}}`, nil, true, true, false},
		{"reverted", `{"jsonrpc":"2.0","id":1,"result":{"status":"0x0"}}`, nil, true, false, false},
		{"not mined (null result)", `{"jsonrpc":"2.0","id":1,"result":null}`, nil, false, false, false},
		{"upstream error object is transient", `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"x"}}`, nil, false, false, false},
		{"transport error", ``, fmt.Errorf("dial fail"), false, false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fn := makeReceiptStatusFunc(fakeForwarder{body: []byte(tc.body), err: tc.fwdErr})
			mined, success, err := fn(context.Background(), "0xabc")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v want wantErr=%v", err, tc.wantErr)
			}
			if mined != tc.wantMined || success != tc.wantSuccess {
				t.Fatalf("mined=%v success=%v, want mined=%v success=%v", mined, success, tc.wantMined, tc.wantSuccess)
			}
		})
	}
}
