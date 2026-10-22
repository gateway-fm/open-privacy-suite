package rbac

import (
	"context"
	"errors"
	"testing"
	"time"
)

const admissionSigner = "0x1111111111111111111111111111111111111111"
const admissionTarget = "0x2222222222222222222222222222222222222222"

type admissionStore struct {
	fakeStore
	user    *User
	methods []string
	linked  []string
	linkErr error
	owner   string
	orgs    []string
}

func newAdmissionStore() *admissionStore {
	return &admissionStore{user: &User{ID: "principal-1", ExternalID: "did:test:alice", KYC: true}, methods: []string{"eth_call", "eth_sendTransaction", "eth_estimateGas", "debug_traceCall"}, linked: []string{admissionSigner}, owner: "org-1", orgs: []string{"org-1"}}
}
func (s *admissionStore) GetUserByExternalID(_ context.Context, id string) (*User, error) {
	if s.user != nil && s.user.ExternalID == id {
		return s.user, nil
	}
	return nil, nil
}
func (s *admissionStore) GetOrganization(_ context.Context, id string) (*Organization, error) {
	for _, org := range s.orgs {
		if org == id {
			return &Organization{ID: org}, nil
		}
	}
	return nil, nil
}
func (s *admissionStore) ListUserMembershipsWithDetails(context.Context, string) ([]*MembershipWithDetails, error) {
	var out []*MembershipWithDetails
	for _, org := range s.orgs {
		out = append(out, &MembershipWithDetails{Group: &Group{ID: "group-" + org, OrgID: org}})
	}
	return out, nil
}
func (s *admissionStore) ListActiveUserMembershipsWithDetails(ctx context.Context, userID string) ([]*MembershipWithDetails, error) {
	return s.ListUserMembershipsWithDetails(ctx, userID)
}
func (s *admissionStore) GetContractOwnerOrgID(context.Context, string) (string, error) {
	return s.owner, nil
}
func (s *admissionStore) GetCachedPermissions(_ context.Context, user, org string) (*EffectivePermissions, error) {
	return &EffectivePermissions{UserID: user, OrgID: org, AllowedMethods: s.methods, ContractAccess: map[string]ContractAccess{}, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (s *admissionStore) GetLinkedEthAddresses(context.Context, string) ([]string, error) {
	return s.linked, s.linkErr
}
func (s *admissionStore) IsOrgAdmin(context.Context, string) (bool, []string, error) {
	return false, nil, nil
}

func admissionRequest() *AccessCheckRequest {
	return &AccessCheckRequest{UserExternalID: "did:test:alice", Method: "eth_call", TargetAddress: admissionTarget, FunctionSelector: "0xdeadbeef", Params: []any{map[string]any{"from": admissionSigner, "to": admissionTarget, "data": "0xdeadbeef"}, "latest"}}
}

func TestExecutionAdmissionDoesNotUseLegacyContractOrOperationalRules(t *testing.T) {
	for _, method := range []string{"eth_call", "eth_sendTransaction", "eth_estimateGas"} {
		t.Run(method, func(t *testing.T) {
			store := newAdmissionStore()
			ctrl := NewAccessController(store, time.Minute)
			req := admissionRequest()
			req.Method = method
			if method != "eth_call" {
				req.TargetAddress = ""
				req.Params = []any{map[string]any{"from": admissionSigner, "data": "0x60006000f3"}}
				req.RequiredClaims = []Claim{ClaimDeploy}
			}
			got, err := ctrl.CheckExecutionAdmission(context.Background(), req)
			if err != nil || !got.Allowed || got.UserID != "principal-1" || got.OrgID != "org-1" || got.Signer != admissionSigner {
				t.Fatalf("admission=%+v err=%v", got, err)
			}
		})
	}
}

func TestExecutionAdmissionRetainsIdentityAndMethodGates(t *testing.T) {
	for _, name := range []string{"anonymous", "unknown", "banned", "kyc", "method", "foreign-org", "unlinked", "lookup-error", "historical"} {
		t.Run(name, func(t *testing.T) {
			store := newAdmissionStore()
			req := admissionRequest()
			switch name {
			case "anonymous":
				req.UserExternalID = ""
			case "unknown":
				store.user = nil
			case "banned":
				store.user.Banned = true
			case "kyc":
				store.user.KYC = false
			case "method":
				store.methods = nil
			case "foreign-org":
				store.owner = "other"
			case "unlinked":
				store.linked = nil
			case "lookup-error":
				store.linkErr = errors.New("private store failure")
			case "historical":
				req.Params[1] = "0x1"
			}
			got, err := NewAccessController(store, time.Minute).CheckExecutionAdmission(context.Background(), req)
			if err == nil && got.Allowed {
				t.Fatalf("%s unexpectedly admitted", name)
			}
		})
	}
}

func TestExecutionAdmissionDefaultsOnlySoleLinkedSimulationSender(t *testing.T) {
	for _, count := range []int{0, 1, 2} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			store := newAdmissionStore()
			req := admissionRequest()
			delete(req.Params[0].(map[string]any), "from")
			if count == 0 {
				store.linked = nil
			}
			if count == 2 {
				store.linked = append(store.linked, admissionTarget)
			}
			got, err := NewAccessController(store, time.Minute).CheckExecutionAdmission(context.Background(), req)
			if count == 1 {
				if err != nil || !got.Allowed || got.Signer != admissionSigner {
					t.Fatalf("sole sender: %+v %v", got, err)
				}
			} else if err == nil && got.Allowed {
				t.Fatal("ambiguous sender admitted")
			}
		})
	}
}

func TestExecutionAdmissionHistoricalGuardCoversEverySimulation(t *testing.T) {
	for _, method := range []string{"eth_call", "eth_estimateGas", "debug_traceCall", "chain_traceCall"} {
		t.Run(method, func(t *testing.T) {
			store := newAdmissionStore()
			store.methods = append(store.methods, method)
			req := admissionRequest()
			req.Method = method
			if method == "chain_traceCall" {
				req.AccessMethod = "debug_traceCall"
			}
			req.Params[1] = "0x1"
			ctrl := NewAccessController(store, time.Minute)
			defer ctrl.Stop()
			got, err := ctrl.CheckExecutionAdmission(context.Background(), req)
			if err == nil && got.Allowed {
				t.Fatalf("historical simulation %s admitted", method)
			}
		})
	}
}
