package server

import (
	"context"
	"encoding/hex"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/explorer"
	"privacy-proxy/internal/rbac"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestExplorerRedactorWiring_FullStack is the wiring-drift watchdog
// for the explorer-side log filter. It exists because the
// pre-this-PR codebase shipped RD-888 / RD-889 / RD-890 with the
// EventRuleChecker resolver wired only from unit tests — production
// startup never called SetEventRuleChecker, so the entire tri-state
// event-rule check (Phase 4 of RedactLogs) was dead at runtime. The
// existing unit tests in redactor_test.go all injected a stub via
// engine.SetEventRuleChecker(...), so they couldn't catch the gap.
//
// This test exercises the production wiring helper
// (wireExplorerRedactor) against a real database and asserts:
//
//  1. After wiring, every Set*Resolver method on RedactionEngine maps
//     to a non-nil resolver. Reflection-based so a future Set5Resolver
//     method auto-fails until wireExplorerRedactor learns about it.
//  2. The wired engine actually enforces the rules end-to-end:
//     - null event_rules ⇒ deny (RD-888 fix is alive)
//     - allowlist ⇒ only listed topic0 passes
//     - allowlist + ParamRule(must_be:self) ⇒ topic1 must encode
//     the viewer's address (this fact alone failed in pre-fix
//     code because EventRuleInfo had no ParamRules field)
//     - tier-2 org admin ⇒ ABI-less contract logs visible
//     - non-admin viewer + ABI-less contract ⇒ logs dropped
//
// If any of these regresses, this test stays red, and so does the PR.
//
// The test uses testcontainers Postgres — same pattern as
// admin_event_rules_test.go.
func TestExplorerRedactorWiring_FullStack(t *testing.T) {
	ctx := context.Background()

	dbURL := sharedTestDBURL(t)

	database, err := db.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	require.NoError(t, db.ResetTestDatabase(database))

	// ----- Fixture -------------------------------------------------------
	// One org, four contracts:
	//   contractRules    — ABI registered, viewer has event_rules:[Transfer]
	//   contractParam    — ABI registered, viewer has event_rules with
	//                      a param-rule {topic0:Transfer, params:[{0,self}]}
	//   contractDeny     — ABI registered, viewer has event_rules:null (deny)
	//   contractNoABI    — NO ABI, viewer has wildcard event_rules
	// Two viewers:
	//   "did:viewer:user"    — granted on contractRules / contractParam /
	//                          contractDeny / contractNoABI (deny on contractNoABI by default
	//                          since no admin claim and no ABI)
	//   "did:viewer:orgadmin"— is_org_admin in this org (tier-2 admin
	//                          bypass — should see logs from contractNoABI)
	// Linked addresses for "did:viewer:user" include `viewerLinked` so
	// the param-rule "self" check can fire.

	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "wiring-test", Name: "WiringTest", Settings: map[string]any{},
	}))

	// Group with claims=[] (granted via grant) — used by the regular viewer.
	grantedGID := wiringCreateGroup(t, database, orgID, "wiring-granted", nil, false)
	// Group flagged as is_org_admin — used by the admin viewer.
	orgAdminGID := wiringCreateGroup(t, database, orgID, "wiring-orgadmin", nil, true)

	contractRules := "0x1111111111111111111111111111111111111111"
	contractParam := "0x2222222222222222222222222222222222222222"
	contractDeny := "0x3333333333333333333333333333333333333333"
	contractNoABI := "0x4444444444444444444444444444444444444444"

	// All three "rules" contracts get a real ABI so the deny-when-no-ABI
	// gate stays out of the way for these tests; contractNoABI gets none.
	rulesCID := wiringCreateContractWithABI(t, database, orgID, contractRules, "Rules", erc20ABI)
	paramCID := wiringCreateContractWithABI(t, database, orgID, contractParam, "Param", erc20ABI)
	denyCID := wiringCreateContractWithABI(t, database, orgID, contractDeny, "Deny", erc20ABI)
	noABICID := wiringCreateContract(t, database, orgID, contractNoABI, "NoABI") // no ABI, no metadata

	transferTopic := "0x" + topicHex("Transfer(address,address,uint256)")
	approvalTopic := "0x" + topicHex("Approval(address,address,uint256)")

	// Grant: viewer's group has Transfer-only event_rules on contractRules.
	wiringCreateGrant(t, database, rulesCID, grantedGID, &rbac.EventRulesField{
		Rules: []rbac.EventRule{{Topic0: transferTopic, Name: "Transfer"}},
	})
	// Grant: viewer's group has Transfer with self-on-param-0 on contractParam.
	wiringCreateGrant(t, database, paramCID, grantedGID, &rbac.EventRulesField{
		Rules: []rbac.EventRule{{
			Topic0:     transferTopic,
			Name:       "Transfer",
			ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}},
		}},
	})
	// Grant: viewer's group has nil event_rules on contractDeny (null in DB).
	wiringCreateGrant(t, database, denyCID, grantedGID, nil)
	// Grant: viewer's group has wildcard event_rules on contractNoABI.
	wiringCreateGrant(t, database, noABICID, grantedGID, &rbac.EventRulesField{Wildcard: true})

	// Org admin doesn't need explicit grants; is_org_admin grants admin
	// on every org contract.

	// User + linked address. The viewer's address is what the param-rule
	// "self" comparison checks against, so we need it on file.
	viewerLinked := "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
	wiringCreateUserInGroup(t, database, "did:viewer:user", grantedGID)
	require.NoError(t, database.SystemLinkEthAddress(ctx, "did:viewer:user", viewerLinked))
	wiringCreateUserInGroup(t, database, "did:viewer:orgadmin", orgAdminGID)

	// ----- Wire the redactor exactly as production does. ----------------
	// The first arg (ContractStore) is only used when ABIResolver is
	// nil; since wireExplorerRedactor wires the resolver, we pass a
	// no-op stub.
	accessCtrl := rbac.NewAccessController(database, 1*time.Minute)
	t.Cleanup(accessCtrl.Stop)
	engine := explorer.NewRedactionEngine(noopContractStore{}, database)
	// RD-939: wireExplorerRedactor now also wires the log-participant
	// store. The test asserts wiring completeness via reflection
	// (expectedSetters below); to satisfy SetLogParticipantStore we pass
	// a stub that returns "no participants" for every query — this test
	// isn't exercising the log path (RedactTransactions tests cover
	// that), only the wiring.
	wireExplorerRedactor(engine, database, accessCtrl, noopLogParticipantStore{}, nil)

	// ----- (1) Wiring completeness check. ------------------------------
	// Enumerate every interface-typed Set* method on *RedactionEngine
	// and compare against the expected list. If someone adds a fourth
	// resolver-style setter to RedactionEngine without updating
	// wireExplorerRedactor (and this list), this assertion fires —
	// before the gap can ship as another silently-disabled resolver.
	expectedSetters := []string{"SetABIResolver", "SetAdminContractsResolver", "SetCapturedAudienceResolver", "SetDynamicPayloadAllowedResolver", "SetEventRuleChecker", "SetLogParticipantStore", "SetVisibleToUnlockResolver"}
	require.Equal(t, sortedStrings(expectedSetters), interfaceTypedSetters(engine),
		"wireExplorerRedactor must wire every interface-typed Set* method on RedactionEngine; mismatch means a setter was added/removed without updating the helper. See wireExplorerRedactor doc-comment.")

	// ----- (2) End-to-end behaviour assertions. ------------------------
	// Build representative logs for each contract.
	tr := transferTopic
	ap := approvalTopic
	// Viewer-linked-address as topic1 (left-padded to 32 bytes).
	viewerTopic := zeroPadAddrToTopic(viewerLinked)
	otherTopic := zeroPadAddrToTopic("0xdeaddeaddeaddeaddeaddeaddeaddeaddeaddead")

	logs := []explorer.Log{
		{ID: 1, Address: contractRules, TxHash: "0xtx1", Topic0: &tr, Topic1: &otherTopic, Data: "0x"},
		{ID: 2, Address: contractRules, TxHash: "0xtx2", Topic0: &ap, Topic1: &otherTopic, Data: "0x"},  // not allowlisted
		{ID: 3, Address: contractParam, TxHash: "0xtx3", Topic0: &tr, Topic1: &viewerTopic, Data: "0x"}, // self => pass
		{ID: 4, Address: contractParam, TxHash: "0xtx4", Topic0: &tr, Topic1: &otherTopic, Data: "0x"},  // not self => drop
		{ID: 5, Address: contractDeny, TxHash: "0xtx5", Topic0: &tr, Topic1: &otherTopic, Data: "0x"},   // null rules => drop
		{ID: 6, Address: contractNoABI, TxHash: "0xtx6", Topic0: &tr, Topic1: &otherTopic, Data: "0x"},  // no ABI => drop for non-admin
	}

	// Regular viewer.
	out, err := engine.RedactLogs(ctx, logs, "did:viewer:user")
	require.NoError(t, err)
	gotIDs := make(map[int64]bool)
	for _, l := range out {
		gotIDs[l.ID] = true
	}
	require.True(t, gotIDs[1], "Transfer on contractRules should pass for granted viewer")
	require.False(t, gotIDs[2], "Approval on contractRules NOT in allowlist — must drop")
	require.True(t, gotIDs[3], "Transfer w/ self-on-topic1 on contractParam — must pass param rule")
	require.False(t, gotIDs[4], "Transfer w/ other-on-topic1 on contractParam — must FAIL param rule (regression #2)")
	require.False(t, gotIDs[5], "null event_rules on contractDeny — must drop (regression #1: RD-888 wiring)")
	require.False(t, gotIDs[6], "no ABI on contractNoABI — must drop for non-admin viewer (RD-889)")

	// Org admin should bypass the no-ABI gate but is otherwise subject
	// to event_rules. Since the org admin has no explicit grant on
	// contractRules / contractParam / contractDeny, the per-grant rules
	// don't apply — but is_org_admin synthesises an admin claim on every
	// org contract, which means GetEventRules returns wildcard via the
	// resolver.
	out, err = engine.RedactLogs(ctx, logs, "did:viewer:orgadmin")
	require.NoError(t, err)
	gotIDs = make(map[int64]bool)
	for _, l := range out {
		gotIDs[l.ID] = true
	}
	require.True(t, gotIDs[6], "org admin on contractNoABI — must bypass deny gate (RD-890)")
}

// TestExplorerRedactorWiring_RecordAudience is the explorer half of the RD-1206
// rule-71 symmetry guard. It proves the explorer redactor admits/hides a governed
// dynamic-payload event log identically to the RPC filter — the parity asserted
// by TestFilterEventLogs_RecordAudienceAdditive (internal/rbac) and
// TestRecordAudienceGate_EventLogAdmits (internal/server) on the RPC side.
//
// Setup mirrors those tests: a contract with a method policy governing
// PaymentProcessed(string,uint8) (whose `string` param is dynamic → M15 would
// drop the log for a non-admin viewer) and a captured audience for record PAY-1.
// Two viewers both hold a wildcard-event grant on the contract (VisibilityFull —
// the eligibility bound), so the ONLY thing that decides visibility is the
// record-audience admit:
//   - a viewer IN the captured audience sees the log (additive admit, M15 bypassed);
//   - a viewer NOT in the audience does not (falls through to the M15 drop).
//
// This is the coherence the rule-71 handoff requires: same event, same verdict
// via eth_getLogs and the explorer, through the ONE shared decision
// rbac.EventAudienceAdmits.
func TestExplorerRedactorWiring_RecordAudience(t *testing.T) {
	ctx := context.Background()

	dbURL := sharedTestDBURL(t)
	database, err := db.New(dbURL)
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	require.NoError(t, db.ResetTestDatabase(database))

	orgID := uuid.New().String()
	require.NoError(t, database.CreateOrganization(ctx, &rbac.Organization{
		ID: orgID, Slug: "audience-test", Name: "AudienceTest", Settings: map[string]any{},
	}))

	// One group, granted (wildcard events) on the policied contract. Both
	// viewers join it so both clear the VisibilityFull eligibility gate; only
	// the captured audience separates them.
	grantedGID := wiringCreateGroup(t, database, orgID, "audience-granted", nil, false)

	contractAudience := "0x5555555555555555555555555555555555555555"
	audienceCID := wiringCreateContractWithABI(t, database, orgID, contractAudience, "Audience", audienceEventsABI)
	// Attach the method policy (CreateContract does not persist it).
	require.NoError(t, database.UpdateContractMethodPolicies(ctx, audienceCID, []byte(audienceEventsPolicy)))

	// Wildcard event grant → both viewers get VisibilityFull on the contract.
	wiringCreateGrant(t, database, audienceCID, grantedGID, &rbac.EventRulesField{Wildcard: true})

	// Two viewers: alice is in PAY-1's captured audience, eve is not. Both are
	// members of the granted group (both eligible / VisibilityFull).
	wiringCreateUserInGroup(t, database, "did:viewer:alice", grantedGID)
	wiringCreateUserInGroup(t, database, "did:viewer:eve", grantedGID)

	// Seed PAY-1's captured audience = {alice} via the real outbox → promote
	// path (the same storage the capture half writes at settle time).
	require.NoError(t, database.EnqueuePendingRecordCaptures(ctx, "0xseedtx", orgID, contractAudience, "did:viewer:alice",
		[]rbac.CapturedWrite{{RecordType: "payment", RecordKey: "PAY-1", Field: "audience", Value: "did:viewer:alice", Merge: "union"}}))
	pending, err := database.ListDuePendingRecordCaptures(ctx, 10)
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.NoError(t, database.PromoteRecordCapture(ctx, pending[0]))

	// Wire the redactor exactly as production does.
	accessCtrl := rbac.NewAccessController(database, 1*time.Minute)
	t.Cleanup(accessCtrl.Stop)
	engine := explorer.NewRedactionEngine(noopContractStore{}, database)
	wireExplorerRedactor(engine, database, accessCtrl, noopLogParticipantStore{}, nil)

	// Build the governed PaymentProcessed(PAY-1, status=1) log. Its `string`
	// param is dynamic → M15 drops it for a non-admin viewer unless the
	// record-audience admit fires first.
	topics, dataHex := audienceProcessedLog(t, "PAY-1")
	require.NotEmpty(t, topics)
	topic0 := topics[0]
	log := explorer.Log{ID: 1, Address: contractAudience, TxHash: "0xtxpay1", Topic0: &topic0, Data: dataHex}

	// Sanity: baseline (before the audience admit) drops the dynamic-payload
	// log even for an eligible viewer. Prove it by asking for eve, who is
	// eligible (VisibilityFull) but NOT in the audience — she must not see it.
	outEve, err := engine.RedactLogs(ctx, []explorer.Log{log}, "did:viewer:eve")
	require.NoError(t, err)
	eveSees := false
	for _, l := range outEve {
		if l.ID == 1 {
			eveSees = true
		}
	}
	require.False(t, eveSees, "eligible viewer NOT in the captured audience must NOT see the governed dynamic-payload log (M15 drop; record gate abstains)")

	// alice is in the captured audience → the additive admit passes the log
	// through unredacted, bypassing M15.
	outAlice, err := engine.RedactLogs(ctx, []explorer.Log{log}, "did:viewer:alice")
	require.NoError(t, err)
	aliceSees := false
	for _, l := range outAlice {
		if l.ID == 1 {
			aliceSees = true
		}
	}
	require.True(t, aliceSees, "viewer IN the captured audience must see the governed event log (RD-1206 rule 71 explorer parity)")
}

// interfaceTypedSetters returns the names of every Set* method on
// *RedactionEngine whose single argument is an interface — those are
// the resolver/checker setters the wiring helper must call.
// Sorted for stable comparison.
func interfaceTypedSetters(engine *explorer.RedactionEngine) []string {
	typ := reflect.TypeOf(engine)
	var out []string
	for i := 0; i < typ.NumMethod(); i++ {
		m := typ.Method(i)
		if !strings.HasPrefix(m.Name, "Set") {
			continue
		}
		// Method type for pointer receivers: in[0]=receiver, in[1]=arg.
		if m.Type.NumIn() != 2 {
			continue
		}
		if m.Type.In(1).Kind() != reflect.Interface {
			continue
		}
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

// sortedStrings returns a sorted copy of s — convenience wrapper so
// the assertion message reads well.
func sortedStrings(s []string) []string {
	out := make([]string, len(s))
	copy(out, s)
	sort.Strings(out)
	return out
}

// ----- DB helpers (kept tiny on purpose) -----

func wiringCreateGroup(t *testing.T, database *db.DB, orgID, slug string, claims []rbac.Claim, isOrgAdmin bool) string {
	t.Helper()
	ctx := context.Background()
	gid := uuid.New().String()
	require.NoError(t, database.CreateGroup(ctx, &rbac.Group{
		ID: gid, OrgID: orgID, Slug: slug, Name: slug, Depth: 0, Path: slug, IsOrgAdmin: isOrgAdmin,
	}))
	require.NoError(t, database.CreateGroupAccess(ctx, &rbac.GroupAccess{
		ID: uuid.New().String(), GroupID: gid, AllowedMethods: []string{"eth_call", "eth_getLogs"}, Claims: claims,
	}))
	return gid
}

func wiringCreateUserInGroup(t *testing.T, database *db.DB, did, groupID string) string {
	t.Helper()
	ctx := context.Background()
	uid := uuid.New().String()
	require.NoError(t, database.CreateUser(ctx, &rbac.User{
		ID: uid, ExternalID: did, KYC: true, Banned: false, Metadata: map[string]any{},
	}))
	require.NoError(t, database.CreateMembership(ctx, &rbac.UserMembership{
		ID: uuid.New().String(), UserID: uid, GroupID: groupID, Source: rbac.MembershipSourceAdmin,
	}))
	return uid
}

func wiringCreateContract(t *testing.T, database *db.DB, orgID, address, name string) string {
	t.Helper()
	ctx := context.Background()
	cid := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: cid, OrgID: orgID, Address: strings.ToLower(address), Name: name, Metadata: map[string]any{},
	}))
	return cid
}

func wiringCreateContractWithABI(t *testing.T, database *db.DB, orgID, address, name, abiJSON string) string {
	t.Helper()
	ctx := context.Background()
	cid := uuid.New().String()
	require.NoError(t, database.CreateContract(ctx, &rbac.Contract{
		ID: cid, OrgID: orgID, Address: strings.ToLower(address), Name: name, ABI: abiJSON, Metadata: map[string]any{},
	}))
	return cid
}

func wiringCreateGrant(t *testing.T, database *db.DB, contractID, groupID string, eventRules *rbac.EventRulesField) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, database.CreateContractGrant(ctx, &rbac.ContractGrant{
		ID: uuid.New().String(), ContractID: contractID, GroupID: groupID, Functions: nil, EventRules: eventRules,
	}))
}

// topicHex computes keccak256 of an event signature, returning bare hex
// (no 0x prefix), lowercase. Equivalent to the explorer test helper
// eventTopic0 but local to this file to avoid cross-package coupling.
func topicHex(sig string) string {
	h := crypto.Keccak256([]byte(sig))
	return hex.EncodeToString(h)
}

// zeroPadAddrToTopic encodes a 20-byte address as a 32-byte topic
// value — left-padded with 12 zero bytes.
func zeroPadAddrToTopic(addr string) string {
	a := strings.ToLower(strings.TrimPrefix(addr, "0x"))
	return "0x" + strings.Repeat("0", 64-len(a)) + a
}

// noopContractStore satisfies explorer.ContractStore for the wiring
// test. The redactor only consults ContractStore when ABIResolver is
// nil — wireExplorerRedactor sets the resolver so this stub is never
// hit, but the constructor still needs *something* non-nil.
type noopContractStore struct{}

func (noopContractStore) GetContract(_ context.Context, _ string) (*explorer.Contract, error) {
	return nil, nil
}

// noopLogParticipantStore satisfies explorer.LogParticipantStore for the
// wiring test. RD-939's RedactTransactions tests live in
// internal/explorer/redactor_test.go and exercise the real signal; this
// stub exists only so wireExplorerRedactor sees a non-nil dependency
// during the wiring-completeness check.
type noopLogParticipantStore struct{}

func (noopLogParticipantStore) FindLogParticipantTxs(_ context.Context, _ []string, _ []string) (map[string]bool, error) {
	return map[string]bool{}, nil
}
