package explorer

import (
	"context"
	"errors"
	"strings"
	"testing"

	"privacy-proxy/internal/rbac"
)

// The explorer takes the Full disclosure-grant fact from the shared fact
// builder (rbac.ResolveDisclosureGrants over SetDisclosureGrantResolver) and
// feeds it to the shared decisions, exactly as the JSON-RPC filters do:
// rbac.DecideTxEnvelope for transaction rows and rbac.DecideLogEmitter for
// events and the token-transfer rows derived from them. A Full grant shown in
// the visibility map without the shared fact (for example a failed lookup)
// opens nothing.

const (
	dgSubject = "0x5b1ec70000000000000000000000000000000001"
	dgPeer    = "0x9ee7000000000000000000000000000000000002"
	dgToken   = "0x70c3000000000000000000000000000000000003"
	dgViewer  = "0xa0d1000000000000000000000000000000000004"
	dgTx      = "0x1353000000000000000000000000000000000000000000000000000000000001"
	dgT0      = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	dgERC20   = `[{"type":"event","name":"Transfer","anonymous":false,"inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":true},{"name":"value","type":"uint256","indexed":false}]}]`
	dgValue   = "0x00000000000000000000000000000000000000000000000000000000000003e8"
)

type stubGrantResolver struct {
	addrs map[string][]string
	calls int
}

func (s *stubGrantResolver) FullDisclosureGrantAddresses(context.Context, string) (map[string][]string, error) {
	s.calls++
	return s.addrs, nil
}

const dgGrantID = "22222222-2222-2222-2222-222222222222"

// dgEngine: the viewer holds a contract grant on the token whose rules
// allowlist Transfer for transfers that name the viewer, and (when grant is
// true) a Full disclosure grant on the subject. The subject and the peer are
// other users' private addresses.
func dgEngine(profile rbac.ReadProfile, grant bool, withLog bool) (*RedactionEngine, *countingDB) {
	db := newCountingDB(VisibilityMap{dgSubject: VisibilityHidden, dgPeer: VisibilityHidden, dgToken: VisibilityFull, dgViewer: VisibilityFull}, []string{dgViewer})
	db.eventAccessMap = map[string]bool{dgToken: true}
	db.detailed[dgViewer] = AddressVisibility{Address: dgViewer, Level: VisibilityFull, Reason: ReasonOwnAddress, Visible: true}
	db.detailed[dgToken] = AddressVisibility{Address: dgToken, Level: VisibilityFull, Reason: ReasonRBACGroupMember, Visible: true}
	resolver := &stubGrantResolver{}
	if grant {
		// The visibility merge shows the subject at the grant's level.
		db.visMap[dgSubject] = VisibilityFull
		db.detailed[dgSubject] = AddressVisibility{Address: dgSubject, Level: VisibilityFull, Reason: ReasonDisclosureGrant, Visible: true}
		resolver.addrs = map[string][]string{dgSubject: {dgGrantID}}
	}
	engine := NewRedactionEngine(nil, db, profile)
	engine.SetDisclosureGrantResolver(resolver)
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{dgToken: dgERC20}})
	engine.SetEventRuleChecker(&stubEventRuleChecker{byAddr: map[string]EventRulesResolution{dgToken: {Rules: []EventRuleInfo{{
		Topic0:     dgT0,
		ParamRules: []rbac.ParamRule{{Index: 0, MustBe: "self"}, {Index: 1, MustBe: "self"}},
	}}}}})
	to := dgToken
	data := &countingTxData{txs: map[string]*Transaction{dgTx: {Hash: dgTx, From: dgSubject, To: &to}}, logs: map[string][]Log{}}
	if withLog {
		t0 := dgT0
		data.logs[dgTx] = []Log{{TxHash: dgTx, LogIndex: 0, Address: dgToken, Topic0: &t0, Topic1: sbTopic(dgSubject), Topic2: sbTopic(dgPeer), Data: dgValue}}
	}
	engine.SetTxDataResolver(data)
	return engine, db
}

func dgTransferLog() Log {
	t0 := dgT0
	return Log{TxHash: dgTx, LogIndex: 0, Address: dgToken, Topic0: &t0, Topic1: sbTopic(dgSubject), Topic2: sbTopic(dgPeer), Data: dgValue}
}

func TestRedactTransactions_FullGrantIsTheSharedFact(t *testing.T) {
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			peer := dgPeer
			tx := Transaction{Hash: dgTx, From: dgSubject, To: &peer, Value: "1000", InputData: "0xaa"}

			engine, _ := dgEngine(profile, true, false)
			stats := &RedactStats{}
			got, err := engine.RedactTransactions(context.Background(), []Transaction{tx}, "did:viewer", RedactOpts{Stats: stats})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].From != dgSubject || got[0].To == nil || *got[0].To != dgPeer || got[0].Value != "1000" {
				t.Fatalf("a Full grant over the sender admits the tx with the counterparty revealed: %+v", got)
			}
			if stats.GrantFullReveals != 1 {
				t.Fatalf("GrantFullReveals = %d, want 1", stats.GrantFullReveals)
			}

			// The visibility map still says "Full via disclosure grant", but the
			// shared fact (the grant lookup) does not: the grant opens nothing.
			engine, _ = dgEngine(profile, true, false)
			engine.SetDisclosureGrantResolver(&stubGrantResolver{})
			got, err = engine.RedactTransactions(context.Background(), []Transaction{tx}, "did:viewer")
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range got {
				if row.To != nil && *row.To == dgPeer {
					t.Fatalf("without the shared grant fact the counterparty must not be revealed: %+v", row)
				}
			}
			if profile.Strict() && len(got) != 0 {
				t.Fatalf("strict: without the shared grant fact the row is not admitted: %+v", got)
			}
		})
	}
}

func TestRedactLogs_FullGrantRevealsTheSubjectsEvent(t *testing.T) {
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			engine, _ := dgEngine(profile, true, true)
			stats := &RedactStats{}
			got, err := engine.RedactLogsWithOpts(context.Background(), []Log{dgTransferLog()}, "did:viewer", &RedactOpts{Stats: stats})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("the subject's Transfer is admitted through the Full grant, got %d", len(got))
			}
			if got[0].Topic2 == nil || !strings.EqualFold(*got[0].Topic2, *sbTopic(dgPeer)) {
				t.Fatalf("the Full grant returns the event in full (counterparty revealed): %+v", got[0])
			}
			if stats.GrantFullReveals != 1 {
				t.Fatalf("a grant-revealed event is counted for the audit trail: %d", stats.GrantFullReveals)
			}

			engine, _ = dgEngine(profile, false, true)
			got, err = engine.RedactLogs(context.Background(), []Log{dgTransferLog()}, "did:viewer")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Fatalf("without the grant the event does not name the viewer and is dropped: %+v", got)
			}
		})
	}
}

func TestRedactTransfers_FullGrantFollowsTheEventDecision(t *testing.T) {
	row := TokenTransfer{TxHash: dgTx, LogIndex: 0, TokenAddress: dgToken, From: dgSubject, To: dgPeer, Value: "1000"}
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			engine, _ := dgEngine(profile, true, true)
			stats := &RedactStats{}
			got, err := engine.RedactTransfers(context.Background(), []TokenTransfer{row}, "did:viewer", RedactOpts{Stats: stats})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].From != dgSubject || got[0].To != dgPeer || got[0].Value != "1000" {
				t.Fatalf("the row of an admitted grant event renders as the event does: %+v", got)
			}
			if stats.GrantFullReveals != 1 {
				t.Fatalf("GrantFullReveals = %d, want 1", stats.GrantFullReveals)
			}

			// The event behind the row is not available (or not admitted): the
			// grant does not keep the row on its own.
			engine, _ = dgEngine(profile, true, false)
			got, err = engine.RedactTransfers(context.Background(), []TokenTransfer{row}, "did:viewer")
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range got {
				if r.To == dgPeer {
					t.Fatalf("no admitted event, no grant reveal: %+v", r)
				}
			}
			if len(got) != 0 {
				t.Fatalf("no admitted event: the row follows the ordinary rules and is dropped: %+v", got)
			}
		})
	}
}

// Non-Full grants keep the explorer-only lens: the row survives, every party
// renders as a pseudonym or [PRIVATE], and nothing is attributed to a Full
// reveal. The shared Full fact is not consulted for them.
func TestRedactors_NonFullGrantLensUnchanged(t *testing.T) {
	for _, level := range []VisibilityLevel{VisibilityPseudonymous, VisibilityRedacted} {
		for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
			t.Run(string(level)+"/"+profile.String(), func(t *testing.T) {
				engine, db := dgEngine(profile, false, true)
				db.visMap[dgSubject] = level
				db.detailed[dgSubject] = AddressVisibility{Address: dgSubject, Level: level, Reason: ReasonDisclosureGrant, Visible: true}
				peer := dgPeer
				stats := &RedactStats{}
				txs, err := engine.RedactTransactions(context.Background(), []Transaction{{Hash: dgTx, From: dgSubject, To: &peer, Value: "1000"}}, "did:viewer", RedactOpts{Stats: stats})
				if err != nil {
					t.Fatal(err)
				}
				if len(txs) != 1 || txs[0].From == dgSubject || txs[0].To == nil || *txs[0].To == dgPeer {
					t.Fatalf("the %s lens keeps the row without real addresses: %+v", level, txs)
				}
				transfers, err := engine.RedactTransfers(context.Background(), []TokenTransfer{{TxHash: dgTx, TokenAddress: dgToken, From: dgSubject, To: dgPeer, Value: "1000"}}, "did:viewer", RedactOpts{Stats: stats})
				if err != nil {
					t.Fatal(err)
				}
				if len(transfers) != 1 || transfers[0].From == dgSubject || transfers[0].To == dgPeer {
					t.Fatalf("the %s lens keeps the transfer row without real addresses: %+v", level, transfers)
				}
				if stats.GrantFullReveals != 0 {
					t.Fatalf("a %s grant is never a Full reveal: %d", level, stats.GrantFullReveals)
				}
			})
		}
	}
}

// The grant set is looked up once per redaction call, whatever the number of
// rows.
func TestRedactors_OneGrantLookupPerCall(t *testing.T) {
	engine, _ := dgEngine(rbac.ReadProfileStrict, true, true)
	counter := &stubGrantResolver{addrs: map[string][]string{dgSubject: {dgGrantID}}}
	engine.SetDisclosureGrantResolver(counter)
	peer := dgPeer
	var txs []Transaction
	var logs []Log
	for i := 0; i < 10; i++ {
		txs = append(txs, Transaction{Hash: dgTx, From: dgSubject, To: &peer})
		logs = append(logs, dgTransferLog())
	}
	if _, err := engine.RedactTransactions(context.Background(), txs, "did:viewer"); err != nil {
		t.Fatal(err)
	}
	if counter.calls != 1 {
		t.Fatalf("RedactTransactions: %d grant lookups, want 1", counter.calls)
	}
	counter.calls = 0
	if _, err := engine.RedactLogs(context.Background(), logs, "did:viewer"); err != nil {
		t.Fatal(err)
	}
	if counter.calls != 1 {
		t.Fatalf("RedactLogs: %d grant lookups, want 1", counter.calls)
	}
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		engine, _ := dgEngine(profile, true, true)
		counter := &stubGrantResolver{addrs: map[string][]string{dgSubject: {dgGrantID}}}
		engine.SetDisclosureGrantResolver(counter)
		row := TokenTransfer{TxHash: dgTx, TokenAddress: dgToken, From: dgSubject, To: dgPeer, Value: "1"}
		if _, err := engine.RedactTransfers(context.Background(), []TokenTransfer{row, row, row}, "did:viewer"); err != nil {
			t.Fatal(err)
		}
		if counter.calls != 1 {
			t.Fatalf("%v RedactTransfers: %d grant lookups, want 1 (the event decision reuses the page's grant set)", profile, counter.calls)
		}
	}
}

// failingLogsTxData fails every log lookup.
type failingLogsTxData struct{}

func (failingLogsTxData) GetTransaction(context.Context, string) (*Transaction, error) {
	return nil, errors.New("indexer unavailable")
}

func (failingLogsTxData) GetLogsByTransaction(context.Context, string) ([]Log, error) {
	return nil, errors.New("indexer unavailable")
}

// Standard profile: when the events behind a Full-grant holder's transfer page
// cannot be loaded, the page is still served, without any grant reveal: the
// rows follow the ordinary rules (fail closed). Strict depends on those events
// for every row and still fails.
func TestRedactTransfers_GrantEventLookupFailure(t *testing.T) {
	row := TokenTransfer{TxHash: dgTx, LogIndex: 0, TokenAddress: dgToken, From: dgSubject, To: dgPeer, Value: "1000"}
	engine, _ := dgEngine(rbac.ReadProfileStandard, true, true)
	engine.SetTxDataResolver(failingLogsTxData{})
	got, err := engine.RedactTransfers(context.Background(), []TokenTransfer{row}, "did:viewer")
	if err != nil {
		t.Fatalf("standard: a failed event lookup must not fail the page: %v", err)
	}
	for _, r := range got {
		if r.To == dgPeer {
			t.Fatalf("no admitted event, no grant reveal: %+v", r)
		}
	}
	engine, _ = dgEngine(rbac.ReadProfileStrict, true, true)
	engine.SetTxDataResolver(failingLogsTxData{})
	if _, err := engine.RedactTransfers(context.Background(), []TokenTransfer{row}, "did:viewer"); err == nil {
		t.Fatal("strict: the event lookup failure is still an error")
	}
}

// withTransferEvents gives engine the Transfer(from -> to) event, emitted by
// token with an ERC-20 ABI, behind log index 0 of each tx hash: the event a
// token-transfer row of those transactions derives from.
func withTransferEvents(engine *RedactionEngine, token, from, to string, hashes ...string) {
	engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{strings.ToLower(token): dgERC20}})
	logs := map[string][]Log{}
	for _, h := range hashes {
		t0 := dgT0
		logs[strings.ToLower(h)] = []Log{{TxHash: h, LogIndex: 0, Address: token, Topic0: &t0, Topic1: sbTopic(from), Topic2: sbTopic(to), Data: dgValue}}
	}
	engine.SetTxDataResolver(&countingTxData{logs: logs})
}

// A Full grant on one party and a pseudonymous or redacted grant on the other:
// the Full lens wins, as JSON-RPC returns the whole transaction to this viewer.
func TestRedactTransactions_FullGrantLensWinsOverNonFull(t *testing.T) {
	for _, level := range []VisibilityLevel{VisibilityPseudonymous, VisibilityRedacted} {
		for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
			t.Run(string(level)+"/"+profile.String(), func(t *testing.T) {
				engine, db := dgEngine(profile, true, false)
				db.visMap[dgPeer] = level
				db.detailed[dgPeer] = AddressVisibility{Address: dgPeer, Level: level, Reason: ReasonDisclosureGrant, Visible: true}
				peer := dgPeer
				got, err := engine.RedactTransactions(context.Background(), []Transaction{{Hash: dgTx, From: dgSubject, To: &peer, Value: "1000", InputData: "0xaa"}}, "did:viewer")
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 1 || got[0].From != dgSubject || got[0].To == nil || *got[0].To != dgPeer || got[0].Value != "1000" || got[0].InputData != "0xaa" {
					t.Fatalf("the Full lens shows the whole transaction: %+v", got)
				}
			})
		}
	}
}

// A deployment by the grant subject is shown as the subject sees it, the
// created contract included: JSON-RPC returns it in the receipt.
func TestRedactTransactions_FullGrantDeploymentShowsContract(t *testing.T) {
	const created = "0xc4ea7ed000000000000000000000000000000005"
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			engine, db := dgEngine(profile, true, false)
			db.visMap[created] = VisibilityRedacted
			db.detailed[created] = AddressVisibility{Address: created, Level: VisibilityRedacted, Reason: ReasonNoAccess}
			ca := created
			got, err := engine.RedactTransactions(context.Background(), []Transaction{{Hash: dgTx, From: dgSubject, ContractAddress: &ca, Value: "0", InputData: "0x6080"}}, "did:viewer")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].From != dgSubject || got[0].ContractAddress == nil || *got[0].ContractAddress != created {
				t.Fatalf("the subject's deployment shows its contract: %+v", got)
			}

			engine, _ = dgEngine(profile, false, false)
			got, err = engine.RedactTransactions(context.Background(), []Transaction{{Hash: dgTx, From: dgSubject, ContractAddress: &ca}}, "did:viewer")
			if err != nil {
				t.Fatal(err)
			}
			for _, row := range got {
				if row.ContractAddress != nil && *row.ContractAddress == created {
					t.Fatalf("without the grant the created contract stays private: %+v", row)
				}
			}
		})
	}
}

// The grant lens reveals the parties an event names in its ABI-indexed address
// parameters — never an address carried in the event data — on the explorer
// exactly as on JSON-RPC.
func TestRedactLogs_FullGrantLensRevealsIndexedPartiesOnly(t *testing.T) {
	const (
		settledABI = `[{"type":"event","name":"Settled","anonymous":false,"inputs":[{"name":"payer","type":"address","indexed":true},{"name":"payee","type":"address","indexed":true},{"name":"agent","type":"address","indexed":false}]}]`
		agent      = "0xa9e0700000000000000000000000000000000006"
	)
	settledT0 := eventTopic0("Settled(address,address,address)")
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			engine, db := dgEngine(profile, true, false)
			db.visMap[agent] = VisibilityHidden
			db.detailed[agent] = AddressVisibility{Address: agent, Level: VisibilityHidden, Reason: ReasonNoAccess}
			engine.SetABIResolver(&stubABIResolver{byAddr: map[string]string{dgToken: settledABI}})
			engine.SetEventRuleChecker(&stubEventRuleChecker{byAddr: map[string]EventRulesResolution{dgToken: {Wildcard: true}}})
			agentWord := "0x" + strings.Repeat("0", 24) + strings.TrimPrefix(agent, "0x")
			l := Log{TxHash: dgTx, Address: dgToken, Topic0: &settledT0, Topic1: sbTopic(dgSubject), Topic2: sbTopic(dgPeer), Data: agentWord}
			got, err := engine.RedactLogs(context.Background(), []Log{l}, "did:viewer")
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 {
				t.Fatalf("the subject's event is admitted, got %d", len(got))
			}
			if got[0].Topic2 == nil || !strings.EqualFold(*got[0].Topic2, *sbTopic(dgPeer)) {
				t.Fatalf("the indexed counterparty is revealed: %+v", got[0])
			}
			if strings.Contains(strings.ToLower(got[0].Data), strings.TrimPrefix(agent, "0x")) {
				t.Fatalf("an address in the event data keeps the viewer's own level: %s", got[0].Data)
			}
			if _, ok := got[0].AddressMetadata[agent]; ok {
				t.Fatalf("the masked data address has no metadata key: %+v", got[0].AddressMetadata)
			}
		})
	}
}

// Strict internal calls belong to their parent: a Full grant over the parent's
// sender admits its frames; a Full grant over a party of a frame in someone
// else's transaction does not.
func TestRedactInternalTransactions_StrictFullGrantFollowsTheParent(t *testing.T) {
	peer := dgPeer
	token := dgToken
	for _, tc := range []struct {
		name       string
		parentFrom string
		admit      bool
	}{
		{"parent sent by the subject", dgSubject, true},
		{"parent sent by someone else", dgPeer, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engine, _ := dgEngine(rbac.ReadProfileStrict, true, false)
			engine.SetTxDataResolver(&countingTxData{txs: map[string]*Transaction{dgTx: {Hash: dgTx, From: tc.parentFrom, To: &token}}})
			frame := InternalTransaction{TxHash: dgTx, TraceAddress: "0", From: dgSubject, To: &peer, Value: "5"}
			got, err := engine.RedactInternalTransactions(context.Background(), []InternalTransaction{frame}, "did:viewer")
			if err != nil {
				t.Fatal(err)
			}
			if tc.admit != (len(got) == 1) {
				t.Fatalf("admit = %v, got %+v", tc.admit, got)
			}
		})
	}
}

// A transfer row reveals through the grant only the parties its event names:
// a row whose recorded counterparty differs from the event's (an indexing
// fault) does not show it.
func TestRedactTransfers_FullGrantRevealsOnlyTheEventsParties(t *testing.T) {
	const other = "0x07e4000000000000000000000000000000000009"
	for _, profile := range []rbac.ReadProfile{rbac.ReadProfileStandard, rbac.ReadProfileStrict} {
		t.Run(profile.String(), func(t *testing.T) {
			engine, db := dgEngine(profile, true, true) // the event: Transfer(subject -> peer)
			db.visMap[other] = VisibilityHidden
			db.detailed[other] = AddressVisibility{Address: other, Level: VisibilityHidden, Reason: ReasonNoAccess}
			row := TokenTransfer{TxHash: dgTx, LogIndex: 0, TokenAddress: dgToken, From: dgSubject, To: other, Value: "1000"}
			got, err := engine.RedactTransfers(context.Background(), []TokenTransfer{row}, "did:viewer")
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range got {
				if strings.EqualFold(r.To, other) {
					t.Fatalf("a party the event does not name must not be revealed: %+v", r)
				}
			}
		})
	}
}
