package nodepolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
	"math/big"
	"os"
	"strings"
	"testing"
)

// Regenerate intentionally with UPDATE_NODE_POLICY_VECTORS=1. Rust tests consume
// these same signed bytes rather than generating signatures in their own code.
func TestGoldenEnvelopes(t *testing.T) {
	i, err := testSigner().Seal("identity", identityFixture())
	if err != nil {
		t.Fatal(err)
	}
	s, err := testSigner().Seal("snapshot", snapshotFixture())
	if err != nil {
		t.Fatal(err)
	}
	r, err := EncodeSimulation(SimulationRequest{Method: "eth_call", Params: json.RawMessage(`[{"from":"0x1111111111111111111111111111111111111111","to":"0x1111111111111111111111111111111111111111","data":"0x"},"latest"]`)})
	if err != nil {
		t.Fatal(err)
	}
	fixture := struct {
		PublicKey           string          `json:"public_key"`
		Now                 int64           `json:"now"`
		Identity            json.RawMessage `json:"identity"`
		Snapshot            json.RawMessage `json:"snapshot"`
		Delta               json.RawMessage `json:"delta"`
		Heartbeat           json.RawMessage `json:"heartbeat"`
		Simulation          string          `json:"simulation"`
		SimulationHash      string          `json:"simulation_hash"`
		SimulationIdentity  json.RawMessage `json:"simulation_identity"`
		RawTransaction      string          `json:"raw_transaction"`
		TransactionIdentity json.RawMessage `json:"transaction_identity"`
		TransactionSnapshot json.RawMessage `json:"transaction_snapshot"`
		BlobTransaction     string          `json:"blob_transaction"`
		BlobIdentity        json.RawMessage `json:"blob_identity"`
	}{PublicKey: base64.StdEncoding.EncodeToString(testSigner().PrivateKey.Public().(ed25519.PublicKey)), Now: 1020,
		Identity: i, Snapshot: s, Simulation: base64.StdEncoding.EncodeToString(r), SimulationHash: SimulationHash(r)}
	simIdentity := identityFixture()
	simIdentity.Scope, simIdentity.ContextID, simIdentity.BindingHash = "simulation", "sim-1", SimulationHash(r)
	fixture.SimulationIdentity, err = testSigner().Seal("identity", simIdentity)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ethcrypto.HexToECDSA(strings.Repeat("01", 32))
	if err != nil {
		t.Fatal(err)
	}
	to := common.HexToAddress(identityFixture().Signer)
	tx, err := types.SignNewTx(key, types.NewLondonSigner(big.NewInt(31337)), &types.DynamicFeeTx{ChainID: big.NewInt(31337), Nonce: 0, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(10), Gas: 21000, To: &to, Value: big.NewInt(1)})
	if err != nil {
		t.Fatal(err)
	}
	rawTx, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	fixture.RawTransaction = "0x" + hex.EncodeToString(rawTx)
	txIdentity := identityFixture()
	txIdentity.PrincipalID, txIdentity.ContextID = "user-b", "tx-1"
	txIdentity.Signer = strings.ToLower(ethcrypto.PubkeyToAddress(key.PublicKey).Hex())
	txIdentity.BindingHash = tx.Hash().Hex()
	fixture.TransactionIdentity, err = testSigner().Seal("identity", txIdentity)
	if err != nil {
		t.Fatal(err)
	}
	txSnapshot := snapshotFixture()
	txSnapshot.Principals[1].LinkedAddresses = []string{txIdentity.Signer}
	fixture.TransactionSnapshot, err = testSigner().Seal("snapshot", txSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	// Empty sidecar is a transport hash vector, not a claim that this fixture
	// passes transaction-pool blob validation. The pool validates blob contents.
	blob, err := types.SignNewTx(key, types.NewCancunSigner(big.NewInt(31337)), &types.BlobTx{
		ChainID: uint256.NewInt(31337), Nonce: 1, GasTipCap: uint256.NewInt(1), GasFeeCap: uint256.NewInt(10), Gas: 21000,
		To: to, Value: uint256.NewInt(1), BlobFeeCap: uint256.NewInt(1), Sidecar: &types.BlobTxSidecar{},
	})
	if err != nil {
		t.Fatal(err)
	}
	blobRaw, err := blob.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if ethcrypto.Keccak256Hash(blobRaw) == blob.Hash() {
		t.Fatal("fixture does not exercise network sidecar wrapper")
	}
	fixture.BlobTransaction = "0x" + hex.EncodeToString(blobRaw)
	blobIdentity := txIdentity
	blobIdentity.ContextID, blobIdentity.BindingHash = "blob-1", blob.Hash().Hex()
	fixture.BlobIdentity, err = testSigner().Seal("identity", blobIdentity)
	if err != nil {
		t.Fatal(err)
	}
	base := snapshotFixture()
	baseBytes, err := testVerifier().Open("snapshot", s)
	if err != nil {
		t.Fatal(err)
	}
	next := cloneSnapshot(base)
	next.Version = 10
	next.IssuedAt, next.ExpiresAt = 1010, 1110
	next.Principals[0].Banned = true
	d, err := BuildDelta(base, PayloadDigest(baseBytes), next)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Delta, err = testSigner().Seal("delta", d)
	if err != nil {
		t.Fatal(err)
	}
	deltaBytes, err := testVerifier().Open("delta", fixture.Delta)
	if err != nil {
		t.Fatal(err)
	}
	fixture.Heartbeat, err = testSigner().Seal("heartbeat", Heartbeat{
		Header: Header{Network: base.Network, IssuedAt: 1015, ExpiresAt: 1115}, Version: next.Version, Digest: PayloadDigest(deltaBytes)})
	if err != nil {
		t.Fatal(err)
	}
	feed := new(Feed)
	for _, wire := range [][]byte{s, fixture.Delta, fixture.Heartbeat} {
		if err := feed.Apply(testVerifier(), wire); err != nil {
			t.Fatal(err)
		}
	}
	b, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, '\n')
	const path = "testdata/envelopes-v1.json"
	if os.Getenv("UPDATE_NODE_POLICY_VECTORS") == "1" {
		if err := os.MkdirAll("testdata", 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, b) {
		t.Fatal("protocol golden vectors changed; review compatibility before regeneration")
	}
	if _, err := testVerifier().OpenIdentity(i); err != nil {
		t.Fatal(err)
	}
	if _, err := testVerifier().OpenSnapshot(s); err != nil {
		t.Fatal(err)
	}
}
