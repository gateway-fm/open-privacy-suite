package nodeapproval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"log/slog"
	"net/http"
	"os"
	"privacy-proxy/internal/nodehttp"
	"privacy-proxy/internal/tracer"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Approval struct {
	HashMode    uint8 `json:"hash_mode,omitempty"`
	hop         *Hop
	ChainID     uint64      `json:"chain_id"`
	TxHash      common.Hash `json:"tx_hash"`
	Fingerprint common.Hash `json:"fingerprint"`
	Principal   common.Hash `json:"principal"`
	Signature   string      `json:"signature,omitempty"`
}

func (a Approval) Message() []byte {
	domain := "OPS_APPROVAL_V1\x00"
	if a.HashMode == HashCalls {
		domain = "OPS_APPROVAL_V3\x00"
	}
	b := append([]byte{}, []byte(domain)...)
	b = binary.BigEndian.AppendUint64(b, a.ChainID)
	b = append(b, a.TxHash[:]...)
	b = append(b, a.Fingerprint[:]...)
	return append(b, a.Principal[:]...)
}

type Prepared struct {
	NoCodeRecipients   map[string]bool `json:"-"`
	Approval           Approval
	Trace              *tracer.TraceResult
	CodeHashes         map[string]string `json:"-"`
	FreshCreations     map[string]bool   `json:"-"`
	SurvivingCreations map[string]bool   `json:"-"`
	PlainValueTransfer bool              `json:"-"`
}

func (p *Prepared) GetCodeHash(_ context.Context, address string) (string, error) {
	hash, ok := p.CodeHashes[strings.ToLower(address)]
	if !ok {
		return "", errors.New("code missing from approved execution snapshot")
	}
	return hash, nil
}

type Service struct {
	hashMode    uint8
	connections atomic.Uint64
	hops        *hops
	rpc         *rpc.Client
	rpcHTTP     *http.Client
	key         ed25519.PrivateKey
	address     string
	queue       chan Approval
	signed      chan Batch
	maxBatch    int
	sign        func(ed25519.PrivateKey, []Approval) (Batch, error)
	cancel      context.CancelFunc
	done        chan struct{}
	signDone    chan struct{}
	once        sync.Once
}

func New(url, address string, seed []byte) (*Service, error) {
	return NewWithTransport(url, address, seed, nodehttp.DefaultTransportConfig())
}

// NewWithTransport uses the same upstream pool settings as OPS forwarding and
// tracing. Geth's default HTTP client retains only two idle connections per host.
func NewWithTransport(url, address string, seed []byte, tc nodehttp.TransportConfig) (*Service, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("approval key must be a 32-byte Ed25519 seed")
	}
	mode, err := configuredHashMode()
	if err != nil {
		return nil, err
	}
	maxBatch := MaxBatchApprovals
	if value := os.Getenv("OPS_APPROVAL_MAX_BATCH"); value != "" {
		var err error
		maxBatch, err = strconv.Atoi(value)
		if err != nil || maxBatch < 1 || maxBatch > MaxBatchApprovals {
			return nil, errors.New("OPS_APPROVAL_MAX_BATCH must be between 1 and 32")
		}
	}
	client, httpClient, err := dialPreflightRPC(url, tc)
	if err != nil {
		return nil, err
	}
	conn, err := dialApproval(context.Background(), address)
	if err != nil {
		client.Close()
		httpClient.CloseIdleConnections()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Service{hashMode: mode, hops: newHops(), rpc: client, rpcHTTP: httpClient, key: ed25519.NewKeyFromSeed(seed), address: address, queue: make(chan Approval, 4096), signed: make(chan Batch, 128), maxBatch: maxBatch, sign: SignBatch, cancel: cancel, done: make(chan struct{}), signDone: make(chan struct{})}
	s.connections.Store(1)
	go s.signLoop(ctx)
	go s.deliver(ctx, conn)
	return s, nil
}

// NewPreflight opens only the RPC client, for offline fixture preparation.
func NewPreflight(url string) (*Service, error) {
	mode, err := configuredHashMode()
	if err != nil {
		return nil, err
	}
	client, httpClient, err := dialPreflightRPC(url, nodehttp.DefaultTransportConfig())
	if err != nil {
		return nil, err
	}
	return &Service{hashMode: mode, rpc: client, rpcHTTP: httpClient}, nil
}

func dialPreflightRPC(url string, tc nodehttp.TransportConfig) (*rpc.Client, *http.Client, error) {
	httpClient := nodehttp.NewClient(30*time.Second, tc)
	client, err := rpc.DialOptions(context.Background(), url, rpc.WithHTTPClient(httpClient))
	if err != nil {
		httpClient.CloseIdleConnections()
	}
	return client, httpClient, err
}
func (s *Service) Close() {
	s.once.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		if s.rpc != nil {
			s.rpc.Close()
		}
		if s.rpcHTTP != nil {
			s.rpcHTTP.CloseIdleConnections()
		}
		if s.signDone != nil {
			<-s.signDone
		}
		if s.done != nil {
			<-s.done
		}
		s.hops.flush()
		if count := s.connections.Load(); count > 0 {
			slog.Info("approval connections used", "count", count)
		}
	})
}
func (s *Service) Prepare(ctx context.Context, raw string) (*Prepared, error) {
	rawBytes, err := hexutil.Decode(raw)
	if err != nil {
		return nil, err
	}
	var tx types.Transaction
	if err = tx.UnmarshalBinary(rawBytes); err != nil {
		return nil, err
	}
	if !tx.Protected() || (tx.Type() != types.LegacyTxType && tx.Type() != types.DynamicFeeTxType) {
		return nil, errors.New("V2 supports protected legacy/EIP-1559 transactions only")
	}
	from, err := types.Sender(types.LatestSignerForChainID(tx.ChainId()), &tx)
	if err != nil {
		return nil, err
	}
	var chain hexutil.Uint64
	if err = s.rpc.CallContext(ctx, &chain, "eth_chainId"); err != nil {
		return nil, err
	}
	if tx.ChainId().Uint64() != uint64(chain) {
		return nil, errors.New("wrong chain")
	}
	var block struct {
		Hash common.Hash `json:"hash"`
	}
	if err = s.rpc.CallContext(ctx, &block, "eth_getHeaderByNumber", "latest"); err != nil {
		return nil, err
	}
	args := object{"from": from, "to": tx.To(), "input": hexutil.Bytes(tx.Data()), "gas": hexutil.Uint64(tx.Gas()), "nonce": hexutil.Uint64(tx.Nonce()), "value": (*hexutil.Big)(tx.Value())}
	if tx.Type() == types.LegacyTxType {
		args["gasPrice"] = (*hexutil.Big)(tx.GasPrice())
	} else {
		args["maxFeePerGas"] = (*hexutil.Big)(tx.GasFeeCap())
		args["maxPriorityFeePerGas"] = (*hexutil.Big)(tx.GasTipCap())
		args["accessList"] = tx.AccessList()
	}
	overrides := object{from.Hex(): object{"nonce": hexutil.Uint64(tx.Nonce())}}
	var muxRaw json.RawMessage
	if err = s.rpc.CallContext(ctx, &muxRaw, "debug_traceCall", args, block.Hash.Hex(), object{"stateOverrides": overrides, "tracer": "muxTracer", "tracerConfig": object{"callTracer": object{"withLog": true}, "prestateTracer": object{"diffMode": false}}}); err != nil {
		return nil, err
	}
	var diffRaw json.RawMessage
	if err = s.rpc.CallContext(ctx, &diffRaw, "debug_traceCall", args, block.Hash.Hex(), object{"stateOverrides": overrides, "tracer": "prestateTracer", "tracerConfig": object{"diffMode": true}}); err != nil {
		return nil, err
	}
	var mux, diff object
	for _, pair := range []struct {
		raw json.RawMessage
		out *object
	}{{muxRaw, &mux}, {diffRaw, &diff}} {
		d := json.NewDecoder(bytes.NewReader(pair.raw))
		d.UseNumber()
		if err = d.Decode(pair.out); err != nil {
			return nil, err
		}
	}
	hash, trace, mode, err := fingerprintForMode(s.hashMode, obj(mux["callTracer"]), obj(mux["prestateTracer"]), diff)
	if err != nil {
		return nil, err
	}
	codeHashes := map[string]string{}
	for address, account := range obj(mux["prestateTracer"]) {
		codeHashes[strings.ToLower(address)] = crypto.Keccak256Hash(common.FromHex(str(obj(account)["code"]))).Hex()
	}
	fresh, surviving := creationSets(trace, obj(mux["prestateTracer"]), diff)
	noCode := map[string]bool{}
	for address, code := range codeHashes {
		if code == crypto.Keccak256Hash(nil).Hex() {
			noCode[address] = true
		}
	}
	call := obj(mux["callTracer"])
	plain := tx.To() != nil && len(tx.Data()) == 0 && len(trace.CallTargets) == 1 && str(call["type"]) == "CALL" && codeHashes[strings.ToLower(tx.To().Hex())] == crypto.Keccak256Hash(nil).Hex()
	return &Prepared{Approval: Approval{HashMode: mode, ChainID: uint64(chain), TxHash: tx.Hash(), Fingerprint: hash}, Trace: trace, CodeHashes: codeHashes, FreshCreations: fresh, SurvivingCreations: surviving, PlainValueTransfer: plain, NoCodeRecipients: noCode}, nil
}

// Enqueue is called only AFTER OPS RBAC, trace and compliance gates have passed.
// It never waits for a node acknowledgement and never resubmits a transaction.
func (s *Service) Enqueue(p *Prepared, principal string) error {
	p.Approval.hop = s.hops.add(p.Approval.TxHash)
	a := p.Approval
	a.Principal = crypto.Keccak256Hash([]byte(principal))
	a.Signature = ""
	select {
	case <-s.done:
		return errors.New("approval sender closed")
	default:
	}
	select {
	case s.queue <- a:
		return nil
	default:
		return errors.New("approval delivery queue full")
	}
}

// One consumer: snapshot only what is ready now; arrivals during signing belong
// to a subsequent batch. There is no timer or wait to fill the batch.
func (s *Service) takeBatch(first Approval) []Approval {
	count := min(len(s.queue)+1, s.maxBatch)
	batch := make([]Approval, 1, count)
	batch[0] = first
	for len(batch) < count {
		batch = append(batch, <-s.queue)
	}
	return batch
}

func (s *Service) signLoop(ctx context.Context) {
	defer close(s.signDone)
	for {
		select {
		case <-ctx.Done():
			return
		case first := <-s.queue:
			approvals := s.takeBatch(first)
			mark(approvals, func(h *Hop, n int64) { h.SignStart = n })
			batch, err := s.sign(s.key, approvals)
			mark(approvals, func(h *Hop, n int64) { h.SignEnd = n })
			if err != nil {
				slog.Error("approval batch signing failed", "error", err)
				continue
			}
			// The sender owns transport. Backpressure here is bounded and never
			// makes the request goroutine wait for signing or network delivery.
			select {
			case s.signed <- batch:
			case <-ctx.Done():
				return
			}
		}
	}
}

// Use the pinned prestate, not a second code lookup at latest. A failed CREATE
// collision cannot grant access to an existing contract. Registration includes
// only creations surviving the whole transaction, including empty runtime code.
func creationSets(trace *tracer.TraceResult, pre, diff object) (map[string]bool, map[string]bool) {
	fresh, surviving := map[string]bool{}, map[string]bool{}
	for _, target := range trace.CallTargets {
		if target.Type != "CREATE" && target.Type != "CREATE2" {
			continue
		}
		a := strings.ToLower(target.To)
		if !common.IsHexAddress(a) {
			continue
		}
		original := obj(pre[a])
		n, err := number(original["nonce"])
		if err != nil || n.Sign() != 0 || field(original, "code", "0x") != "0x" {
			continue
		}
		fresh[a] = true
		post := obj(obj(diff["post"])[a])
		n, err = number(post["nonce"])
		if err == nil && (n.Sign() != 0 || field(post, "code", "0x") != "0x") {
			surviving[a] = true
		}
	}
	return fresh, surviving
}
