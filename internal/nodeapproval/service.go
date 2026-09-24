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
	// Principal is the reserved field: OPS writes zeros, receivers sign over it and ignore it
	// (wire contract §2). The golden vectors keep a value there to prove decoders accept any.
	Principal common.Hash `json:"principal"`
	Signature string      `json:"signature,omitempty"`
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
	hashMode uint8
	node     nodeKind
	hops     *hops
	rpc      *rpc.Client
	rpcHTTP  *http.Client
	signer   Signer
	// ttl is OPS_APPROVAL_TTL; batches are signed for less when a producer accepts less.
	ttl       time.Duration
	signedTTL time.Duration // the signer goroutine's last TTL, to log a change once
	maxBatch  int
	queue     chan Approval
	// mu orders Enqueue against Close: once closing is set, nothing more enters the queue, so
	// the signer's drain sees everything Enqueue accepted.
	mu      sync.RWMutex
	closing bool
	chainID atomic.Uint64 // the chain OPS approves for, learned from what it enqueues
	retain  *retention
	lanes   []*lane
	metrics *deliveryMetrics
	drain   time.Duration
	log     logGate
	// cancel stops the signer; stop ends delivery once the drain is over.
	cancel   context.CancelFunc
	stop     context.CancelFunc
	signDone chan struct{}
	once     sync.Once
}

// New starts the approval service: preflight against the node at url, delivery to every producer
// in targets (the value of OPS_APPROVAL_TARGETS, a comma-separated host:port list).
func New(url, targets string, seed []byte) (*Service, error) {
	return NewWithTransport(url, targets, seed, nodehttp.DefaultTransportConfig())
}

// NewWithTransport uses the same upstream pool settings as OPS forwarding and
// tracing. Geth's default HTTP client retains only two idle connections per host.
func NewWithTransport(url, targets string, seed []byte, tc nodehttp.TransportConfig) (*Service, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("approval key must be a 32-byte Ed25519 seed")
	}
	keyID := os.Getenv("OPS_APPROVAL_KEY_ID")
	if keyID == "" {
		keyID = "default"
	}
	if !ValidKeyID(keyID) {
		return nil, errors.New("OPS_APPROVAL_KEY_ID must be 1-64 characters of [A-Za-z0-9._:-]")
	}
	mode, err := configuredHashMode()
	if err != nil {
		return nil, err
	}
	node, err := configuredNodeKind(mode)
	if err != nil {
		return nil, err
	}
	ttl, err := configuredApprovalTTL()
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
	delivery, err := configuredDelivery(targets)
	if err != nil {
		return nil, err
	}
	client, httpClient, err := dialPreflightRPC(url, tc)
	if err != nil {
		return nil, err
	}
	s := &Service{hashMode: mode, node: node, hops: newHops(), rpc: client, rpcHTTP: httpClient, signer: NewEd25519Signer(keyID, seed), ttl: ttl, maxBatch: maxBatch}
	if err := s.startDelivery(delivery); err != nil {
		client.Close()
		httpClient.CloseIdleConnections()
		return nil, err
	}
	return s, nil
}

// NewPreflight opens only the RPC client, for offline fixture preparation.
func NewPreflight(url string) (*Service, error) {
	mode, err := configuredHashMode()
	if err != nil {
		return nil, err
	}
	node, err := configuredNodeKind(mode)
	if err != nil {
		return nil, err
	}
	client, httpClient, err := dialPreflightRPC(url, nodehttp.DefaultTransportConfig())
	if err != nil {
		return nil, err
	}
	return &Service{hashMode: mode, node: node, rpc: client, rpcHTTP: httpClient}, nil
}

func dialPreflightRPC(url string, tc nodehttp.TransportConfig) (*rpc.Client, *http.Client, error) {
	httpClient := nodehttp.NewClient(30*time.Second, tc)
	client, err := rpc.DialOptions(context.Background(), url, rpc.WithHTTPClient(httpClient))
	if err != nil {
		httpClient.CloseIdleConnections()
	}
	return client, httpClient, err
}

// Close refuses new approvals, signs what Enqueue already accepted, delivers it for at most the
// drain timeout, and closes the connections.
func (s *Service) Close() {
	s.once.Do(func() {
		s.mu.Lock()
		s.closing = true // Enqueue refuses from here; what it accepted is drained
		s.mu.Unlock()
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
		s.stopDelivery()
		s.hops.flush()
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
	if s.node == nodeBesu {
		return s.prepareBesu(ctx, raw, &tx, from, uint64(chain))
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
// It never waits for a node acknowledgement and never resubmits a transaction. It refuses when
// no producer is ready to take the approval (wire contract §5): the caller answers 503 instead
// of forwarding a transaction that cannot be approved.
func (s *Service) Enqueue(p *Prepared) error {
	p.Approval.hop = s.hops.add(p.Approval.TxHash)
	a := p.Approval
	a.Principal = common.Hash{} // reserved: senders write zeros
	a.Signature = ""
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closing {
		s.refuse(refusedClosed)
		return errors.New("approval sender closed")
	}
	if s.chainID.Load() != a.ChainID {
		s.chainID.Store(a.ChainID)
	}
	if now := time.Now(); !s.ready(a.ChainID, now) {
		s.refuse(refusedNotReady)
		if held, ok := s.log.allow(refusedNotReady, now); ok {
			slog.Warn("approval refused: no producer is ready; the transaction is answered 503", "chain_id", a.ChainID, "suppressed", held)
		}
		return errNoProducerReady
	}
	select {
	case s.queue <- a:
		return nil
	default:
		s.refuse(refusedQueueFull)
		return errors.New("approval delivery queue full")
	}
}

func (s *Service) refuse(reason string) {
	if s.metrics != nil {
		s.metrics.refused.WithLabelValues(reason).Inc()
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
	defer s.retain.finish() // tells the lanes the drain can complete
	prune := time.NewTicker(pruneEvery)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			// Stop: sign whatever Enqueue already accepted, so the lanes can drain it.
			// Nothing new arrives — Enqueue refuses once closing is set.
			for len(s.queue) > 0 {
				s.signOne(<-s.queue)
			}
			return
		case first := <-s.queue:
			s.signOne(first)
		case now := <-prune.C:
			s.retain.prune(now)
		}
	}
}

// signOne signs one batch starting with first and publishes it. Nothing here waits for a
// producer: the request goroutine never waits for signing or network delivery.
func (s *Service) signOne(first Approval) {
	approvals := s.takeBatch(first)
	ttl := s.signingTTL()
	if ttl != s.signedTTL {
		if ttl < s.ttl {
			slog.Warn("approvals signed for less than OPS_APPROVAL_TTL: a producer accepts no more", "ttl", ttl, "configured", s.ttl)
		} else if s.signedTTL != 0 {
			slog.Info("approvals signed for OPS_APPROVAL_TTL again", "ttl", ttl)
		}
		s.signedTTL = ttl
	}
	mark(approvals, func(h *Hop, n int64) { h.SignStart = n })
	batch, err := s.signer.SignBatch(approvals, ttl)
	mark(approvals, func(h *Hop, n int64) { h.SignEnd = n })
	if err != nil {
		slog.Error("approval batch signing failed", "error", err)
		return
	}
	s.publish(batch)
}

// publish hands a signed batch to delivery: retained for redelivery, and taken by every lane.
func (s *Service) publish(b Batch) {
	s.retain.add(b, time.Now())
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
