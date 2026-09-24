// Test fixture: runs the real OPS preflight (nodeapproval.Service in Besu mode), signs approval
// batches with the fixture key and delivers them over the gRPC contract
// (ops.approvals.v1.ApprovalDelivery), so the harness exercises internal/nodeapproval and the
// plugin's ingress exactly as OPS would.
//
// Usage: client <node-rpc-url> <approval-target host:port>. One JSON query per stdin line, one JSON
// answer per stdout line:
//
//	{"raw": "0x…"}                                  preflight
//	{"fingerprint": {"calls": …, "pre": …}}         Go encoder over a geth-shaped trace
//	{"approvals": […], "ttl_ms": n}                 sign a batch now: {"envelope": hex}; optional
//	                                                "issued_at"/"expires_at" (ms), "key_id", "seed"
//	{"deliver": hex}                                Deliver: {"code": "OK", "boot_id", "stored"} or
//	                                                {"code", "message", "reason"}
//	{"status": true, "wait_ms": n}                  Status; wait_ms > 0 waits for a (re)connection
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
)

// deliveryTimeout is OPS's default deadline of one Deliver call (OPS_APPROVAL_DELIVERY_TIMEOUT).
const deliveryTimeout = 2 * time.Second

func keys(m map[string]bool) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	return out
}

var camel = regexp.MustCompile(`([a-z])([A-Z])`)

// codeName spells a status code as the wire contract does: INVALID_ARGUMENT, not InvalidArgument.
func codeName(err error) string {
	return strings.ToUpper(camel.ReplaceAllString(status.Code(err).String(), "${1}_${2}"))
}

func main() {
	if len(os.Args) != 3 {
		panic("usage: client <node-rpc-url> <approval-target host:port>")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	s, err := nodeapproval.NewPreflight(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer s.Close()
	// The channel OPS holds per producer: plaintext, keepalive every 20 s also without calls, and
	// reconnects with backoff capped at 1 s (wire contract §1).
	conn, err := grpc.NewClient(os.Args[2],
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: 5 * time.Second, PermitWithoutStream: true}),
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff:           backoff.Config{BaseDelay: 100 * time.Millisecond, Multiplier: 1.6, Jitter: 0.2, MaxDelay: time.Second},
			MinConnectTimeout: 2 * time.Second,
		}))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	delivery := approvalpb.NewApprovalDeliveryClient(conn)

	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 1<<20)
	out := json.NewEncoder(os.Stdout)
	emit := func(v any) {
		if err := out.Encode(v); err != nil {
			log.Fatal(err)
		}
	}
	for scan.Scan() {
		var q struct {
			Approvals   []nodeapproval.Approval `json:"approvals"`
			KeyID       string                  `json:"key_id"`
			Seed        byte                    `json:"seed"`
			TTLMs       uint64                  `json:"ttl_ms"`
			IssuedAt    uint64                  `json:"issued_at"`
			ExpiresAt   uint64                  `json:"expires_at"`
			Deliver     string                  `json:"deliver"`
			Status      bool                    `json:"status"`
			WaitMs      int64                   `json:"wait_ms"`
			Raw         string                  `json:"raw"`
			Fingerprint map[string]any          `json:"fingerprint"` // {calls, pre}: Go encoder over a geth trace
		}
		if err := json.Unmarshal(scan.Bytes(), &q); err != nil {
			panic(err)
		}
		switch {
		case q.Fingerprint != nil:
			calls, _ := q.Fingerprint["calls"].(map[string]any)
			pre, _ := q.Fingerprint["pre"].(map[string]any)
			h, _, err := nodeapproval.CallFingerprint(calls, pre)
			if err != nil {
				emit(map[string]any{"error": err.Error()})
			} else {
				emit(map[string]any{"fingerprint": h.Hex()})
			}
		case q.Approvals != nil:
			emit(sign(key, q.Approvals, q.KeyID, q.Seed, q.TTLMs, q.IssuedAt, q.ExpiresAt))
		case q.Deliver != "":
			envelope, err := hex.DecodeString(q.Deliver)
			if err != nil {
				panic(err)
			}
			emit(deliver(delivery, envelope))
		case q.Status:
			emit(describe(delivery, time.Duration(q.WaitMs)*time.Millisecond))
		default:
			p, err := s.Prepare(context.Background(), q.Raw)
			if err != nil {
				emit(map[string]any{"error": err.Error()})
				continue
			}
			// The creation sets drive OPS's contract registration, so the harness asserts them.
			emit(map[string]any{
				"Approval":           p.Approval,
				"Trace":              p.Trace,
				"surviving":          keys(p.SurvivingCreations),
				"fresh":              keys(p.FreshCreations),
				"plainValueTransfer": p.PlainValueTransfer,
			})
		}
	}
}

// sign builds the envelope as OPS signs it — the signed message, then its Ed25519 signature — now
// with the given TTL (default OPS's 10 minutes), or at explicit instants, under any key id or seed,
// so a scenario can also produce every batch the receiver must refuse.
func sign(key ed25519.PrivateKey, approvals []nodeapproval.Approval, keyID string, seed byte, ttlMs, issuedAt, expiresAt uint64) map[string]any {
	for i := range approvals {
		approvals[i].Signature = ""
	}
	if keyID == "" {
		keyID = "default"
	}
	if seed != 0 {
		key = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	}
	if ttlMs == 0 {
		ttlMs = uint64(nodeapproval.DefaultApprovalTTL.Milliseconds())
	}
	if issuedAt == 0 {
		issuedAt = uint64(time.Now().UnixMilli())
	}
	if expiresAt == 0 {
		expiresAt = issuedAt + ttlMs
	}
	b := nodeapproval.Batch{Version: nodeapproval.BatchVersion, KeyID: keyID, IssuedAt: issuedAt, ExpiresAt: expiresAt, Approvals: approvals}
	message, err := b.Message()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	envelope := append(message, ed25519.Sign(key, message)...)
	return map[string]any{"envelope": hex.EncodeToString(envelope), "issued_at": issuedAt, "expires_at": expiresAt}
}

func deliver(delivery approvalpb.ApprovalDeliveryClient, envelope []byte) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), deliveryTimeout)
	defer cancel()
	var trailer metadata.MD
	resp, err := delivery.Deliver(ctx, &approvalpb.DeliverRequest{Batch: envelope}, grpc.Trailer(&trailer))
	if err != nil {
		answer := map[string]any{"code": codeName(err), "message": status.Convert(err).Message()}
		if reason := trailer.Get("ops-approval-reason"); len(reason) > 0 {
			answer["reason"] = reason[0]
		}
		return answer
	}
	return map[string]any{"code": "OK", "boot_id": resp.GetBootId(), "stored": resp.GetStored()}
}

// describe calls Status, as OPS does whenever a connection becomes ready; with a wait it rides out
// a reconnection instead of failing fast.
func describe(delivery approvalpb.ApprovalDeliveryClient, wait time.Duration) map[string]any {
	timeout, opts := deliveryTimeout, []grpc.CallOption{}
	if wait > 0 {
		timeout, opts = wait, append(opts, grpc.WaitForReady(true))
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	resp, err := delivery.Status(ctx, &approvalpb.StatusRequest{}, opts...)
	if err != nil {
		return map[string]any{"code": codeName(err), "message": status.Convert(err).Message()}
	}
	return map[string]any{
		"code":            "OK",
		"boot_id":         resp.GetBootId(),
		"chain_id":        resp.GetChainId(),
		"trusted_key_ids": resp.GetTrustedKeyIds(),
		"max_ttl_ms":      resp.GetMaxTtlMs(),
		"capacity":        resp.GetCapacity(),
		"wait_ms":         resp.GetWaitMs(),
	}
}
