// Test fixture: runs the real OPS approval service, including preflight, Enqueue, signing,
// delivery, retention, Status polling and restart recovery. Raw signing and Deliver are available
// only to exercise envelopes the real sender cannot produce (malformed/refused delivery cases).
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
//	{"enqueue": […], "wait_ms": n}                 Enqueue via the real sender, waiting for readiness
//	{"metrics": true}                              sender Prometheus metrics, without network calls
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"log"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
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
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	seed := bytes.Repeat([]byte{7}, 32)
	key := ed25519.NewKeyFromSeed(seed)
	s, err := nodeapproval.New(os.Args[1], os.Args[2], seed)
	if err != nil {
		panic(err)
	}
	defer s.Close()
	registry := prometheus.NewRegistry()
	registry.MustRegister(s)
	// Created only if a negative scenario explicitly asks for raw Deliver. Normal scenarios use
	// exactly the one connection that nodeapproval.Service owns.
	var rawConn *grpc.ClientConn
	defer func() {
		if rawConn != nil {
			rawConn.Close()
		}
	}()

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
			Enqueue     []nodeapproval.Approval `json:"enqueue"`
			Metrics     bool                    `json:"metrics"`
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
		case q.Enqueue != nil:
			emit(enqueue(s, q.Enqueue, time.Duration(q.WaitMs)*time.Millisecond))
		case q.Metrics:
			emit(metrics(registry))
		case q.Approvals != nil:
			emit(sign(key, q.Approvals, q.KeyID, q.Seed, q.TTLMs, q.IssuedAt, q.ExpiresAt))
		case q.Deliver != "":
			envelope, err := hex.DecodeString(q.Deliver)
			if err != nil {
				panic(err)
			}
			if rawConn == nil {
				rawConn, err = grpc.NewClient(os.Args[2], grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					panic(err)
				}
			}
			emit(deliver(approvalpb.NewApprovalDeliveryClient(rawConn), envelope))
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
	if err := scan.Err(); err != nil {
		log.Fatal(err)
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

// enqueue exercises the actual readiness gate, queue and signer. A harness may wait for the
// first Status answer before enqueueing; an accepted approval is never enqueued a second time.
func enqueue(s *nodeapproval.Service, approvals []nodeapproval.Approval, wait time.Duration) map[string]any {
	deadline := time.Now().Add(wait)
	for i, a := range approvals {
		for {
			err := s.Enqueue(&nodeapproval.Prepared{Approval: a})
			if err == nil {
				break
			}
			if err.Error() != "no approval producer is ready" || !time.Now().Before(deadline) {
				return map[string]any{"error": err.Error(), "enqueued": i}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return map[string]any{"enqueued": len(approvals)}
}

// metrics observes the real sender without issuing Status, Deliver, or any other RPC itself.
func metrics(registry *prometheus.Registry) map[string]any {
	families, err := registry.Gather()
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	out := map[string]any{}
	for _, family := range families {
		rows := []map[string]any{}
		for _, metric := range family.GetMetric() {
			labels := map[string]string{}
			for _, pair := range metric.GetLabel() {
				labels[pair.GetName()] = pair.GetValue()
			}
			if metric.Counter != nil {
				rows = append(rows, map[string]any{"labels": labels, "value": metric.GetCounter().GetValue()})
			} else if metric.Gauge != nil {
				rows = append(rows, map[string]any{"labels": labels, "value": metric.GetGauge().GetValue()})
			}
		}
		out[family.GetName()] = rows
	}
	return out
}
