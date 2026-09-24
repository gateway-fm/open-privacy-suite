// Test fixture standing in for OPS in the Reth harness: it prepares approvals with the real
// preflight, signs batches with the fixture key and delivers them over the approval gRPC service
// (docs/implementation/approvals-wire-contract.md). Authorization itself is exercised separately
// through the real OPS processor + PostgreSQL.
//
// Usage: approval-client <rpc-url> [<approval host:port>]
//
// With a delivery target it connects and calls Status first, as OPS does when a lane becomes
// ready. Then one JSON request per stdin line, one JSON reply per stdout line:
//
//	{"raw": "0x…"}                          preflight → {"Approval": {…}}
//	{"approvals": […], "ttl_ms": n}         sign a batch → the batch and its "envelope" (hex);
//	                                        "issued_at"/"expires_at" (Unix ms) override the times
//	{"deliver": {batch}}                    Deliver the batch's fields under its signature
//	{"envelope": "hex"}                     Deliver these bytes as they are
//	{"status": true}                        Status
//
// Deliver and Status reply {"code": "OK" | "INVALID_ARGUMENT" | …} plus the response fields,
// or "message" and the "ops-approval-reason" trailer as "reason".
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/internal/nodeapproval/approvalpb"
)

type request struct {
	Raw       string                  `json:"raw"`
	Approvals []nodeapproval.Approval `json:"approvals"`
	TTLMs     uint64                  `json:"ttl_ms"`
	IssuedAt  uint64                  `json:"issued_at"`
	ExpiresAt uint64                  `json:"expires_at"`
	Deliver   *nodeapproval.Batch     `json:"deliver"`
	Envelope  *string                 `json:"envelope"`
	Status    bool                    `json:"status"`
}

type signed struct {
	nodeapproval.Batch
	Envelope string `json:"envelope"`
}

func main() {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	pre, err := nodeapproval.NewPreflight(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer pre.Close()
	var lane approvalpb.ApprovalDeliveryClient
	if len(os.Args) > 2 {
		conn, err := grpc.NewClient(os.Args[2],
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: 5 * time.Second, PermitWithoutStream: true}))
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		lane = approvalpb.NewApprovalDeliveryClient(conn)
		if reply := callStatus(lane, grpc.WaitForReady(true)); reply["code"] != "OK" {
			panic(reply)
		}
	}
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for scan.Scan() {
		var q request
		if err := json.Unmarshal(scan.Bytes(), &q); err != nil {
			panic(err)
		}
		reply, err := handle(pre, lane, key, q)
		if err != nil {
			reply = map[string]any{"error": err.Error()}
		}
		if err := out.Encode(reply); err != nil {
			panic(err)
		}
	}
}

func handle(pre *nodeapproval.Service, lane approvalpb.ApprovalDeliveryClient, key ed25519.PrivateKey, q request) (any, error) {
	needLane := q.Deliver != nil || q.Envelope != nil || q.Status
	if needLane && lane == nil {
		return nil, errors.New("no delivery target")
	}
	switch {
	case q.Approvals != nil:
		return sign(key, q)
	case q.Deliver != nil:
		envelope, err := encode(*q.Deliver)
		if err != nil {
			return nil, err
		}
		return deliver(lane, envelope), nil
	case q.Envelope != nil:
		envelope, err := hex.DecodeString(strings.TrimPrefix(*q.Envelope, "0x"))
		if err != nil {
			return nil, err
		}
		return deliver(lane, envelope), nil
	case q.Status:
		return callStatus(lane), nil
	default:
		return pre.Prepare(context.Background(), q.Raw)
	}
}

// sign signs like OPS: key id "default", the reserved field zero, a 10-minute TTL unless the
// request sets the times.
func sign(key ed25519.PrivateKey, q request) (signed, error) {
	approvals := append([]nodeapproval.Approval(nil), q.Approvals...)
	for i := range approvals {
		approvals[i].Signature = ""
		approvals[i].Principal = common.Hash{}
	}
	issued := q.IssuedAt
	if issued == 0 {
		issued = uint64(time.Now().UnixMilli())
	}
	expires := q.ExpiresAt
	if expires == 0 {
		ttl := q.TTLMs
		if ttl == 0 {
			ttl = uint64(nodeapproval.DefaultApprovalTTL.Milliseconds())
		}
		expires = issued + ttl
	}
	b := nodeapproval.Batch{Version: nodeapproval.BatchVersion, KeyID: "default", IssuedAt: issued, ExpiresAt: expires, Approvals: approvals}
	message, err := b.Message()
	if err != nil {
		return signed{}, err
	}
	signature := ed25519.Sign(key, message)
	b.Signature = hex.EncodeToString(signature)
	return signed{Batch: b, Envelope: hex.EncodeToString(append(message, signature...))}, nil
}

// encode re-encodes a batch's fields and appends its signature, so a test can alter a field and
// deliver it under the original signature.
func encode(b nodeapproval.Batch) ([]byte, error) {
	message, err := b.Message()
	if err != nil {
		return nil, err
	}
	signature, err := hex.DecodeString(b.Signature)
	if err != nil {
		return nil, err
	}
	return append(message, signature...), nil
}

func deliver(lane approvalpb.ApprovalDeliveryClient, envelope []byte) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var trailer metadata.MD
	resp, err := lane.Deliver(ctx, &approvalpb.DeliverRequest{Batch: envelope}, grpc.Trailer(&trailer))
	if err != nil {
		reply := map[string]any{"code": codeName(status.Code(err)), "message": status.Convert(err).Message()}
		if reason := trailer.Get("ops-approval-reason"); len(reason) > 0 {
			reply["reason"] = reason[0]
		}
		return reply
	}
	return map[string]any{"code": "OK", "boot_id": resp.GetBootId(), "stored": resp.GetStored()}
}

func callStatus(lane approvalpb.ApprovalDeliveryClient, opts ...grpc.CallOption) map[string]any {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := lane.Status(ctx, &approvalpb.StatusRequest{}, opts...)
	if err != nil {
		return map[string]any{"code": codeName(status.Code(err)), "message": status.Convert(err).Message()}
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

// codeName spells a status code the way the contract does: INVALID_ARGUMENT, not InvalidArgument.
func codeName(c codes.Code) string {
	if c == codes.OK {
		return "OK"
	}
	var name strings.Builder
	for i, r := range c.String() {
		if i > 0 && unicode.IsUpper(r) {
			name.WriteByte('_')
		}
		name.WriteRune(unicode.ToUpper(r))
	}
	return name.String()
}
