// Test fixture standing in for OPS in the Reth harness. Connected clients use nodeapproval.New
// and Enqueue: OPS owns signing, TTL negotiation, delivery, retries, retention and boot recovery.
// Authorization itself is exercised separately through the real OPS processor + PostgreSQL.
//
// Usage: approval-client <rpc-url> [<approval host:port>]
// One JSON request per stdin line, one JSON reply per stdout line:
//
// {"raw": "0x…"}       preflight → {"Approval": {…}}
// {"enqueue": […]}     enqueue prepared approvals with the real OPS sender
// {"metrics": true}    observe the sender without making receiver calls
//
// Deliberately invalid authentication/expiry tests alone use fixture_approvals to sign custom
// times, fixture_deliver to send altered batch fields, or fixture_envelope for malformed bytes.
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
	"github.com/prometheus/client_golang/prometheus"
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
	Approvals []nodeapproval.Approval `json:"fixture_approvals"`
	TTLMs     uint64                  `json:"ttl_ms"`
	IssuedAt  uint64                  `json:"issued_at"`
	ExpiresAt uint64                  `json:"expires_at"`
	Deliver   *nodeapproval.Batch     `json:"fixture_deliver"`
	Envelope  *string                 `json:"fixture_envelope"`
	Enqueue   []nodeapproval.Approval `json:"enqueue"`
	Metrics   bool                    `json:"metrics"`
}

type signed struct {
	nodeapproval.Batch
	Envelope string `json:"envelope"`
}

type client struct {
	service  *nodeapproval.Service
	registry *prometheus.Registry
	key      ed25519.PrivateKey
	conn     *grpc.ClientConn
	lane     approvalpb.ApprovalDeliveryClient
}

func newClient(url, target string) (*client, error) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	var service *nodeapproval.Service
	var err error
	if target == "" {
		service, err = nodeapproval.NewPreflight(url)
	} else {
		service, err = nodeapproval.New(url, target, seed)
	}
	if err != nil {
		return nil, err
	}
	c := &client{service: service, key: ed25519.NewKeyFromSeed(seed), registry: prometheus.NewRegistry()}
	c.registry.MustRegister(service)
	if target != "" {
		// NewClient is lazy: ordinary approvals open only OPS's own lane. The separate raw
		// connection is dialled only when an invalid fixture explicitly requests Deliver.
		c.conn, err = grpc.NewClient(target,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithKeepaliveParams(keepalive.ClientParameters{Time: 20 * time.Second, Timeout: 5 * time.Second, PermitWithoutStream: true}))
		if err != nil {
			service.Close()
			return nil, err
		}
		c.lane = approvalpb.NewApprovalDeliveryClient(c.conn)
	}
	return c, nil
}

func (c *client) close() {
	c.service.Close()
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		panic("usage: approval-client <rpc-url> [<approval host:port>]")
	}
	var target string
	if len(os.Args) == 3 {
		target = os.Args[2]
	}
	c, err := newClient(os.Args[1], target)
	if err != nil {
		panic(err)
	}
	defer c.close()
	scan := bufio.NewScanner(os.Stdin)
	scan.Buffer(make([]byte, 4096), 1<<20)
	out := json.NewEncoder(os.Stdout)
	for scan.Scan() {
		var q request
		if err := json.Unmarshal(scan.Bytes(), &q); err != nil {
			panic(err)
		}
		reply, err := c.handle(q)
		if err != nil {
			reply = map[string]any{"error": err.Error()}
		}
		if err := out.Encode(reply); err != nil {
			panic(err)
		}
	}
	if err := scan.Err(); err != nil {
		panic(err)
	}
}

func (c *client) handle(q request) (any, error) {
	needLane := q.Deliver != nil || q.Envelope != nil || q.Enqueue != nil
	if needLane && c.lane == nil {
		return nil, errors.New("no delivery target")
	}
	switch {
	case q.Enqueue != nil:
		// The harness can submit immediately after construction. Wait for OPS's own initial
		// Status handshake; a failed enqueue has not signed or sent anything.
		deadline := time.Now().Add(10 * time.Second)
		for i := range q.Enqueue {
			for {
				err := c.service.Enqueue(&nodeapproval.Prepared{Approval: q.Enqueue[i]})
				if err == nil {
					break
				}
				if err.Error() != "no approval producer is ready" || time.Now().After(deadline) {
					return nil, err
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
		return map[string]any{"code": "QUEUED", "queued": len(q.Enqueue)}, nil
	case q.Metrics:
		families, err := c.registry.Gather()
		if err != nil {
			return nil, err
		}
		result := map[string]float64{}
		for _, family := range families {
			for _, metric := range family.Metric {
				name := family.GetName()
				for _, label := range metric.Label {
					if label.GetName() == "code" {
						name += "/" + label.GetValue()
					}
				}
				if metric.Counter != nil {
					result[name] += metric.Counter.GetValue()
				}
				if metric.Gauge != nil {
					result[name] += metric.Gauge.GetValue()
				}
			}
		}
		return result, nil
	case q.Approvals != nil:
		return sign(c.key, q)
	case q.Deliver != nil:
		envelope, err := encode(*q.Deliver)
		if err != nil {
			return nil, err
		}
		return deliver(c.lane, envelope), nil
	case q.Envelope != nil:
		envelope, err := hex.DecodeString(strings.TrimPrefix(*q.Envelope, "0x"))
		if err != nil {
			return nil, err
		}
		return deliver(c.lane, envelope), nil
	default:
		return c.service.Prepare(context.Background(), q.Raw)
	}
}

// sign creates authentication/expiry boundary fixtures; normal approvals use Service.Enqueue.
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
