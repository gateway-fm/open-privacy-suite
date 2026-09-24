// Delivery benchmark sender: the same signed OPS approval batches over raw TCP (as the plugin
// receives them today), over a gRPC bidirectional stream, or as one gRPC unary call per batch on one
// shared connection; each gRPC shape plain or mTLS. Records when each batch left and when it was
// confirmed; the receiver records when it arrived; report.py joins the two by the frame's digest.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"privacy-proxy/internal/nodeapproval"
	"privacy-proxy/poc/besu-signed-approvals/bench/gen"
)

type record struct {
	ID     string `json:"id"`
	SentNs int64  `json:"sent_ns"`
	AckNs  int64  `json:"ack_ns,omitempty"`
	Bytes  int    `json:"bytes"`
}

func main() {
	transport := flag.String("transport", "tcp", "tcp | grpc | grpc-mtls | grpc-unary | grpc-unary-mtls")
	addr := flag.String("addr", "127.0.0.1:19000", "receiver address")
	rate := flag.Int("rate", 500, "batches per second")
	count := flag.Int("count", 10000, "batches to send")
	perBatch := flag.Int("batch", 32, "approvals per batch (max 32)")
	out := flag.String("out", "sender.jsonl", "records file")
	certs := flag.String("certs", "certs", "directory with ca.crt, client.crt, client.key")
	inflight := flag.Int("inflight", 8, "grpc-unary: most calls outstanding at once on the shared connection")
	flag.Parse()
	if *inflight < 1 {
		log.Fatal("-inflight must be at least 1")
	}

	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	frames := make([][]byte, *count) // pre-signed: signing is measured elsewhere (24 µs p50)
	for i := range frames {
		approvals := make([]nodeapproval.Approval, *perBatch)
		for j := range approvals {
			unique := sha256.Sum256([]byte(fmt.Sprintf("%d-%d", i, j)))
			approvals[j] = nodeapproval.Approval{HashMode: nodeapproval.HashCalls, ChainID: 31337,
				TxHash: common.BytesToHash(unique[:]), Fingerprint: common.HexToHash("0x5678")}
		}
		b, err := nodeapproval.SignBatch(key, approvals)
		if err != nil {
			log.Fatal(err)
		}
		frames[i] = b.Encoded() // the signed envelope; each transport adds its own framing
	}
	f, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	w := bufio.NewWriter(f)
	defer func() { w.Flush(); f.Close() }()
	records := make(map[string]*record, *count)
	tick := time.NewTicker(time.Second / time.Duration(*rate))
	defer tick.Stop()
	started := time.Now()
	var sendTime time.Duration // the send loop alone, so SENT rates compare across shapes (drains come after)
	var note string            // unary runs add their in-flight detail to the SENT line

	switch *transport {
	case "tcp":
		conn, err := net.Dial("tcp", *addr)
		if err != nil {
			log.Fatal(err)
		}
		conn.(*net.TCPConn).SetNoDelay(true)
		for _, body := range frames {
			<-tick.C
			id := digest(body)
			frame := binary.BigEndian.AppendUint32(nil, uint32(len(body)))
			frame = append(frame, body...)
			r := &record{ID: id, SentNs: time.Now().UnixNano(), Bytes: len(body)}
			if _, err := conn.Write(frame); err != nil {
				log.Fatal(err)
			}
			records[id] = r
		}
		sendTime = time.Since(started)
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	case "grpc", "grpc-mtls":
		cc := dial(*transport, *addr, *certs)
		defer cc.Close()
		stream, err := gen.NewApprovalDeliveryClient(cc).Deliver(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		var mu sync.Mutex // the ack reader looks records up while the send loop adds them
		acked := make(chan struct{})
		go func() {
			defer close(acked)
			for {
				ack, err := stream.Recv()
				if err != nil {
					return
				}
				at := time.Now().UnixNano()
				mu.Lock()
				if r, ok := records[ack.Id]; ok {
					r.AckNs = at
				}
				mu.Unlock()
			}
		}()
		for _, body := range frames {
			<-tick.C
			id := digest(body)
			r := &record{ID: id, SentNs: time.Now().UnixNano(), Bytes: len(body)}
			mu.Lock()
			records[id] = r // before Send: the ack reader looks it up
			mu.Unlock()
			if err := stream.Send(&gen.Batch{Id: id, Frame: body, SentNs: r.SentNs}); err != nil {
				log.Fatal(err)
			}
		}
		sendTime = time.Since(started)
		time.Sleep(500 * time.Millisecond) // let the last acks land
		stream.CloseSend()
		select {
		case <-acked:
		case <-time.After(2 * time.Second):
		}
		mu.Lock() // an ack still arriving after the timeout must not race the write-out below
		defer mu.Unlock()
	case "grpc-unary", "grpc-unary-mtls":
		cc := dial(*transport, *addr, *certs)
		defer cc.Close()
		connect(cc) // before the first batch, as opening the stream does for the stream shape
		client := gen.NewApprovalDeliveryClient(cc)
		// A receiver that stops answering must fail the run, not hang it (the stream shape gives up after 2 s).
		watchdog := time.AfterFunc(time.Duration(*count)*time.Second/time.Duration(*rate)+30*time.Second, func() {
			log.Fatal("unary calls still outstanding 30 s after the schedule ended")
		})
		slots := make(chan struct{}, *inflight)
		var calls sync.WaitGroup
		peak, waited := 0, 0
		for _, body := range frames {
			<-tick.C
			id := digest(body)
			r := &record{ID: id, SentNs: time.Now().UnixNano(), Bytes: len(body)}
			records[id] = r // only this loop touches the map; each call fills in its own AckNs
			// Timed from the same point as a stream Send: waiting for a free slot counts, as a blocked Send would.
			select {
			case slots <- struct{}{}:
			default: // every slot taken
				waited++
				slots <- struct{}{}
			}
			peak = max(peak, len(slots))
			calls.Add(1)
			go func() {
				defer func() { <-slots; calls.Done() }()
				if _, err := client.DeliverOne(context.Background(), &gen.Batch{Id: id, Frame: body, SentNs: r.SentNs}); err != nil {
					log.Fatal(err)
				}
				r.AckNs = time.Now().UnixNano() // the call's OK status is the confirmation
			}()
		}
		sendTime = time.Since(started)
		calls.Wait()
		watchdog.Stop()
		note = fmt.Sprintf("; up to %d of %d calls in flight, %d sends waited for a slot", peak, *inflight, waited)
	default:
		log.Fatalf("unknown transport %q", *transport)
	}
	for _, r := range records {
		line, _ := json.Marshal(r)
		w.Write(line)
		w.WriteByte('\n')
	}
	fmt.Printf("SENT %d batches x %d approvals over %s in %.1fs (%.0f batches/s requested %d%s)\n",
		*count, *perBatch, *transport, sendTime.Seconds(), float64(*count)/sendTime.Seconds(), *rate, note)
}

// dial opens the one client connection a gRPC run shares; "-mtls" transports present a client certificate.
func dial(transport, addr, certs string) *grpc.ClientConn {
	creds := insecure.NewCredentials()
	if strings.HasSuffix(transport, "-mtls") {
		ca, err := os.ReadFile(filepath.Join(certs, "ca.crt"))
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(ca)
		cert, err := tls.LoadX509KeyPair(filepath.Join(certs, "client.crt"), filepath.Join(certs, "client.key"))
		if err != nil {
			log.Fatal(err)
		}
		creds = credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13})
	}
	cc, err := grpc.NewClient(addr, grpc.WithTransportCredentials(creds))
	if err != nil {
		log.Fatal(err)
	}
	return cc
}

// connect waits until the connection (and its TLS handshake) is up, so no timed call pays for it.
func connect(cc *grpc.ClientConn) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cc.Connect()
	for s := cc.GetState(); s != connectivity.Ready; s = cc.GetState() {
		if !cc.WaitForStateChange(ctx, s) {
			log.Fatalf("receiver not ready: %s", s)
		}
	}
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
