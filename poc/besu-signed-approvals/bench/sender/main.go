// Delivery benchmark sender: the same signed OPS approval batches over raw TCP (as the plugin
// receives them today) or over a gRPC bidirectional stream, plain or mTLS. Records when each batch
// left; the receiver records when it arrived; report.py joins the two by the frame's digest.
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
	"time"

	"github.com/ethereum/go-ethereum/common"
	"google.golang.org/grpc"
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
	transport := flag.String("transport", "tcp", "tcp | grpc | grpc-mtls")
	addr := flag.String("addr", "127.0.0.1:19000", "receiver address")
	rate := flag.Int("rate", 500, "batches per second")
	count := flag.Int("count", 10000, "batches to send")
	perBatch := flag.Int("batch", 32, "approvals per batch (max 32)")
	out := flag.String("out", "sender.jsonl", "records file")
	certs := flag.String("certs", "certs", "directory with ca.crt, client.crt, client.key")
	flag.Parse()

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
		frames[i] = b.Frame()[4:] // body without the length prefix; the transport adds its own framing
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
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	case "grpc", "grpc-mtls":
		opts := []grpc.DialOption{}
		if *transport == "grpc-mtls" {
			ca, err := os.ReadFile(filepath.Join(*certs, "ca.crt"))
			if err != nil {
				log.Fatal(err)
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(ca)
			cert, err := tls.LoadX509KeyPair(filepath.Join(*certs, "client.crt"), filepath.Join(*certs, "client.key"))
			if err != nil {
				log.Fatal(err)
			}
			opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				Certificates: []tls.Certificate{cert}, RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13})))
		} else {
			opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		}
		cc, err := grpc.NewClient(*addr, opts...)
		if err != nil {
			log.Fatal(err)
		}
		defer cc.Close()
		stream, err := gen.NewApprovalDeliveryClient(cc).Deliver(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		acked := make(chan struct{})
		go func() {
			defer close(acked)
			for {
				ack, err := stream.Recv()
				if err != nil {
					return
				}
				if r, ok := records[ack.Id]; ok {
					r.AckNs = time.Now().UnixNano()
				}
			}
		}()
		for _, body := range frames {
			<-tick.C
			id := digest(body)
			r := &record{ID: id, SentNs: time.Now().UnixNano(), Bytes: len(body)}
			records[id] = r // before Send: the ack reader looks it up
			if err := stream.Send(&gen.Batch{Id: id, Frame: body, SentNs: r.SentNs}); err != nil {
				log.Fatal(err)
			}
		}
		time.Sleep(500 * time.Millisecond) // let the last acks land
		stream.CloseSend()
		select {
		case <-acked:
		case <-time.After(2 * time.Second):
		}
	default:
		log.Fatalf("unknown transport %q", *transport)
	}
	for _, r := range records {
		line, _ := json.Marshal(r)
		w.Write(line)
		w.WriteByte('\n')
	}
	fmt.Printf("SENT %d batches x %d approvals over %s in %.1fs (%.0f batches/s requested %d)\n",
		*count, *perBatch, *transport, time.Since(started).Seconds(), float64(*count)/time.Since(started).Seconds(), *rate)
}

func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
