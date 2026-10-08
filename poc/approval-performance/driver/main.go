// The delivery probe uses OPS's real signer, retention and gRPC lanes against a
// real receiver. Synthetic hashes deliberately exclude preflight, authorization,
// transaction forwarding and execution: these numbers are not transaction TPS.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"time"

	"privacy-proxy/internal/nodeapproval"

	"github.com/prometheus/client_golang/prometheus"
)

type command struct {
	Op      string  `json:"op"`
	Rate    int     `json:"rate"`
	Seconds float64 `json:"seconds"`
	Count   int     `json:"count"`
	Timeout float64 `json:"timeout_seconds"`
	RawTx   string  `json:"raw_tx"`
}

type probe struct {
	s      *nodeapproval.Service
	r      *prometheus.Registry
	serial uint64
}

func (p *probe) snapshot() map[string]any {
	runtime.GC() // snapshots are outside measured sending intervals
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	families, err := p.r.Gather()
	if err != nil {
		panic(err)
	}
	return map[string]any{"at_unix_ms": time.Now().UnixMilli(), "heap_alloc_bytes": mem.HeapAlloc,
		"heap_inuse_bytes": mem.HeapInuse, "total_alloc_bytes": mem.TotalAlloc,
		"gc_count": mem.NumGC, "gc_pause_total_ns": mem.PauseTotalNs, "metrics": families}
}

func (p *probe) confirmed() float64 {
	families, err := p.r.Gather()
	if err != nil {
		panic(err)
	}
	var n float64
	for _, family := range families {
		if family.GetName() == "privacyproxy_approval_confirmed_total" {
			for _, m := range family.Metric {
				n += m.GetCounter().GetValue()
			}
		}
	}
	return n
}

func (p *probe) run(c command) map[string]any {
	start := time.Now()
	duration := time.Duration(c.Seconds * float64(time.Second))
	want := int(c.Seconds * float64(c.Rate))
	accepted, refused := 0, 0
	latencies := make([]int64, 0, want)
	lag := make([]int64, 0, want)
	for i := 0; i < want; i++ {
		due := start.Add(time.Duration(float64(i) * float64(time.Second) / float64(c.Rate)))
		if delay := time.Until(due); delay > 0 {
			time.Sleep(delay)
		}
		if time.Since(start) >= duration {
			break // do not stretch the sending window to manufacture the requested rate
		}
		p.serial++
		a := nodeapproval.Approval{ChainID: 31337, HashMode: nodeapproval.HashCalls}
		binary.BigEndian.PutUint64(a.TxHash[24:], p.serial)
		a.Fingerprint[0] = 1
		before := time.Now()
		err := p.s.Enqueue(&nodeapproval.Prepared{Approval: a})
		latencies = append(latencies, time.Since(before).Nanoseconds())
		lag = append(lag, before.Sub(due).Nanoseconds())
		if err != nil {
			refused++
		} else {
			accepted++
		}
	}
	if delay := time.Until(start.Add(duration)); delay > 0 {
		time.Sleep(delay)
	}
	elapsed := time.Since(start).Seconds()
	return map[string]any{"requested": want, "accepted": accepted, "refused": refused,
		"not_offered_before_deadline": want - accepted - refused, "elapsed_seconds": elapsed,
		"accepted_per_second": float64(accepted) / elapsed,
		"started_unix_ms":     start.UnixMilli(), "confirmed_at_end": p.confirmed(),
		"enqueue_ns": quantiles(latencies), "schedule_lag_ns": quantiles(lag)}
}

func quantiles(values []int64) map[string]int64 {
	if len(values) == 0 {
		return nil
	}
	slices.Sort(values)
	return map[string]int64{"p50": values[(len(values)-1)/2], "p95": values[(len(values)-1)*95/100],
		"p99": values[(len(values)-1)*99/100], "max": values[len(values)-1]}
}

func run() error {
	rpc := flag.String("rpc", "", "isolated node's JSON-RPC URL")
	target := flag.String("target", "", "isolated approval receiver host:port")
	flag.Parse()
	if *rpc == "" || *target == "" {
		return fmt.Errorf("-rpc and -target are required")
	}
	s, err := nodeapproval.New(*rpc, *target, bytes.Repeat([]byte{7}, 32))
	if err != nil {
		return err
	}
	defer s.Close()
	p := probe{s: s, r: prometheus.NewRegistry()}
	p.r.MustRegister(s)
	deadline := time.Now().Add(20 * time.Second)
	for !s.Accepting() {
		if time.Now().After(deadline) {
			return fmt.Errorf("approval receiver did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	decoder, encoder := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	if err := encoder.Encode(map[string]any{"ready": true, "snapshot": p.snapshot()}); err != nil {
		return err
	}
	for {
		var c command
		if err := decoder.Decode(&c); err == io.EOF {
			return nil
		} else if err != nil {
			return err
		}
		var result any
		switch c.Op {
		case "prepare":
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			prepared, err := p.s.Prepare(ctx, c.RawTx)
			cancel()
			if err != nil {
				return err
			}
			// A local execution/recovery probe. The transaction benchmark separately
			// exercises OPS's complete authentication and policy path.
			if err := p.s.Enqueue(prepared); err != nil {
				return err
			}
			result = map[string]any{"tx_hash": prepared.Approval.TxHash.Hex()}
		case "run":
			if c.Rate < 1 || c.Rate > 100_000 || c.Seconds <= 0 || c.Seconds > 600 {
				return fmt.Errorf("run requires rate 1..100000 and duration (0,600] seconds")
			}
			result = p.run(c)
		case "wait":
			if c.Count < 0 || c.Timeout <= 0 || c.Timeout > 120 {
				return fmt.Errorf("wait requires nonnegative count and timeout (0,120] seconds")
			}
			started := time.Now()
			for p.confirmed() < float64(c.Count) && time.Since(started).Seconds() < c.Timeout {
				time.Sleep(10 * time.Millisecond)
			}
			result = map[string]any{"reached": p.confirmed() >= float64(c.Count),
				"elapsed_seconds": time.Since(started).Seconds(), "confirmed": p.confirmed()}
		case "snapshot":
			result = p.snapshot()
		case "close":
			s.Close()
			return encoder.Encode(map[string]any{"op": "close", "result": p.snapshot()})
		default:
			return fmt.Errorf("unknown operation %q", c.Op)
		}
		if err := encoder.Encode(map[string]any{"op": c.Op, "result": result}); err != nil {
			return err
		}
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
