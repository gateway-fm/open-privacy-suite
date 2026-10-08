package nodeapproval

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"runtime"
	"testing"
	"time"
)

// BenchmarkRetentionHeap measures live Go heap for actual signed envelopes and
// approval structs retained by OPS. No transport, hops recorder or EVM is running.
// Run with -benchtime=1x; each case is an independent empty-to-full measurement.
// Batch size matters: sparse traffic often signs much smaller batches than 32.
func BenchmarkRetentionHeap(b *testing.B) {
	for _, capacity := range []int{100_000, 300_000, 1_000_000} {
		for _, size := range []int{1, 8, 32} {
			b.Run(fmt.Sprintf("capacity_%d/batch_%d", capacity, size), func(b *testing.B) {
				for range b.N {
					s, _ := offlineLanes(capacity)
					signer := NewEd25519Signer("default", bytes.Repeat([]byte{7}, 32))
					runtime.GC()
					var before, after runtime.MemStats
					runtime.ReadMemStats(&before)
					for n := 0; n < capacity; n += size {
						approvals := make([]Approval, min(size, capacity-n))
						for i := range approvals {
							approvals[i].ChainID = 31337
							binary.BigEndian.PutUint64(approvals[i].TxHash[24:], uint64(n+i+1))
						}
						batch, err := signer.SignBatch(approvals, time.Hour)
						if err != nil {
							b.Fatal(err)
						}
						s.retain.add(batch, time.Now())
					}
					runtime.GC()
					runtime.ReadMemStats(&after)
					runtime.KeepAlive(s)
					live := int64(after.HeapAlloc) - int64(before.HeapAlloc)
					if live <= 0 || s.retain.approvals != capacity {
						b.Fatalf("invalid heap sample: live=%d retained=%d", live, s.retain.approvals)
					}
					b.ReportMetric(float64(live), "live-heap-B")
					b.ReportMetric(float64(live)/float64(capacity), "live-B/approval")
					b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc)/float64(capacity), "allocated-B/approval")
				}
			})
		}
	}
}
