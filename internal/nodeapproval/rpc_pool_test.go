package nodeapproval

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Bursts model concurrent OPS preflights. Waiting for every request in a burst
// ensures the transport needs the whole pool; subsequent bursts should reuse it.
func TestPreflightRPCReusesConnectionsAcrossBursts(t *testing.T) {
	const parallel, bursts = 32, 5
	var connections, requests atomic.Int64
	gates := make([]chan struct{}, bursts)
	for i := range gates {
		gates[i] = make(chan struct{})
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		n := int(requests.Add(1)) - 1
		gate := gates[n/parallel]
		if n%parallel == parallel-1 {
			close(gate)
		}
		select {
		case <-gate:
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "0x7a69"})
	}))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			connections.Add(1)
		}
	}
	server.Start()
	defer server.Close()
	client, err := NewPreflight(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for range bursts {
		var wg sync.WaitGroup
		for range parallel {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var result string
				if err := client.rpc.CallContext(ctx, &result, "eth_chainId"); err != nil {
					t.Error(err)
				} else if result != "0x7a69" {
					t.Errorf("unexpected result: %s", result)
				}
			}()
		}
		wg.Wait()
	}
	t.Logf("%d requests, %d TCP connections", requests.Load(), connections.Load())
	if got := connections.Load(); got > parallel+2 {
		t.Fatalf("preflight RPC churns connections: got %d connections for %d requests; want at most %d", got, parallel*bursts, parallel+2)
	}
}
