package server

import (
	"sort"
	"strconv"
	"testing"
)

// TestCountAcrossPages verifies the paged counter sums survivors across ALL
// pages — not just the first — which is the core of the address-stats fix:
// privacy/gRPC mode clamps each fetch to ~100 rows, so a single fetch capped the
// count at 100. It also pins the maxScan bound, termination, and identity dedup
// against a backend that ignores `before` (re-serving or reordering rows).
func TestCountAcrossPages(t *testing.T) {
	type item struct {
		id    int
		block uint64
		vis   bool
	}
	const total = 250
	// Newest-first feed across blocks total..1, one tx per block; every 3rd is
	// not visible (would be dropped by redaction).
	feed := make([]item, 0, total)
	for b := uint64(total); b >= 1; b-- {
		feed = append(feed, item{id: int(b), block: b, vis: b%3 != 0})
	}
	wantVisible := 0
	for _, it := range feed {
		if it.vis {
			wantVisible++
		}
	}

	const perPage = 100 // simulate the privacy/gRPC indexer page clamp
	// fetch returns up to perPage items strictly older than `before` (nil=newest),
	// mirroring GetTransactionsByAddress(... block_number < before ...).
	fetch := func(before *uint64) ([]item, error) {
		out := make([]item, 0, perPage)
		for _, it := range feed {
			if before != nil && it.block >= *before {
				continue
			}
			out = append(out, it)
			if len(out) == perPage {
				break
			}
		}
		return out, nil
	}
	cursorOf := func(it item) uint64 { return it.block }
	keyOf := func(it item) string { return strconv.Itoa(it.id) }
	survivors := func(page []item) (int, error) {
		n := 0
		for _, it := range page {
			if it.vis {
				n++
			}
		}
		return n, nil
	}

	t.Run("counts across all pages (not capped at one page)", func(t *testing.T) {
		got, err := countAcrossPages(fetch, cursorOf, keyOf, survivors, 10000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		if got != wantVisible {
			t.Errorf("count = %d, want %d (must scan all %d items, not just the first %d)",
				got, wantVisible, total, perPage)
		}
		if wantVisible <= perPage {
			t.Fatalf("test setup: wantVisible (%d) must exceed perPage (%d) to prove uncapped", wantVisible, perPage)
		}
	})

	t.Run("respects maxScan bound (rounds up to a page)", func(t *testing.T) {
		// maxScan=150 with perPage=100 -> scans 2 pages (200 items) then stops.
		got, err := countAcrossPages(fetch, cursorOf, keyOf, survivors, 150)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		want := 0
		for _, it := range feed[:200] {
			if it.vis {
				want++
			}
		}
		if got != want {
			t.Errorf("bounded count = %d, want %d (first 2 pages)", got, want)
		}
		if got >= wantVisible {
			t.Errorf("bounded count = %d should be < full %d (maxScan must engage)", got, wantVisible)
		}
	})

	t.Run("single block larger than a page terminates (remainder omitted)", func(t *testing.T) {
		// All items in the same block (block 7). After the first page the cursor
		// advances to 7; the next fetch (block < 7) is empty, so the loop
		// terminates. The same-block remainder beyond one page is omitted, but
		// the loop is always bounded — never infinite.
		same := make([]item, 500)
		for i := range same {
			same[i] = item{id: i, block: 7, vis: true}
		}
		fetchSame := func(before *uint64) ([]item, error) {
			if before != nil && *before <= 7 {
				return nil, nil
			}
			return same[:perPage], nil
		}
		got, err := countAcrossPages(fetchSame, cursorOf, keyOf, survivors, 10000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		if got != perPage {
			t.Errorf("count = %d, want %d (one page counted, then bounded break)", got, perPage)
		}
	})

	t.Run("backend that re-serves the identical page is not double-counted", func(t *testing.T) {
		// The gRPC chain-indexer backend ignores `before` and re-serves the same
		// page on every call. Identity dedup counts the page once; the second
		// fetch yields no new rows and breaks.
		wantFirstPage := 0
		for _, it := range feed[:perPage] {
			if it.vis {
				wantFirstPage++
			}
		}
		calls := 0
		fetchIgnoresBefore := func(_ *uint64) ([]item, error) {
			calls++
			return feed[:perPage], nil
		}
		got, err := countAcrossPages(fetchIgnoresBefore, cursorOf, keyOf, survivors, 10000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		if got != wantFirstPage {
			t.Errorf("count = %d, want %d (re-served page counted once, not doubled)", got, wantFirstPage)
		}
		if calls != 2 {
			t.Errorf("fetch calls = %d, want 2 (count first page, then no new rows breaks)", calls)
		}
	})

	t.Run("backend re-serves an inclusive, reordered page is not double-counted", func(t *testing.T) {
		// Real gRPC failure the old page[0]>=before guard missed: `before` is
		// mapped to an INCLUSIVE block bound and rows come back ascending, so the
		// re-served page's first row is the minimum block (< before) and the last
		// is the maximum. The old guard advanced the cursor to the max and never
		// tripped, counting the overlap again. Identity dedup counts each row once.
		small := []item{
			{id: 1, block: 50, vis: true},
			{id: 2, block: 40, vis: true},
			{id: 3, block: 30, vis: false},
			{id: 4, block: 20, vis: true},
			{id: 5, block: 10, vis: true},
		}
		wantVis := 0
		for _, it := range small {
			if it.vis {
				wantVis++
			}
		}
		fetchInclusiveAsc := func(before *uint64) ([]item, error) {
			out := make([]item, 0, len(small))
			for _, it := range small {
				if before != nil && it.block > *before { // inclusive: keep block <= before
					continue
				}
				out = append(out, it)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].block < out[j].block }) // ascending
			return out, nil
		}
		got, err := countAcrossPages(fetchInclusiveAsc, cursorOf, keyOf, survivors, 10000)
		if err != nil {
			t.Fatalf("countAcrossPages: %v", err)
		}
		if got != wantVis {
			t.Errorf("count = %d, want %d (inclusive reordered re-serve must not double-count)", got, wantVis)
		}
	})
}
