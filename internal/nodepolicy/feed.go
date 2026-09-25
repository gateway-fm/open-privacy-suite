package nodepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"sync"
	"time"
)

var ErrFeedConflict = errors.New("node policy stream requires resynchronisation")

type FactSet struct {
	Principals []Principal      `json:"principals"`
	Groups     []Group          `json:"groups"`
	Contracts  []Contract       `json:"contracts"`
	Policies   []PolicyArtifact `json:"policies"`
	Sanctions  []Sanction       `json:"sanctions"`
}
type FactDeletes struct {
	Principals []string   `json:"principals"`
	Groups     []string   `json:"groups"`
	Contracts  []string   `json:"contracts"`
	Policies   []string   `json:"policies"`
	Sanctions  []Sanction `json:"sanctions"`
}
type Delta struct {
	Header
	PreviousVersion uint64      `json:"previous_version"`
	PreviousDigest  string      `json:"previous_digest"`
	Version         uint64      `json:"version"`
	Upserts         FactSet     `json:"upserts"`
	Deletes         FactDeletes `json:"deletes"`
}
type Heartbeat struct {
	Header
	Version uint64 `json:"version"`
	Digest  string `json:"digest"`
}

func (d Delta) MarshalJSON() ([]byte, error) {
	type wire Delta
	s := cloneSnapshot(Snapshot{Principals: d.Upserts.Principals, Groups: d.Upserts.Groups, Contracts: d.Upserts.Contracts, Policies: d.Upserts.Policies, Sanctions: d.Upserts.Sanctions})
	d.Upserts = FactSet{s.Principals, s.Groups, s.Contracts, s.Policies, s.Sanctions}
	d.Deletes.Principals = append([]string{}, d.Deletes.Principals...)
	d.Deletes.Groups = append([]string{}, d.Deletes.Groups...)
	d.Deletes.Contracts = append([]string{}, d.Deletes.Contracts...)
	d.Deletes.Policies = append([]string{}, d.Deletes.Policies...)
	d.Deletes.Sanctions = append([]Sanction{}, d.Deletes.Sanctions...)
	return json.Marshal(wire(d))
}

// Feed is the Go reference implementation of the node's signed, atomic stream.
// Each view pins facts and their freshness lease together for one execution.
type Feed struct {
	mu      sync.RWMutex
	current *FeedView
}
type FeedView struct {
	facts  *PinnedSnapshot
	digest string
	lease  Header
}

func (p *FeedView) Digest() string     { return p.digest }
func (p *FeedView) Version() uint64    { return p.facts.snapshot.Version }
func (p *FeedView) Snapshot() Snapshot { return p.facts.Snapshot() }
func (p *FeedView) Lease() Header      { return p.lease }
func (p *FeedView) Resolve(i Identity, at time.Time) (ResolvedFacts, error) {
	return p.facts.resolve(i, at, p.lease)
}
func (f *Feed) Pin(at time.Time) (*FeedView, error) {
	f.mu.RLock()
	p := f.current
	f.mu.RUnlock()
	if p == nil {
		return nil, ErrSnapshotLag
	}
	if err := (Verifier{Network: p.lease.Network, Now: func() time.Time { return at }}).ValidateHeader(p.lease); err != nil {
		return nil, err
	}
	return p, nil
}

func PayloadDigest(payload []byte) string {
	d := sha256.Sum256(payload)
	return hex.EncodeToString(d[:])
}
func (f *Feed) Apply(v Verifier, wire []byte) error {
	if len(wire) > MaxEnvelopeBytes {
		return ErrEnvelope
	}
	var envelope Envelope
	if err := decodeStrict(wire, &envelope); err != nil {
		return ErrEnvelope
	}
	if envelope.Kind != "snapshot" && envelope.Kind != "delta" && envelope.Kind != "heartbeat" {
		return ErrEnvelope
	}
	payload, err := v.Open(envelope.Kind, wire)
	if err != nil {
		return err
	}
	digest := PayloadDigest(payload)
	f.mu.Lock()
	defer f.mu.Unlock()
	current := f.current
	switch envelope.Kind {
	case "snapshot":
		var s Snapshot
		if err := decodeStrict(payload, &s); err != nil {
			return ErrSnapshot
		}
		if err := v.ValidateHeader(s.Header); err != nil {
			return err
		}
		if current != nil && s.Version <= current.Version() {
			if s.Version == current.Version() && digest == current.digest {
				return nil
			}
			return ErrFeedConflict
		}
		p, err := Pin(s)
		if err != nil {
			return err
		}
		f.current = &FeedView{facts: p, digest: digest, lease: s.Header}
	case "delta":
		var d Delta
		if err := decodeStrict(payload, &d); err != nil {
			return ErrSnapshot
		}
		if err := v.ValidateHeader(d.Header); err != nil {
			return err
		}
		if current == nil || !hexDigest(d.PreviousDigest) || d.Version <= d.PreviousVersion {
			return ErrFeedConflict
		}
		if d.Version == current.Version() && digest == current.digest {
			return nil
		}
		if d.PreviousVersion != current.Version() || d.PreviousDigest != current.digest {
			return ErrFeedConflict
		}
		next, err := applyDelta(current.facts.snapshot, d)
		if err != nil {
			return err
		}
		p, err := Pin(next)
		if err != nil {
			return err
		}
		f.current = &FeedView{facts: p, digest: digest, lease: d.Header}
	case "heartbeat":
		var h Heartbeat
		if err := decodeStrict(payload, &h); err != nil {
			return ErrSnapshot
		}
		if err := v.ValidateHeader(h.Header); err != nil {
			return err
		}
		if current == nil || h.Version != current.Version() || h.Digest != current.digest || h.IssuedAt < current.lease.IssuedAt || h.ExpiresAt < current.lease.ExpiresAt {
			return ErrFeedConflict
		}
		f.current = &FeedView{facts: current.facts, digest: current.digest, lease: h.Header}
	}
	return nil
}

func principalKey(p Principal) string { return p.ID }
func groupKey(g Group) string         { return g.ID }
func contractKey(c Contract) string   { return c.Address }

// The NUL separator cannot occur in either identifier. Keep legacy org-only
// keys unchanged so an upgrade can delete previously published artifacts.
func policyKey(p PolicyArtifact) string {
	if p.GroupID == "" {
		return p.OrgID
	}
	return p.OrgID + "\x00" + p.GroupID
}
func sanctionKey(s Sanction) string { return s.OrgID + ":" + s.Address }

func applyDelta(base Snapshot, d Delta) (Snapshot, error) {
	out := cloneSnapshot(base)
	out.Header, out.Version = d.Header, d.Version
	var err error
	if out.Principals, err = mergeFacts(out.Principals, d.Upserts.Principals, d.Deletes.Principals, principalKey); err != nil {
		return Snapshot{}, err
	}
	if out.Groups, err = mergeFacts(out.Groups, d.Upserts.Groups, d.Deletes.Groups, groupKey); err != nil {
		return Snapshot{}, err
	}
	if out.Contracts, err = mergeFacts(out.Contracts, d.Upserts.Contracts, d.Deletes.Contracts, contractKey); err != nil {
		return Snapshot{}, err
	}
	if out.Policies, err = mergeFacts(out.Policies, d.Upserts.Policies, d.Deletes.Policies, policyKey); err != nil {
		return Snapshot{}, err
	}
	deletes := make([]string, 0, len(d.Deletes.Sanctions))
	for _, s := range d.Deletes.Sanctions {
		deletes = append(deletes, sanctionKey(s))
	}
	if out.Sanctions, err = mergeFacts(out.Sanctions, d.Upserts.Sanctions, deletes, sanctionKey); err != nil {
		return Snapshot{}, err
	}
	return out, nil
}

func mergeFacts[T any](base, upserts []T, deletes []string, key func(T) string) ([]T, error) {
	values := make(map[string]T, len(base)+len(upserts))
	for _, v := range base {
		values[key(v)] = v
	}
	seen := map[string]bool{}
	for _, id := range deletes {
		if _, ok := values[id]; !ok || seen[id] {
			return nil, ErrSnapshot
		}
		seen[id] = true
		delete(values, id)
	}
	for _, v := range upserts {
		id := key(v)
		if seen[id] {
			return nil, ErrSnapshot
		}
		seen[id] = true
		values[id] = v
	}
	ids := make([]string, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]T, 0, len(ids))
	for _, id := range ids {
		out = append(out, values[id])
	}
	return out, nil
}

// BuildDelta compares two coherent database generations. The prior digest is
// the acknowledged signed payload digest, not a re-encoding of prior facts.
func BuildDelta(previous Snapshot, previousDigest string, next Snapshot) (Delta, error) {
	d := Delta{Header: next.Header, PreviousVersion: previous.Version, PreviousDigest: previousDigest, Version: next.Version}
	if previous.Network != next.Network || previous.Version >= next.Version || !hexDigest(previousDigest) {
		return Delta{}, ErrFeedConflict
	}
	if _, err := Pin(previous); err != nil {
		return Delta{}, err
	}
	if _, err := Pin(next); err != nil {
		return Delta{}, err
	}
	previous, next = cloneSnapshot(previous), cloneSnapshot(next)
	d.Upserts.Principals, d.Deletes.Principals = diffFacts(previous.Principals, next.Principals, principalKey)
	d.Upserts.Groups, d.Deletes.Groups = diffFacts(previous.Groups, next.Groups, groupKey)
	d.Upserts.Contracts, d.Deletes.Contracts = diffFacts(previous.Contracts, next.Contracts, contractKey)
	d.Upserts.Policies, d.Deletes.Policies = diffFacts(previous.Policies, next.Policies, policyKey)
	sanctions, deletes := diffFacts(previous.Sanctions, next.Sanctions, sanctionKey)
	d.Upserts.Sanctions = sanctions
	removed := map[string]bool{}
	for _, key := range deletes {
		removed[key] = true
	}
	for _, s := range previous.Sanctions {
		if removed[sanctionKey(s)] {
			d.Deletes.Sanctions = append(d.Deletes.Sanctions, s)
		}
	}
	sort.Slice(d.Deletes.Sanctions, func(i, j int) bool { return sanctionKey(d.Deletes.Sanctions[i]) < sanctionKey(d.Deletes.Sanctions[j]) })
	return d, nil
}
func diffFacts[T any](before, after []T, key func(T) string) ([]T, []string) {
	old := map[string]T{}
	for _, v := range before {
		old[key(v)] = v
	}
	upserts := []T{}
	for _, v := range after {
		id := key(v)
		if previous, ok := old[id]; !ok || !reflect.DeepEqual(previous, v) {
			upserts = append(upserts, v)
		}
		delete(old, id)
	}
	deletes := make([]string, 0, len(old))
	for id := range old {
		deletes = append(deletes, id)
	}
	sort.Slice(upserts, func(i, j int) bool { return key(upserts[i]) < key(upserts[j]) })
	sort.Strings(deletes)
	return upserts, deletes
}
