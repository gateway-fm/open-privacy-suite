package nodepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"
)

const (
	ClaimAdmin   uint8 = 1
	ClaimDeploy  uint8 = 2
	ClaimUpgrade uint8 = 4
)

var (
	ErrSnapshot        = errors.New("invalid policy fact snapshot")
	ErrSnapshotLag     = errors.New("policy fact snapshot has not caught up")
	ErrPrincipal       = errors.New("execution principal is unavailable or not authorised")
	ErrBindingConflict = errors.New("execution binding belongs to another principal")
	ErrCapacity        = errors.New("execution context capacity reached")
)

type Snapshot struct {
	Header
	Version    uint64           `json:"version"`
	Principals []Principal      `json:"principals"`
	Groups     []Group          `json:"groups"`
	Contracts  []Contract       `json:"contracts"`
	Policies   []PolicyArtifact `json:"policies"`
	Sanctions  []Sanction       `json:"sanctions"`
}

func (s Snapshot) MarshalJSON() ([]byte, error) {
	type wireSnapshot Snapshot
	return json.Marshal(wireSnapshot(cloneSnapshot(s)))
}

type Principal struct {
	ID              string       `json:"id"`
	Banned          bool         `json:"banned"`
	KYC             bool         `json:"kyc"`
	LinkedAddresses []string     `json:"linked_addresses"`
	Memberships     []Membership `json:"memberships"`
}

type Membership struct {
	GroupID   string `json:"group_id"`
	ExpiresAt int64  `json:"expires_at"`
}

type Group struct {
	ID             string          `json:"id"`
	OrgID          string          `json:"org_id"`
	Claims         uint8           `json:"claims"`
	OrgAdmin       bool            `json:"org_admin"`
	ContractClaims []ContractClaim `json:"contract_claims"`
}

type ContractClaim struct {
	Address string `json:"address"`
	Claims  uint8  `json:"claims"`
}

type Contract struct {
	Address              string `json:"address"`
	OrgID                string `json:"org_id"`
	SharedInfrastructure bool   `json:"shared_infrastructure"`
	CodeHash             string `json:"code_hash"`
	DeployerPrincipalID  string `json:"deployer_principal_id"`
	Pending              bool   `json:"pending"`
}

type Sanction struct {
	OrgID   string `json:"org_id"`
	Address string `json:"address"`
}

type PolicyArtifact struct {
	OrgID         string `json:"org_id"`
	Revision      uint64 `json:"revision"`
	PolicyDigest  string `json:"policy_digest"`
	RuntimeDigest string `json:"runtime_digest"`
	Bytecode      []byte `json:"bytecode"`
}

// PinnedSnapshot owns its backing memory. Input/output values are copied so
// neither the pusher nor an evaluator can mutate another execution's facts.
type PinnedSnapshot struct {
	snapshot   Snapshot
	principals map[string]Principal
	groups     map[string]Group
}

func Pin(s Snapshot) (*PinnedSnapshot, error) {
	if s.Version == 0 {
		return nil, ErrSnapshot
	}
	v := Verifier{Network: s.Network, Now: func() time.Time { return time.Unix(s.IssuedAt, 0) }}
	if err := v.ValidateHeader(s.Header); err != nil {
		return nil, err
	}
	s = cloneSnapshot(s)
	p := &PinnedSnapshot{snapshot: s, principals: make(map[string]Principal, len(s.Principals)), groups: make(map[string]Group, len(s.Groups))}
	for _, g := range s.Groups {
		if !identifier(g.ID) || !identifier(g.OrgID) || g.Claims&^uint8(7) != 0 {
			return nil, ErrSnapshot
		}
		if _, ok := p.groups[g.ID]; ok {
			return nil, ErrSnapshot
		}
		seen := map[string]bool{}
		for _, grant := range g.ContractClaims {
			if !hexField(grant.Address, 20) || grant.Claims&^uint8(7) != 0 || seen[grant.Address] {
				return nil, ErrSnapshot
			}
			seen[grant.Address] = true
		}
		p.groups[g.ID] = g
	}
	for _, principal := range s.Principals {
		if !identifier(principal.ID) {
			return nil, ErrSnapshot
		}
		if _, ok := p.principals[principal.ID]; ok {
			return nil, ErrSnapshot
		}
		seen := map[string]bool{}
		for _, address := range principal.LinkedAddresses {
			if !hexField(address, 20) || seen[address] {
				return nil, ErrSnapshot
			}
			seen[address] = true
		}
		seen = map[string]bool{}
		for _, m := range principal.Memberships {
			if _, ok := p.groups[m.GroupID]; !ok || seen[m.GroupID] || m.ExpiresAt < 0 {
				return nil, ErrSnapshot
			}
			seen[m.GroupID] = true
		}
		p.principals[principal.ID] = principal
	}
	seen := map[string]bool{}
	for _, c := range s.Contracts {
		if !hexField(c.Address, 20) || seen[c.Address] || (!identifier(c.OrgID) && !(c.SharedInfrastructure && c.OrgID == "")) || (c.CodeHash != "" && !hexField(c.CodeHash, 32)) {
			return nil, ErrSnapshot
		}
		if (c.DeployerPrincipalID != "" && !identifier(c.DeployerPrincipalID)) || (c.Pending && (c.SharedInfrastructure || c.DeployerPrincipalID != "")) {
			return nil, ErrSnapshot
		}
		seen[c.Address] = true
	}
	seen = map[string]bool{}
	for _, artifact := range s.Policies {
		if !validPolicyArtifact(artifact) || seen[artifact.OrgID] {
			return nil, ErrSnapshot
		}
		seen[artifact.OrgID] = true
	}
	seen = map[string]bool{}
	for _, sanction := range s.Sanctions {
		key := sanction.OrgID + ":" + sanction.Address
		if !hexField(sanction.Address, 20) || seen[key] || (sanction.OrgID != "" && !identifier(sanction.OrgID)) {
			return nil, ErrSnapshot
		}
		seen[key] = true
	}
	return p, nil
}

func validPolicyArtifact(artifact PolicyArtifact) bool {
	if !identifier(artifact.OrgID) || artifact.Revision == 0 || len(artifact.Bytecode) == 0 || len(artifact.Bytecode) > 24576 || !hexDigest(artifact.PolicyDigest) || !hexDigest(artifact.RuntimeDigest) {
		return false
	}
	digest := sha256.Sum256(artifact.Bytecode)
	return hex.EncodeToString(digest[:]) == artifact.RuntimeDigest
}

func hexDigest(s string) bool { return len(s) == 64 && hexField("0x"+s, 32) }

type ResolvedFacts struct {
	Principal Principal
	Groups    []Group
	Version   uint64
}

// Resolve uses the execution timestamp for expiry. The identity must first be
// authenticated at ingestion; its membership claims are never an input here.
func (p *PinnedSnapshot) Resolve(i Identity, at time.Time) (ResolvedFacts, error) {
	return p.resolve(i, at, p.snapshot.Header)
}

func (p *PinnedSnapshot) resolve(i Identity, at time.Time, freshness Header) (ResolvedFacts, error) {
	var out ResolvedFacts
	v := Verifier{Network: p.snapshot.Network, Now: func() time.Time { return at }}
	if err := v.ValidateHeader(freshness); err != nil {
		return out, err
	}
	if err := v.ValidateHeader(i.Header); err != nil {
		return out, err
	}
	if i.MinSnapshotVersion == 0 || p.snapshot.Version < i.MinSnapshotVersion {
		return out, ErrSnapshotLag
	}
	principal, ok := p.principals[i.PrincipalID]
	if !ok || principal.Banned || !slices.Contains(principal.LinkedAddresses, i.Signer) || p.IsSanctioned(i.Signer, i.OrgID) {
		return out, ErrPrincipal
	}
	out = ResolvedFacts{Principal: clonePrincipal(principal), Version: p.snapshot.Version}
	selectedOrgActive := false
	for _, m := range principal.Memberships {
		if m.ExpiresAt != 0 && m.ExpiresAt <= at.Unix() {
			continue
		}
		g := p.groups[m.GroupID]
		if g.OrgID == i.OrgID {
			selectedOrgActive = true
		}
		g.ContractClaims = slices.Clone(g.ContractClaims)
		out.Groups = append(out.Groups, g)
	}
	if !selectedOrgActive {
		return ResolvedFacts{}, ErrPrincipal
	}
	return out, nil
}

func (p *PinnedSnapshot) IsSanctioned(address, orgID string) bool {
	return slices.ContainsFunc(p.snapshot.Sanctions, func(s Sanction) bool { return s.Address == address && (s.OrgID == "" || s.OrgID == orgID) })
}

func (p *PinnedSnapshot) Snapshot() Snapshot { return cloneSnapshot(p.snapshot) }

func (v Verifier) OpenSnapshot(wire []byte) (*PinnedSnapshot, error) {
	b, err := v.Open("snapshot", wire)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := decodeStrict(b, &s); err != nil {
		return nil, ErrSnapshot
	}
	if err := v.ValidateHeader(s.Header); err != nil {
		return nil, err
	}
	return Pin(s)
}

func clonePrincipal(p Principal) Principal {
	p.LinkedAddresses = append([]string{}, p.LinkedAddresses...)
	p.Memberships = append([]Membership{}, p.Memberships...)
	return p
}

func cloneSnapshot(s Snapshot) Snapshot {
	s.Principals = append([]Principal{}, s.Principals...)
	for i := range s.Principals {
		s.Principals[i] = clonePrincipal(s.Principals[i])
	}
	s.Groups = append([]Group{}, s.Groups...)
	for i := range s.Groups {
		s.Groups[i].ContractClaims = append([]ContractClaim{}, s.Groups[i].ContractClaims...)
	}
	s.Contracts = append([]Contract{}, s.Contracts...)
	s.Policies = append([]PolicyArtifact{}, s.Policies...)
	for i := range s.Policies {
		s.Policies[i].Bytecode = slices.Clone(s.Policies[i].Bytecode)
	}
	s.Sanctions = append([]Sanction{}, s.Sanctions...)
	return s
}

// IdentityRegistry keeps the first binding while a request is pending. Expiry
// blocks execution but does not make an existing transaction rebindable.
type IdentityRegistry struct {
	mu       sync.RWMutex
	capacity int
	bindings map[string]Identity
}

func NewIdentityRegistry(capacity int) *IdentityRegistry {
	if capacity < 1 {
		capacity = 1
	}
	return &IdentityRegistry{capacity: capacity, bindings: map[string]Identity{}}
}

func (r *IdentityRegistry) Accept(v Verifier, wire []byte) error {
	i, err := v.OpenIdentity(wire)
	if err != nil {
		return err
	}
	key := i.Scope + ":" + i.BindingHash
	if i.Scope == "simulation" {
		key = i.Scope + ":" + i.ContextID
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.bindings[key]; ok {
		if old.PrincipalID != i.PrincipalID || old.OrgID != i.OrgID || old.Signer != i.Signer || old.Network != i.Network || old.BindingHash != i.BindingHash {
			return ErrBindingConflict
		}
		// A renewal may extend lifetime or require newer facts, but it must
		// never roll either back when an older envelope arrives late.
		if i.IssuedAt < old.IssuedAt || i.ExpiresAt < old.ExpiresAt || i.MinSnapshotVersion < old.MinSnapshotVersion {
			return ErrBindingConflict
		}
	} else if len(r.bindings) >= r.capacity {
		return ErrCapacity
	}
	r.bindings[key] = i
	return nil
}

func (r *IdentityRegistry) Lookup(scope, bindingHash string, at time.Time) (Identity, error) {
	if scope != "transaction" {
		return Identity{}, ErrIdentity
	}
	r.mu.RLock()
	i, ok := r.bindings[scope+":"+bindingHash]
	r.mu.RUnlock()
	if !ok {
		return Identity{}, ErrIdentity
	}
	if i.ExpiresAt <= at.Unix() {
		return Identity{}, ErrExpired
	}
	return i, nil
}

func (r *IdentityRegistry) LookupSimulation(contextID, bindingHash string, at time.Time) (Identity, error) {
	r.mu.RLock()
	i, ok := r.bindings["simulation:"+contextID]
	r.mu.RUnlock()
	if !ok || i.BindingHash != bindingHash {
		return Identity{}, ErrIdentity
	}
	if i.ExpiresAt <= at.Unix() {
		return Identity{}, ErrExpired
	}
	return i, nil
}

// Finish is called only by the trusted terminal-status reconciliation path.
func (r *IdentityRegistry) Finish(scope, bindingHash string) {
	r.mu.Lock()
	delete(r.bindings, scope+":"+bindingHash)
	r.mu.Unlock()
}
