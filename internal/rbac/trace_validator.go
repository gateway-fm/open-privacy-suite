package rbac

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"privacy-proxy/internal/evm/precompile"
	"privacy-proxy/internal/tracer"
)

// TraceValidatorStore is a subset of Store used by TraceValidator.
// This allows using either the full Store or a mock implementation.
type TraceValidatorStore interface {
	// Contract ownership methods
	IsAddressOwnedByOrg(ctx context.Context, address string, orgID string) (bool, error)
	GetContractOwnerOrgID(ctx context.Context, address string) (string, error)

	// IsAddressPreregistered reports whether the address is a pending
	// (precomputed, not-yet-mined) deployment for the org — a CREATE /
	// CREATE2 / CREATE3 address registered before the tx is forwarded
	// (migration 018 / runtime-CREATE2 flow). RD-1053 consults this on the
	// intra-org deny path so strict mode doesn't block an in-flight
	// deployment whose grant row doesn't exist yet (mirrors CheckAccess).
	IsAddressPreregistered(ctx context.Context, orgID, address string) (bool, error)

	// Shared infrastructure methods
	IsSharedInfrastructure(ctx context.Context, address string) (bool, error)
	CreateSharedInfrastructure(ctx context.Context, infra *SharedInfrastructure) error
	ListSharedInfrastructure(ctx context.Context) ([]*SharedInfrastructure, error)
	DeleteSharedInfrastructure(ctx context.Context, address string) error
	// GetSharedInfrastructure returns the full row for a tagged address,
	// or nil when not tagged. Used by M5 codehash-pin: the validator
	// needs the stored codehash, not just the tagged-bool. Returns nil
	// when not found.
	GetSharedInfrastructure(ctx context.Context, address string) (*SharedInfrastructure, error)
}

// CodeHashFetcher fetches the keccak256 of the current bytecode at an
// address. Used by TraceValidator (M5 codehash-pin for
// shared_infrastructure). Implemented by *tracer.RuntimeTracer; tests
// inject a static map.
//
// The implementation MUST resolve the code at "latest" — pinning to a
// historical block would defeat the rotation-detection property the
// codehash check exists to provide.
type CodeHashFetcher interface {
	GetCodeHash(ctx context.Context, address string) (string, error)
}

// TraceValidator validates transaction traces against RBAC rules.
// It ensures that all addresses touched by a transaction are allowed
// for the user's organization(s), enforcing cross-org isolation.
type TraceValidator struct {
	store          TraceValidatorStore
	precompileFunc func(addr string) bool // For dependency injection in tests
	// codeFetcher is used by the M5 codehash-pin check on
	// shared_infrastructure. Nil disables the check — tagged rows
	// continue to behave as before. Set via SetCodeHashFetcher; the
	// server wires *tracer.RuntimeTracer here at startup.
	codeFetcher CodeHashFetcher
}

// SetCodeHashFetcher wires a CodeHashFetcher into the validator. Call
// at startup after the runtime tracer is initialised. A nil fetcher
// disables the M5 codehash-pin check (back-compat for callers that
// don't have node access — tests).
func (v *TraceValidator) SetCodeHashFetcher(f CodeHashFetcher) {
	v.codeFetcher = f
}

// TraceValidationResult contains the result of trace validation.
type TraceValidationResult struct {
	Allowed       bool           // Whether the transaction trace is allowed
	Reason        string         // User-facing reason for denial (single opaque string to prevent enumeration)
	DenialKind    DenialKind     // Structured denial classification for audit/logging — never reaches the response body
	DeniedTarget  string         // Address that caused denial (if any) — never reaches the response body
	CreateTargets []CreateTarget // Contract addresses created during trace execution
}

// DenialKind classifies why a trace was denied so audit logs and SIEM events
// can distinguish "touched another org" from "touched no org" from
// "tried to deploy without the claim". The user-facing Reason stays opaque
// (ErrContractAccessDenied) per the contract-enumeration rule in access.go;
// this field is consumed by slog.Debug + access_logs + metrics labels only.
type DenialKind string

const (
	DenialKindNone                DenialKind = ""
	DenialKindForeignOrg          DenialKind = "foreign_org"                    // target is owned by an org the caller is not in
	DenialKindUnregistered        DenialKind = "unregistered"                   // target is not in the Contract registry at all
	DenialKindDeployClaim         DenialKind = "deploy_claim_missing"           // trace contains CREATE/CREATE2 but caller lacks deploy
	DenialKindCreateForeign       DenialKind = "create_foreign_org"             // CREATE/CREATE2 collides with an address registered to another org
	DenialKindDelegateSharedInfra DenialKind = "delegatecall_shared_infra"      // M6: DELEGATECALL into shared infrastructure
	DenialKindCodehashMismatch    DenialKind = "shared_infra_codehash_mismatch" // M5: shared_infrastructure bytecode rotated since attestation
	DenialKindIntraOrgUngranted   DenialKind = "intra_org_ungranted"            // RD-1053: same-org target the caller has no contract grant for (intra-org scoping on)
)

// TraceOption configures optional behaviour of ValidateTrace. It exists so
// the many call sites that only need cross-org isolation keep the original
// signature, while the read/send paths can opt into intra-org grant scoping
// (RD-1053) without threading extra positional args everywhere.
type TraceOption func(*traceOptions)

type traceOptions struct {
	intraOrgGrantScoping bool
	grantedContracts     map[string]bool
}

// WithIntraOrgGrantScoping enables the RD-1053 intra-org pass: an internal
// frame into a contract owned by one of the caller's orgs is allowed only if
// that contract's lowercased address is present in grantedContracts — the
// union of the caller's resolved contract grants across their orgs, plus the
// already-authorized top-level target. Cross-org and unregistered denials
// (Rules 2d/2e) are unaffected; this only narrows the same-org "allow".
// When this option is not supplied, ValidateTrace gates internal frames on
// org ownership alone (pre-RD-1053 behaviour).
//
// grantedContracts mirrors the entry-point CheckAccess contract-access
// decision (explicit grants + org-admin materialization + deployer
// auto-grant rows). In-flight deployments (precomputed CREATE/CREATE2/CREATE3
// addresses that are pre-registered but not yet mined, hence grant-less) are
// handled separately: a deploy-claim caller is allowed through via the
// IsAddressPreregistered fallback in ValidateTrace, mirroring how the
// entry-point treats pre-registered addresses. The only residual narrowing is
// the transient post-mine-but-pre-grant window (the entry-point's
// deployer-by-address fallback), which RD-735's deploy-time grant creation
// makes effectively empty.
func WithIntraOrgGrantScoping(grantedContracts map[string]bool) TraceOption {
	return func(o *traceOptions) {
		o.intraOrgGrantScoping = true
		o.grantedContracts = grantedContracts
	}
}

// CreateTarget represents a contract address created during trace execution.
type CreateTarget struct {
	Type    string // "CREATE" or "CREATE2"
	Address string // Created contract address (from trace)
	From    string // The contract that executed the CREATE/CREATE2
}

// SharedInfrastructure represents a globally accessible contract (e.g., Uniswap router).
// These contracts are allowed for all organizations and do not require org ownership.
//
// Codehash (M5, security audit follow-up to RD-915): the keccak256 of
// the contract's bytecode at attestation time. When set, the trace
// validator fetches eth_getCode at validation time, hashes it, and
// rejects the skip if the hash drifts — a rotated bytecode behind a
// stable address would otherwise let an operator-misconfigured proxy
// silently bypass the tracer. Optional for legacy rows; admins should
// attest a codehash on every new tag and rotate the entry on
// bytecode change. Tag / untag operations are audit-logged.
//
// Format: lowercase 0x-prefixed 32-byte hex string. Nil/empty disables
// the check for backward compatibility.
type SharedInfrastructure struct {
	Address     string    `json:"address"`            // lowercase 0x-prefixed address
	Name        string    `json:"name"`               // Human-readable name (e.g., "Uniswap V3 Router")
	Description string    `json:"description"`        // Description of the contract
	Codehash    *string   `json:"codehash,omitempty"` // M5: optional codehash pin
	CreatedAt   time.Time `json:"created_at"`
}

// NewTraceValidator creates a new trace validator.
func NewTraceValidator(store TraceValidatorStore) *TraceValidator {
	return &TraceValidator{
		store:          store,
		precompileFunc: precompile.IsPrecompileAddress,
	}
}

// ValidateTrace checks if all addresses in a transaction trace are allowed
// for the user's organizations.
//
// The validation follows this order:
//  1. If trace has CREATE or CREATE2 and user lacks deploy claim, deny
//  2. If user has deploy claim, validate created addresses aren't owned by another org
//  3. For each CallTarget:
//     a. Filter precompiles (0x01-0x09): always allow
//     b. Check if target is shared infrastructure: always allow
//     c. Check if target is owned by any of user's orgs: allow if member —
//     but when WithIntraOrgGrantScoping is set (RD-1053), additionally
//     require a contract grant for that same-org target, else DENY
//     d. If not owned by user's org, check if owned by another org: DENY
//     e. If unregistered (not owned by any org): DENY (private by default)
func (v *TraceValidator) ValidateTrace(
	ctx context.Context,
	userOrgIDs map[string]bool,
	trace *tracer.TraceResult,
	userHasDeploy bool,
	opts ...TraceOption,
) (*TraceValidationResult, error) {
	var o traceOptions
	for _, fn := range opts {
		fn(&o)
	}
	if trace == nil {
		return &TraceValidationResult{
			Allowed: true,
			Reason:  "",
		}, nil
	}

	// Rule 1: Handle runtime CREATE/CREATE2 operations
	var createTargets []CreateTarget
	if trace.HasCreate || trace.HasCreate2 {
		if !userHasDeploy {
			return &TraceValidationResult{
				Allowed:    false,
				Reason:     "runtime contract creation requires deploy claim",
				DenialKind: DenialKindDeployClaim,
			}, nil
		}

		// User has deploy claim — collect and validate CREATE/CREATE2 targets
		for _, target := range trace.CallTargets {
			if target.Type != "CREATE" && target.Type != "CREATE2" {
				continue
			}
			addr := normalizeTraceAddr(target.To)
			if addr == "" || addr == "0x" || addr == "0x0000000000000000000000000000000000000000" {
				continue
			}

			// Ensure the created address isn't already owned by another org
			ownerOrgID, err := v.store.GetContractOwnerOrgID(ctx, addr)
			if err != nil {
				return nil, fmt.Errorf("failed to get contract owner for created address: %w", err)
			}
			if ownerOrgID != "" && !userOrgIDs[ownerOrgID] {
				slog.Debug("runtime create denied: address owned by another org", "address", addr, "user_orgs", userOrgIDs)
				return &TraceValidationResult{
					Allowed:      false,
					Reason:       "contract access denied",
					DenialKind:   DenialKindCreateForeign,
					DeniedTarget: addr,
				}, nil
			}

			createTargets = append(createTargets, CreateTarget{
				Type:    target.Type,
				Address: addr,
				From:    normalizeTraceAddr(target.From),
			})
		}
	}

	// Rule 2: Validate each call target
	for _, target := range trace.CallTargets {
		// Skip CREATE/CREATE2 targets — handled above
		if target.Type == "CREATE" || target.Type == "CREATE2" {
			continue
		}

		// Normalize the target address
		addr := normalizeTraceAddr(target.To)

		// Skip empty addresses
		if addr == "" || addr == "0x" || addr == "0x0000000000000000000000000000000000000000" {
			continue
		}

		// Rule 2a: Precompiles are always allowed
		if v.precompileFunc(addr) {
			continue
		}

		// Rule 2b: Check if target is shared infrastructure.
		//
		// M5/M6 (security audit follow-up to RD-915):
		// - M6: DELEGATECALL into shared infrastructure is denied even
		//   when the address is tagged. DELEGATECALL runs the callee's
		//   bytecode against the CALLER's storage, so a tagged contract
		//   whose bytecode is rotated could exfiltrate caller storage
		//   or impersonate same-org calls. The skip is for CALL +
		//   STATICCALL only.
		// - M5: when the row has a codehash, fetch the current
		//   bytecode hash and compare. Mismatch → treat as untagged
		//   (the contract's code rotated since attestation; the trust
		//   decision the operator made no longer applies). This guards
		//   against a proxy whose implementation slot is rewritten
		//   after the address is tagged.
		sharedRow, err := v.store.GetSharedInfrastructure(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to check shared infrastructure: %w", err)
		}
		if sharedRow != nil {
			if target.Type == "DELEGATECALL" || target.Type == "CALLCODE" {
				slog.Debug("trace denied: context-sharing call into shared infrastructure",
					"call_type", target.Type,
					"address", addr)
				return &TraceValidationResult{
					Allowed:      false,
					Reason:       ErrContractAccessDenied,
					DenialKind:   DenialKindDelegateSharedInfra,
					DeniedTarget: addr,
				}, nil
			}
			// Codehash-pin: if the row carries an attested hash AND
			// the validator has a code fetcher wired, verify.
			if sharedRow.Codehash != nil && *sharedRow.Codehash != "" && v.codeFetcher != nil {
				currentHash, err := v.codeFetcher.GetCodeHash(ctx, addr)
				if err != nil {
					slog.Warn("trace: shared_infra codehash fetch failed; failing closed",
						"address", addr, "err", err)
					// Fail closed: cannot verify, so we don't trust
					// the tag. Fall through to the normal ownership
					// rules (which will likely deny as unregistered).
				} else if strings.EqualFold(currentHash, *sharedRow.Codehash) {
					// Hash matches the attested value → keep the
					// skip (CALL / STATICCALL only — DELEGATECALL
					// branch above already returned).
					continue
				} else {
					slog.Warn("trace: shared_infra codehash mismatch — treating as untagged",
						"address", addr,
						"attested", *sharedRow.Codehash,
						"observed", currentHash)
					return &TraceValidationResult{
						Allowed:      false,
						Reason:       ErrContractAccessDenied,
						DenialKind:   DenialKindCodehashMismatch,
						DeniedTarget: addr,
					}, nil
				}
			} else {
				// No codehash pin OR no fetcher wired → legacy skip.
				continue
			}
		}

		// Rule 2c: Check if target is owned by any of the user's orgs
		isOwnedByUserOrg := false
		for orgID := range userOrgIDs {
			owned, err := v.store.IsAddressOwnedByOrg(ctx, addr, orgID)
			if err != nil {
				return nil, fmt.Errorf("failed to check address ownership for org %s: %w", orgID, err)
			}
			if owned {
				isOwnedByUserOrg = true
				break
			}
		}
		if isOwnedByUserOrg {
			// Rule 2c' (RD-1053): intra-org contract-grant scoping. By
			// default org ownership is sufficient — the org is the
			// isolation boundary. When the operator opts in, a same-org
			// frame must ALSO be a contract the caller has a grant for,
			// mirroring the grant-aware entry-point CheckAccess. This
			// closes the transitive-reach gap where a user reaches a
			// same-org-but-ungranted contract through an internal call
			// rather than as the direct `to`. Cross-org isolation (2d/2e)
			// is independent of this and always enforced.
			if o.intraOrgGrantScoping && !o.grantedContracts[addr] {
				// Pre-registration fallback: an in-flight deployment
				// (precomputed CREATE/CREATE2/CREATE3 address) is owned by
				// the org but has no grant row until it is mined and
				// reconciled (RD-735). The grant-aware entry-point
				// CheckAccess already treats pre-registered addresses as
				// reachable for deploy-claim holders; mirror that here so
				// strict mode doesn't block a multi-contract deploy that
				// touches a not-yet-mined sibling. Only consulted on the
				// rare deny path, and only for deploy-claim callers (the
				// address has no code yet, so a non-deployer reaching it is
				// both exotic and safe to deny — fail-closed).
				if userHasDeploy {
					prereg, err := v.isPreregisteredForAnyOrg(ctx, addr, userOrgIDs)
					if err != nil {
						return nil, fmt.Errorf("failed to check preregistration: %w", err)
					}
					if prereg {
						continue
					}
				}
				slog.Debug("trace denied: same-org target not granted to caller (intra-org scoping)", "address", addr)
				return &TraceValidationResult{
					Allowed:      false,
					Reason:       ErrContractAccessDenied,
					DenialKind:   DenialKindIntraOrgUngranted,
					DeniedTarget: addr,
				}, nil
			}
			continue
		}

		// Rule 2d: Check if owned by another org (not the user's) -> DENY
		ownerOrgID, err := v.store.GetContractOwnerOrgID(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("failed to get contract owner: %w", err)
		}
		if ownerOrgID != "" {
			slog.Debug("trace denied: call target owned by another org", "address", addr)
			return &TraceValidationResult{
				Allowed:      false,
				Reason:       ErrContractAccessDenied,
				DenialKind:   DenialKindForeignOrg,
				DeniedTarget: addr,
			}, nil
		}

		// Rule 2e: Unregistered address — deny. All contracts are private by
		// default; only precompiles (handled in Rule 2a), shared infrastructure
		// (Rule 2b), and org-owned contracts (Rule 2c) are allowed.
		slog.Debug("trace denied: unregistered address (private by default)", "address", addr)
		return &TraceValidationResult{
			Allowed:      false,
			Reason:       ErrContractAccessDenied,
			DenialKind:   DenialKindUnregistered,
			DeniedTarget: addr,
		}, nil
	}

	return &TraceValidationResult{
		Allowed:       true,
		CreateTargets: createTargets,
	}, nil
}

// isPreregisteredForAnyOrg reports whether addr is a pending (precomputed,
// not-yet-mined) deployment for any of the caller's orgs. Used by the RD-1053
// intra-org grant pass to let an in-flight CREATE/CREATE2/CREATE3 sibling
// through before its grant row exists.
func (v *TraceValidator) isPreregisteredForAnyOrg(ctx context.Context, addr string, userOrgIDs map[string]bool) (bool, error) {
	for orgID := range userOrgIDs {
		prereg, err := v.store.IsAddressPreregistered(ctx, orgID, addr)
		if err != nil {
			return false, err
		}
		if prereg {
			return true, nil
		}
	}
	return false, nil
}

// normalizeTraceAddr normalizes an address to lowercase with 0x prefix.
// This has a unique name to avoid conflicts with other normalize functions in the package.
func normalizeTraceAddr(addr string) string {
	addr = strings.TrimSpace(strings.ToLower(addr))
	if addr == "" {
		return ""
	}
	if !strings.HasPrefix(addr, "0x") {
		addr = "0x" + addr
	}
	return addr
}
