package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"privacy-proxy/internal/nodepolicy"
	"privacy-proxy/internal/policydsl"
)

// ExportNodePolicySnapshot reads the watermark first under repeatable-read so
// every following row belongs to that same committed database generation.
func (d *DB) ExportNodePolicySnapshot(ctx context.Context, network nodepolicy.Network, at time.Time, lifetime time.Duration) (nodepolicy.Snapshot, error) {
	var out nodepolicy.Snapshot
	if lifetime <= 0 || lifetime > nodepolicy.MaxMessageLifetime {
		return out, fmt.Errorf("invalid fact lifetime")
	}
	tx, err := d.conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	out.Header = nodepolicy.Header{Network: network, IssuedAt: at.Unix(), ExpiresAt: at.Add(lifetime).Unix()}
	if err := tx.QueryRowContext(ctx, `SELECT version FROM node_policy_clock WHERE singleton`).Scan(&out.Version); err != nil {
		return out, err
	}
	if err := exportNodeFacts(ctx, tx, &out); err != nil {
		return nodepolicy.Snapshot{}, err
	}
	if _, err := nodepolicy.Pin(out); err != nil {
		return nodepolicy.Snapshot{}, fmt.Errorf("invalid exported facts: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nodepolicy.Snapshot{}, err
	}
	return out, nil
}

func exportNodeFacts(ctx context.Context, q DBTX, out *nodepolicy.Snapshot) error {
	principals := map[string]int{}
	err := nodePolicyRows(ctx, q, `SELECT u.id::text,u.kyc,(u.banned OR COALESCE(p.banned,false))
        FROM users u LEFT JOIN access_policies p ON p.external_id=u.external_id ORDER BY u.id`, func(r *sql.Rows) error {
		var p nodepolicy.Principal
		if err := r.Scan(&p.ID, &p.KYC, &p.Banned); err != nil {
			return err
		}
		principals[p.ID] = len(out.Principals)
		out.Principals = append(out.Principals, p)
		return nil
	})
	if err != nil {
		return err
	}
	err = nodePolicyRows(ctx, q, `SELECT DISTINCT u.id::text,lower(e.eth_address)
        FROM eth_address_links e JOIN users u ON u.external_id=e.did
        WHERE e.revoked=false ORDER BY 1,2`, func(r *sql.Rows) error {
		var id, address string
		if err := r.Scan(&id, &address); err != nil {
			return err
		}
		i, ok := principals[id]
		if !ok {
			return fmt.Errorf("linked principal missing from snapshot")
		}
		out.Principals[i].LinkedAddresses = append(out.Principals[i].LinkedAddresses, address)
		return nil
	})
	if err != nil {
		return err
	}
	err = nodePolicyRows(ctx, q, `SELECT user_id::text,group_id::text,expires_at FROM user_memberships ORDER BY user_id,group_id`, func(r *sql.Rows) error {
		var id string
		var m nodepolicy.Membership
		var expiry sql.NullTime
		if err := r.Scan(&id, &m.GroupID, &expiry); err != nil {
			return err
		}
		if expiry.Valid {
			m.ExpiresAt = expiry.Time.Unix()
		}
		i, ok := principals[id]
		if !ok {
			return fmt.Errorf("membership principal missing from snapshot")
		}
		out.Principals[i].Memberships = append(out.Principals[i].Memberships, m)
		return nil
	})
	if err != nil {
		return err
	}
	groups := map[string]int{}
	err = nodePolicyRows(ctx, q, `SELECT g.id::text,g.org_id::text,g.is_org_admin,to_json(COALESCE(a.claims,'{}'::text[]))
        FROM groups g LEFT JOIN group_access a ON a.group_id=g.id ORDER BY g.id`, func(r *sql.Rows) error {
		var g nodepolicy.Group
		var raw []byte
		if err := r.Scan(&g.ID, &g.OrgID, &g.OrgAdmin, &raw); err != nil {
			return err
		}
		claims, err := nodeClaimMask(raw)
		if err != nil {
			return err
		}
		g.Claims = claims
		groups[g.ID] = len(out.Groups)
		out.Groups = append(out.Groups, g)
		return nil
	})
	if err != nil {
		return err
	}
	err = nodePolicyRows(ctx, q, `SELECT cg.group_id::text,lower(c.address)
        FROM contract_grants cg JOIN contracts c ON c.id=cg.contract_id ORDER BY cg.group_id,c.address`, func(r *sql.Rows) error {
		var id string
		var grant nodepolicy.ContractClaim
		if err := r.Scan(&id, &grant.Address); err != nil {
			return err
		}
		i, ok := groups[id]
		if !ok {
			return fmt.Errorf("claim group missing from snapshot")
		}
		// Match rbac.Resolver.groupPerms: group_access claims apply only
		// to that group's granted targets. contract_grants.claims is legacy.
		grant.Claims = out.Groups[i].Claims
		out.Groups[i].ContractClaims = append(out.Groups[i].ContractClaims, grant)
		return nil
	})
	if err != nil {
		return err
	}
	err = nodePolicyRows(ctx, q, `SELECT lower(COALESCE(c.address,s.address)),COALESCE(c.org_id::text,''),s.address IS NOT NULL,lower(COALESCE(s.codehash,'')),COALESCE(c.deployed_by_user_id::text,'')
        FROM contracts c FULL JOIN shared_infrastructure s ON lower(c.address)=lower(s.address) ORDER BY 1`, func(r *sql.Rows) error {
		var c nodepolicy.Contract
		if err := r.Scan(&c.Address, &c.OrgID, &c.SharedInfrastructure, &c.CodeHash, &c.DeployerPrincipalID); err != nil {
			return err
		}
		out.Contracts = append(out.Contracts, c)
		return nil
	})
	if err != nil {
		return err
	}
	// A registered owner always wins over stale preregistration. Conflicting
	// pending owners fail the export instead of selecting one tenant by order.
	err = nodePolicyRows(ctx, q, `SELECT lower(p.address),min(p.org_id::text),count(DISTINCT p.org_id),bool_or(s.address IS NOT NULL)
        FROM preregistered_addresses p LEFT JOIN shared_infrastructure s ON lower(s.address)=lower(p.address)
        WHERE NOT EXISTS (SELECT 1 FROM contracts c WHERE lower(c.address)=lower(p.address))
        GROUP BY lower(p.address) ORDER BY 1`, func(r *sql.Rows) error {
		c := nodepolicy.Contract{Pending: true}
		var owners int
		var shared bool
		if err := r.Scan(&c.Address, &c.OrgID, &owners, &shared); err != nil {
			return err
		}
		if owners != 1 || shared {
			return fmt.Errorf("ambiguous pending contract ownership")
		}
		out.Contracts = append(out.Contracts, c)
		return nil
	})
	if err != nil {
		return err
	}
	err = nodePolicyRows(ctx, q, `SELECT org_id::text,revision,policy_digest,runtime_digest,runtime_bytecode,artifact_set
        FROM execution_policy_revisions WHERE status='active' ORDER BY org_id`, func(r *sql.Rows) error {
		var p nodepolicy.PolicyArtifact
		var raw []byte
		if err := r.Scan(&p.OrgID, &p.Revision, &p.PolicyDigest, &p.RuntimeDigest, &p.Bytecode, &raw); err != nil {
			return err
		}
		if raw == nil {
			out.Policies = append(out.Policies, p)
		} else {
			set, err := policydsl.DecodeArtifactSet(raw)
			if err != nil {
				return err
			}
			if set.PolicyDigest != p.PolicyDigest {
				return fmt.Errorf("execution artifact document mismatch")
			}
			groups := make([]string, 0, len(set.Groups))
			for group := range set.Groups {
				groups = append(groups, group)
			}
			sort.Strings(groups)
			for _, group := range groups {
				a := set.Groups[group]
				out.Policies = append(out.Policies, nodepolicy.PolicyArtifact{OrgID: p.OrgID, GroupID: group, Revision: p.Revision, PolicyDigest: a.PolicyDigest, RuntimeDigest: a.RuntimeDigest, Bytecode: a.RuntimeBytecode})
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return nodePolicyRows(ctx, q, `SELECT COALESCE(org_id::text,''),lower(address) FROM sanctioned_addresses ORDER BY org_id NULLS FIRST,address`, func(r *sql.Rows) error {
		var s nodepolicy.Sanction
		if err := r.Scan(&s.OrgID, &s.Address); err != nil {
			return err
		}
		out.Sanctions = append(out.Sanctions, s)
		return nil
	})
}

func nodePolicyRows(ctx context.Context, q DBTX, query string, scan func(*sql.Rows) error) error {
	rows, err := q.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func nodeClaimMask(raw []byte) (uint8, error) {
	var claims []string
	if err := json.Unmarshal(raw, &claims); err != nil {
		return 0, err
	}
	var mask uint8
	for _, claim := range claims {
		switch claim {
		case "admin":
			mask |= nodepolicy.ClaimAdmin | nodepolicy.ClaimDeploy | nodepolicy.ClaimUpgrade
		case "deploy":
			mask |= nodepolicy.ClaimDeploy
		case "upgrade":
			mask |= nodepolicy.ClaimUpgrade
		default:
			return 0, fmt.Errorf("unsupported operational claim in node facts")
		}
	}
	return mask, nil
}
