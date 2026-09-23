package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/rbac"
)

type ConfigurationActor struct {
	UserID        string
	ExternalID    string
	IPAddress     string
	PrincipalKind string
	CIApproval    *configuration.CIApproval
}

type ConfigurationRevision struct {
	ID                   string
	Scope                configuration.Scope
	Kind                 configuration.Kind
	Revision             int64
	BaseRevision         int64
	Source               string
	Digest               string
	Dependencies         map[configuration.Kind]string
	Status               string
	CreatedBy            string
	CreatedPrincipalKind string
	CreatedAt            time.Time
	ActivatedBy          *string
	ActivatedAt          *time.Time
	Artifact             json.RawMessage
}

type ConfigurationContext struct {
	Active             *ConfigurationRevision
	Source             *configuration.Document
	Groups             configuration.GroupSnapshot
	Registry           configuration.RegistrySnapshot
	LegacyExecution    []configuration.LegacyExecutionGrant
	Compliance         configuration.ComplianceSnapshot
	Approvers          *configuration.ApproversSpec
	Platform           configuration.PlatformSnapshot
	Execution          *configuration.ExecutionSpec
	ExecutionMigration *configuration.ExecutionMigrationReview
}

type ConfigurationActivation struct {
	Scope           configuration.Scope
	Actor           ConfigurationActor
	Candidates      []*ConfigurationRevision
	Groups          configuration.GroupSnapshot
	GroupDiff       *configuration.GroupDiff
	Registry        configuration.RegistrySnapshot
	RegistryDiff    *configuration.RegistryDiff
	LegacyExecution []configuration.LegacyExecutionGrant
	Compliance      configuration.ComplianceSnapshot
	ComplianceDiff  *configuration.ComplianceDiff
	Approvers       *configuration.ApproversSpec
	ApproversDiff   *configuration.ApproversSpec
	Platform        configuration.PlatformSnapshot
	PlatformDiff    *configuration.PlatformDiff
	ExecutionDiff   *configuration.ExecutionDiff
}

// ConfigurationAuthorizer runs with current state locked, before projection.
// The application must check current author and activator authority, including
// the platform-only gate for changes to full org-admin groups.
type ConfigurationAuthorizer func(context.Context, *Tx, ConfigurationActivation) error

func (d *DB) SubmitConfigurationRevision(ctx context.Context, source []byte, actor ConfigurationActor) (*ConfigurationRevision, error) {
	document, err := configuration.Parse(source)
	if err != nil {
		return nil, err
	}
	if configuration.RequiresHumanAuthor(document.Kind) && actor.PrincipalKind != "human" {
		return nil, ErrConfigurationForbidden
	}

	_, digest, err := document.Canonical()
	if err != nil {
		return nil, err
	}
	var revision *ConfigurationRevision
	err = d.WithTx(ctx, func(tx *Tx) error {
		if err := lockConfigurationScope(ctx, tx.tx, document.Scope); err != nil {
			return err
		}
		if err := validateConfigurationActor(ctx, tx.tx, actor, true); err != nil {
			return err
		}
		var latest, active int64
		if err := tx.tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision),0), COALESCE(MAX(revision) FILTER(WHERE status='active'),0)
            FROM configuration_revisions WHERE scope_kind=$1 AND org_id IS NOT DISTINCT FROM $2::uuid AND kind=$3`, document.Scope.Kind, configurationOrgID(document.Scope), document.Kind).Scan(&latest, &active); err != nil {
			return err
		}
		if document.BaseRevision != active {
			return ErrPolicyStaleBase
		}
		dependencies, err := json.Marshal(document.Dependencies)
		if err != nil {
			return err
		}
		var artifact []byte
		if document.Kind == configuration.ExecutionRules {
			artifact, err = compileConfigurationExecution(ctx, tx.tx, document)
			if err != nil {
				return err
			}
		}
		revision, err = scanConfigurationRevision(tx.tx.QueryRowContext(ctx, `INSERT INTO configuration_revisions
            (scope_kind,org_id,kind,revision,base_revision,source,digest,dependencies,status,created_by,compiled_artifact,created_principal_kind)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,'draft',$9,$10,$11) RETURNING `+configurationRevisionColumns,
			document.Scope.Kind, configurationOrgID(document.Scope), document.Kind, latest+1, active, string(source), digest, dependencies, actor.UserID, artifact, actor.PrincipalKind).Scan)
		return err
	})
	return revision, err
}
func (d *DB) GetConfigurationContext(ctx context.Context, scope configuration.Scope, kind configuration.Kind) (*ConfigurationContext, error) {
	if kind != configuration.Groups && kind != configuration.ContractRegistry && kind != configuration.Compliance && kind != configuration.Approvers && kind != configuration.Platform && kind != configuration.ExecutionRules {
		return nil, ConfigurationConflict("context export for kind %s is not available yet", kind)
	}
	// An editing export must describe one database snapshot, including the
	// active base and operational membership counts shown with deletions.
	read, err := d.conn.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer read.Rollback()
	active, err := activeConfigurationRevision(ctx, read, scope, kind)
	if err != nil {
		return nil, err
	}
	result := &ConfigurationContext{Active: active}
	var spec configuration.Spec
	if kind == configuration.Groups {
		result.Groups, err = configurationGroups(ctx, read, scope, active, false)
		if err != nil {
			return nil, err
		}
		groups := []configuration.Group{}
		for _, state := range result.Groups.Groups {
			groups = append(groups, state.Group)
		}
		spec = configuration.GroupsSpec{Groups: groups}
	} else if kind == configuration.ContractRegistry {
		result.Registry, result.LegacyExecution, err = configurationRegistry(ctx, read, scope, active, false)
		if err != nil {
			return nil, err
		}
		contracts := []configuration.Contract{}
		for _, state := range result.Registry.Contracts {
			contracts = append(contracts, state.Contract)
		}
		spec = configuration.RegistrySpec{Contracts: contracts}
	} else if kind == configuration.Compliance {
		result.Compliance, err = configurationCompliance(ctx, read, scope, active, false)
		if err != nil {
			return nil, err
		}
		spec = result.Compliance.Spec
	} else if kind == configuration.Approvers {
		result.Approvers, err = configurationApprovers(ctx, read, scope)
		if err != nil {
			return nil, err
		}
		if result.Approvers == nil {
			result.Approvers = &configuration.ApproversSpec{GroupIDs: []string{}, TrustedCI: []configuration.TrustedCI{}}
			groups, err := configurationGroups(ctx, read, scope, nil, false)
			if err != nil {
				return nil, err
			}
			for _, state := range groups.Groups {
				if state.Group.IsOrgAdmin {
					result.Approvers.GroupIDs = append(result.Approvers.GroupIDs, state.Group.ID)
				}
			}
		}
		spec = *result.Approvers
	}
	if kind == configuration.Platform {
		result.Platform, err = configurationPlatform(ctx, read, active, false)
		if err != nil {
			return nil, err
		}
		spec = result.Platform.Spec
	}

	if kind == configuration.ExecutionRules {
		spec, err = configurationExecutionContext(ctx, read, scope, active)
		if err != nil {
			return nil, err
		}
		execution := spec.(configuration.ExecutionSpec)
		result.Execution = &execution
		result.ExecutionMigration, err = configurationExecutionMigration(ctx, read, scope)
		if err != nil {
			return nil, err
		}
	}

	dependencies := map[configuration.Kind]string{}
	if active != nil {
		for kind, digest := range active.Dependencies {
			dependencies[kind] = digest
		}
	}
	if err := read.Commit(); err != nil {
		return nil, err
	}
	base := int64(0)
	if active != nil {
		base = active.Revision
	}
	result.Source = &configuration.Document{APIVersion: configuration.APIVersion, Kind: kind, Scope: scope, BaseRevision: base,
		Dependencies: dependencies, Deletions: []configuration.Deletion{}, Spec: spec}
	return result, nil
}
func (d *DB) ActivateConfigurationRevisions(ctx context.Context, scope configuration.Scope, ids []string, actor ConfigurationActor, authorize ConfigurationAuthorizer) ([]*ConfigurationRevision, error) {
	if authorize == nil {
		return nil, ConfigurationConflict("configuration authorization callback is required")
	}
	chain := d.getRBACAuditChain()
	if chain == nil {
		return nil, ConfigurationConflict("configuration activation requires the RBAC audit chain")
	}
	var activated []*ConfigurationRevision
	_, err := chain.Append(func(_ string) (string, func(string) error, error) {
		// Prepare immutable audit content before hashing. It is checked again
		// under database locks inside write; a changed review cannot be applied.
		prepared, err := prepareConfigurationActivation(ctx, d.conn, scope, ids, actor, false, true)
		if err != nil {
			return "", nil, err
		}
		preparedJSON, err := json.Marshal(prepared)
		if err != nil {
			return "", nil, err
		}
		var auditID int64
		if err := d.conn.QueryRowContext(ctx, `SELECT nextval('rbac_audit_log_id_seq')`).Scan(&auditID); err != nil {
			return "", nil, err
		}
		createdAt := time.Now().UTC().Truncate(time.Microsecond)
		auditRevisions := make([]*ConfigurationRevision, 0, len(prepared.Candidates))
		for _, candidate := range prepared.Candidates {
			approved := *candidate
			approved.Status, approved.ActivatedBy, approved.ActivatedAt = PolicyStatusActive, &actor.UserID, &createdAt
			auditRevisions = append(auditRevisions, &approved)
		}
		entry := &rbac.AuditLogEntry{ActorID: &actor.UserID, ActorExternalID: actor.ExternalID, IPAddress: actor.IPAddress,
			Action: rbac.AuditActionUpdate, ResourceType: "configuration_revision", ResourceID: &prepared.Candidates[0].ID,
			ResourceName: "configuration activation", OrgID: configurationAuditOrgID(scope),
			OldValue: map[string]any{"groups": prepared.Groups, "registry": prepared.Registry, "legacyExecution": prepared.LegacyExecution, "compliance": prepared.Compliance, "approvers": prepared.Approvers, "platform": prepared.Platform}, NewValue: map[string]any{"revisions": auditRevisions, "groups": prepared.GroupDiff, "registry": prepared.RegistryDiff, "compliance": prepared.ComplianceDiff, "approvers": prepared.ApproversDiff, "platform": prepared.PlatformDiff, "execution": prepared.ExecutionDiff, "ciApproval": actor.CIApproval}}
		oldValue, err := json.Marshal(entry.OldValue)
		if err != nil {
			return "", nil, err
		}
		newValue, err := json.Marshal(entry.NewValue)
		if err != nil {
			return "", nil, err
		}
		content := buildRBACAuditContent(auditID, createdAt, entry, oldValue, newValue)
		return content, func(hash string) error {
			return d.WithTx(ctx, func(tx *Tx) error {
				if err := lockConfigurationScope(ctx, tx.tx, scope); err != nil {
					return err
				}
				current, err := prepareConfigurationActivation(ctx, tx.tx, scope, ids, actor, true, true)
				if err != nil {
					return err
				}
				currentJSON, err := json.Marshal(current)
				if err != nil {
					return err
				}
				if string(currentJSON) != string(preparedJSON) {
					return ConfigurationConflict("configuration review changed; reload context and review again")
				}
				if err := authorize(ctx, tx, current); err != nil {
					return err
				}
				if err := projectConfiguration(ctx, tx, current); err != nil {
					return err
				}
				activated = nil
				for _, candidate := range current.Candidates {
					if _, err := tx.tx.ExecContext(ctx, `UPDATE configuration_revisions SET status='superseded'
                        WHERE scope_kind=$1 AND org_id IS NOT DISTINCT FROM $2::uuid AND kind=$3 AND status='active'`, scope.Kind, configurationOrgID(scope), candidate.Kind); err != nil {
						return err
					}
					revision, err := scanConfigurationRevision(tx.tx.QueryRowContext(ctx, `UPDATE configuration_revisions SET status='active',activated_by=$2,activated_at=$3 WHERE id=$1 RETURNING `+configurationRevisionColumns, candidate.ID, actor.UserID, createdAt).Scan)
					if err != nil {
						return err
					}
					activated = append(activated, revision)
				}
				_, err = tx.tx.ExecContext(ctx, `INSERT INTO rbac_audit_log
                    (id,actor_id,actor_external_id,action,resource_type,resource_id,resource_name,org_id,old_value,new_value,ip_address,created_at,entry_hash,hash_format_version)
                    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,1)`, auditID, entry.ActorID, entry.ActorExternalID, entry.Action, entry.ResourceType,
					entry.ResourceID, entry.ResourceName, entry.OrgID, oldValue, newValue, entry.IPAddress, createdAt, hash)
				return err
			})
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return activated, nil
}

const configurationRevisionColumns = `id,scope_kind,org_id,kind,revision,base_revision,source,digest,dependencies,status,created_by,created_at,activated_by,activated_at,compiled_artifact,created_principal_kind`

func scanConfigurationRevision(scan func(...any) error) (*ConfigurationRevision, error) {
	var result ConfigurationRevision
	var orgID *string
	var dependencies, artifact []byte
	if err := scan(&result.ID, &result.Scope.Kind, &orgID, &result.Kind, &result.Revision, &result.BaseRevision, &result.Source, &result.Digest, &dependencies,
		&result.Status, &result.CreatedBy, &result.CreatedAt, &result.ActivatedBy, &result.ActivatedAt, &artifact, &result.CreatedPrincipalKind); err != nil {
		return nil, err
	}
	if orgID != nil {
		result.Scope.ID = *orgID
	}
	result.Artifact = artifact
	if err := json.Unmarshal(dependencies, &result.Dependencies); err != nil {
		return nil, err
	}
	return &result, nil
}
func configurationOrgID(scope configuration.Scope) any {
	if scope.Kind == "platform" {
		return nil
	}
	return scope.ID
}
func lockConfigurationScope(ctx context.Context, q DBTX, scope configuration.Scope) error {
	if scope.Kind == "platform" && scope.ID == "" {
		_, err := q.ExecContext(ctx, `SELECT pg_advisory_xact_lock(730074)`)
		return err
	}
	if scope.Kind != "organization" {
		return ConfigurationConflict("invalid configuration scope")
	}
	id, err := uuid.Parse(scope.ID)
	if err != nil || id == uuid.Nil || id.String() != scope.ID {
		return ConfigurationConflict("invalid organization scope")
	}
	var locked string
	if err := q.QueryRowContext(ctx, `SELECT id FROM organizations WHERE id=$1 FOR UPDATE`, scope.ID).Scan(&locked); err != nil {
		return fmt.Errorf("configuration scope not found: %w", err)
	}
	return nil
}
func validateConfigurationActor(ctx context.Context, q DBTX, actor ConfigurationActor, lock bool) error {
	if actor.UserID == "" || strings.TrimSpace(actor.ExternalID) == "" {
		return ErrPolicyActorRequired
	}
	id, err := uuid.Parse(actor.UserID)
	if err != nil || id == uuid.Nil || id.String() != actor.UserID {
		return ErrPolicyActorRequired
	}
	query := `SELECT external_id,banned FROM users WHERE id=$1`
	if lock {
		query += ` FOR SHARE`
	}
	var external string
	var banned bool
	if err := q.QueryRowContext(ctx, query, actor.UserID).Scan(&external, &banned); err != nil {
		return ErrPolicyActorRequired
	}
	if banned || actor.ExternalID != external {
		return ConfigurationConflict("configuration actor is not authorized")
	}
	return nil
}
func activeConfigurationRevision(ctx context.Context, q DBTX, scope configuration.Scope, kind configuration.Kind) (*ConfigurationRevision, error) {
	revision, err := scanConfigurationRevision(q.QueryRowContext(ctx, `SELECT `+configurationRevisionColumns+` FROM configuration_revisions
        WHERE scope_kind=$1 AND org_id IS NOT DISTINCT FROM $2::uuid AND kind=$3 AND status='active'`, scope.Kind, configurationOrgID(scope), kind).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return revision, err
}

func prepareConfigurationActivation(ctx context.Context, q DBTX, scope configuration.Scope, ids []string, actor ConfigurationActor, lock, approval bool) (ConfigurationActivation, error) {
	view := ConfigurationActivation{Scope: scope, Actor: actor, Candidates: []*ConfigurationRevision{}}
	if len(ids) == 0 || len(ids) > 5 {
		return view, ConfigurationConflict("activation requires one to five sibling revision ids")
	}
	if err := validateConfigurationActor(ctx, q, actor, lock); err != nil {
		return view, err
	}
	if scope.Kind == "organization" {
		groupActive, err := activeConfigurationRevision(ctx, q, scope, configuration.Groups)
		if err != nil {
			return view, err
		}
		view.Groups, err = configurationGroups(ctx, q, scope, groupActive, lock)
		if err != nil {
			return view, err
		}
		registryActive, err := activeConfigurationRevision(ctx, q, scope, configuration.ContractRegistry)
		if err != nil {
			return view, err
		}
		view.Registry, view.LegacyExecution, err = configurationRegistry(ctx, q, scope, registryActive, lock)
		if err != nil {
			return view, err
		}
		view.Approvers, err = configurationApprovers(ctx, q, scope)
		if err != nil {
			return view, err
		}
	}

	var executionDoc *configuration.Document
	kinds := map[configuration.Kind]*ConfigurationRevision{}
	for _, id := range ids {
		query := `SELECT ` + configurationRevisionColumns + ` FROM configuration_revisions WHERE id=$1 AND scope_kind=$2 AND org_id IS NOT DISTINCT FROM $3::uuid`
		if lock {
			query += ` FOR UPDATE`
		}
		candidate, err := scanConfigurationRevision(q.QueryRowContext(ctx, query, id, scope.Kind, configurationOrgID(scope)).Scan)
		if err != nil {
			return view, fmt.Errorf("configuration draft not found: %w", err)
		}
		if candidate.Status != PolicyStatusDraft {
			return view, ErrPolicyNotDraft
		}
		if approval && configuration.RequiresHumanAuthor(candidate.Kind) && (actor.PrincipalKind != "human" || candidate.CreatedPrincipalKind != "human") {
			return view, ErrConfigurationForbidden
		}
		if approval && candidate.CreatedBy == actor.UserID && actor.CIApproval == nil {
			return view, ErrPolicySelfApproval
		}
		authorQuery := `SELECT banned FROM users WHERE id=$1`
		if lock {
			authorQuery += ` FOR SHARE`
		}
		var authorBanned bool
		if err := q.QueryRowContext(ctx, authorQuery, candidate.CreatedBy).Scan(&authorBanned); err != nil || authorBanned {
			return view, ConfigurationConflict("configuration author is no longer available for approval")
		}
		if kinds[candidate.Kind] != nil {
			return view, ConfigurationConflict("activation has duplicate sibling kind")
		}
		if candidate.Kind != configuration.Groups && candidate.Kind != configuration.ContractRegistry && candidate.Kind != configuration.Compliance && candidate.Kind != configuration.Approvers && candidate.Kind != configuration.Platform && candidate.Kind != configuration.ExecutionRules {
			return view, ConfigurationConflict("projection for kind %s is not available yet", candidate.Kind)
		}
		active, err := activeConfigurationRevision(ctx, q, scope, candidate.Kind)
		if err != nil {
			return view, err
		}
		base := int64(0)
		if active != nil {
			base = active.Revision
		}
		if candidate.BaseRevision != base {
			return view, ErrPolicyStaleBase
		}
		doc, err := configuration.Parse([]byte(candidate.Source))
		if err != nil {
			return view, err
		}
		_, digest, err := doc.Canonical()
		if err != nil {
			return view, err
		}
		if digest != candidate.Digest || doc.Scope != scope || doc.Kind != candidate.Kind || doc.BaseRevision != candidate.BaseRevision {
			return view, ConfigurationConflict("stored configuration source does not match its revision")
		}
		switch candidate.Kind {
		case configuration.ExecutionRules:
			executionDoc = doc
		case configuration.Platform:
			view.Platform, err = configurationPlatform(ctx, q, active, lock)
			if err != nil {
				return view, err
			}
			diff, err := configuration.DiffPlatform(doc, view.Platform)
			if err != nil {
				return view, ConfigurationConflict("%s", err)
			}
			view.PlatformDiff = &diff
		case configuration.Approvers:
			spec, err := configuration.DiffApprovers(doc, view.Approvers)
			if err != nil {
				return view, ConfigurationConflict("%s", err)
			}
			view.ApproversDiff = &spec
		case configuration.Compliance:
			view.Compliance, err = configurationCompliance(ctx, q, scope, active, lock)
			if err != nil {
				return view, err
			}
			diff, err := configuration.DiffCompliance(doc, view.Compliance)
			if err != nil {
				return view, ConfigurationConflict("%s", err)
			}
			view.ComplianceDiff = &diff
		case configuration.Groups:
			diff, err := configuration.DiffGroups(doc, view.Groups)
			if err != nil {
				return view, ConfigurationConflict("%s", err)
			}
			view.GroupDiff = &diff
		case configuration.ContractRegistry:
			diff, err := configuration.DiffRegistry(doc, view.Registry)
			if err != nil {
				return view, ConfigurationConflict("%s", err)
			}
			view.RegistryDiff = &diff
		}
		kinds[candidate.Kind] = candidate
		view.Candidates = append(view.Candidates, candidate)
	}
	sort.Slice(view.Candidates, func(i, j int) bool { return view.Candidates[i].Kind < view.Candidates[j].Kind })
	for _, candidate := range view.Candidates {
		for kind, digest := range candidate.Dependencies {
			sibling := kinds[kind]
			if sibling == nil {
				var err error
				sibling, err = activeConfigurationRevision(ctx, q, scope, kind)
				if err != nil {
					return view, err
				}
			}
			if sibling == nil || sibling.Digest != digest {
				return view, ConfigurationConflict("sibling dependency %s changed or is not active", kind)
			}
		}
	}
	if err := validateConfigurationRegistry(ctx, q, view, lock); err != nil && scope.Kind == "organization" {
		return view, err
	}
	if err := validateConfigurationApprovers(view); err != nil {
		return view, err
	}
	if scope.Kind == "organization" {
		if err := prepareConfigurationExecution(ctx, q, &view, executionDoc, lock); err != nil {
			return view, err
		}
	}
	if err := validateConfigurationPlatform(ctx, q, view.PlatformDiff, lock); err != nil {
		return view, err
	}
	if approval {
		if err := validateConfigurationCI(ctx, q, view, lock); err != nil {
			return view, err
		}
	}
	return view, nil
}

func configurationGroups(ctx context.Context, q DBTX, scope configuration.Scope, active *ConfigurationRevision, lock bool) (configuration.GroupSnapshot, error) {
	snapshot := configuration.GroupSnapshot{Scope: scope, Groups: []configuration.GroupState{}}
	if scope.Kind != "organization" {
		return snapshot, ConfigurationConflict("groups require organization scope")
	}
	managed := map[string]bool{}
	if active != nil {
		snapshot.ActiveRevision = active.Revision
		doc, err := configuration.Parse([]byte(active.Source))
		if err != nil {
			return snapshot, err
		}
		spec, ok := doc.Spec.(configuration.GroupsSpec)
		if !ok || doc.Scope != scope || doc.Kind != configuration.Groups {
			return snapshot, ConfigurationConflict("active groups source does not match its stream")
		}
		for _, group := range spec.Groups {
			managed[group.ID] = true
		}
	}
	if lock {
		// Parent FOR UPDATE locks stop new FK memberships/access/grants while
		// existing child row locks protect exact counts and access settings.
		for _, query := range []string{
			`SELECT id FROM groups WHERE org_id=$1 ORDER BY id FOR UPDATE`,
			`SELECT ga.id FROM group_access ga JOIN groups g ON g.id=ga.group_id WHERE g.org_id=$1 ORDER BY ga.id FOR UPDATE OF ga`,
			`SELECT m.id FROM user_memberships m JOIN groups g ON g.id=m.group_id WHERE g.org_id=$1 ORDER BY m.id FOR UPDATE OF m`,
			`SELECT u.id FROM users u WHERE EXISTS(SELECT 1 FROM user_memberships m JOIN groups g ON g.id=m.group_id WHERE m.user_id=u.id AND g.org_id=$1) ORDER BY u.id FOR SHARE OF u`,
		} {
			rows, err := q.QueryContext(ctx, query, scope.ID)
			if err != nil {
				return snapshot, err
			}
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return snapshot, err
				}
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return snapshot, err
			}
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT `+groupColumns+` FROM groups WHERE org_id=$1 ORDER BY id`, scope.ID)
	if err != nil {
		return snapshot, err
	}
	groups, err := scanGroups(rows)
	rows.Close()
	if err != nil {
		return snapshot, err
	}
	for _, group := range groups {
		access, err := scanGroupAccessRow(q.QueryRowContext(ctx, `SELECT `+groupAccessColumns+` FROM group_access WHERE group_id=$1`, group.ID))
		if err != nil {
			return snapshot, err
		}
		var members, activeMembers int64
		if err := q.QueryRowContext(ctx, `SELECT COUNT(*),COUNT(*) FILTER(WHERE NOT u.banned) FROM user_memberships m JOIN users u ON u.id=m.user_id WHERE m.group_id=$1 AND (m.expires_at IS NULL OR m.expires_at>NOW())`, group.ID).Scan(&members, &activeMembers); err != nil {
			return snapshot, err
		}
		state := configuration.GroupState{Group: configuration.ExportGroup(group, access), Managed: managed[group.ID], Protected: group.IsSystem, LiveMemberships: members, ActiveMembers: activeMembers, Credential: credentialOwner(access)}
		if group.ParentID != nil || group.Depth != 0 || group.Path != group.Slug {
			state.LegacyHierarchy = &configuration.LegacyGroupHierarchy{ParentID: group.ParentID, Depth: group.Depth, Path: group.Path}
		}
		snapshot.Groups = append(snapshot.Groups, state)
	}
	return snapshot, nil
}

func projectConfigurationGroups(ctx context.Context, tx *Tx, scope configuration.Scope, diff configuration.GroupDiff) error {
	for _, change := range diff.Changes {
		if change.Action == "delete" {
			var grants int64
			if err := tx.tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM contract_grants WHERE group_id=$1`, change.ID).Scan(&grants); err != nil {
				return err
			}
			if grants != 0 {
				return ConfigurationConflict("group has contract grants; revise dependent registry and execution rules before deletion")
			}
			if err := tx.DeleteGroupWithDependenciesTx(ctx, change.ID); err != nil {
				return err
			}
			continue
		}
		group := change.After
		if change.Action == "create" {
			if err := tx.CreateGroup(ctx, &rbac.Group{ID: group.ID, OrgID: scope.ID, Slug: group.Slug, Name: group.Name, Description: group.Description, Path: group.Slug, IsOrgAdmin: group.IsOrgAdmin, IsOrgReadonlyAdmin: group.IsOrgReadonlyAdmin}); err != nil {
				return err
			}
		} else {
			if _, err := tx.tx.ExecContext(ctx, `UPDATE groups SET slug=$2,name=$3,description=$4,is_org_admin=$5,is_org_readonly_admin=$6,updated_at=NOW() WHERE id=$1 AND org_id=$7`, group.ID, group.Slug, group.Name, group.Description, group.IsOrgAdmin, group.IsOrgReadonlyAdmin, scope.ID); err != nil {
				return err
			}
		}
		if _, err := tx.tx.ExecContext(ctx, `INSERT INTO group_access(id,group_id,allowed_methods,claims,verbose_errors)
            VALUES($1,$2,$3,$4,$5) ON CONFLICT(group_id) DO UPDATE SET allowed_methods=EXCLUDED.allowed_methods,claims=EXCLUDED.claims,verbose_errors=EXCLUDED.verbose_errors,updated_at=NOW()`, uuid.NewString(), group.ID, group.AllowedMethods, group.Claims, group.VerboseErrors); err != nil {
			return err
		}
	}
	// Credentials follow the whole projection, not only the changed groups:
	// every activation re-resolves what the document declares, so rotation is
	// "change the variable, activate", and a withdrawn declaration is cleared.
	for _, group := range diff.Projection {
		if err := projectGroupCredential(ctx, tx, group); err != nil {
			return err
		}
	}
	return tx.InvalidateCacheForOrg(ctx, scope.ID)
}

// projectGroupCredential applies a group's declared credential or withdraws
// the one a previous document wrote. Declared: resolve now, inside the
// activation transaction, and store the ciphertext where the rotation
// endpoint would. Not declared: clear only a credential a document wrote,
// never one set operationally. Every refusal names the variable and nothing
// else, and rolls the activation back.
func projectGroupCredential(ctx context.Context, tx *Tx, group configuration.Group) error {
	if group.RpcCredential == nil {
		_, err := tx.tx.ExecContext(ctx, `UPDATE group_access SET rpc_api_key=NULL,rpc_api_key_source=NULL,updated_at=NOW() WHERE group_id=$1 AND rpc_api_key_source IS NOT NULL`, group.ID)
		return err
	}
	name := group.RpcCredential.FromEnv
	if tx.secrets == nil {
		return ConfigurationConflict("group %s declares credential %s but this deployment cannot resolve credentials", group.ID, name)
	}
	ciphertext, err := tx.secrets(name)
	switch {
	case errors.Is(err, configuration.ErrSecretUnset):
		return ConfigurationConflict("group %s credential %s is not set in the OPS environment", group.ID, name)
	case errors.Is(err, configuration.ErrSecretEncryptionUnavailable):
		return ConfigurationConflict("group %s credential %s cannot be stored: credential encryption is not configured", group.ID, name)
	case err != nil:
		return fmt.Errorf("resolve credential %s for group %s: %w", name, group.ID, err)
	}
	result, err := tx.tx.ExecContext(ctx, `UPDATE group_access SET rpc_api_key=$2,rpc_api_key_source=$3,updated_at=NOW() WHERE group_id=$1`, group.ID, ciphertext, name)
	if err != nil {
		return err
	}
	// The access row is written by the upsert just before this step; a
	// declaration that found nothing to hold the value must not pass as done.
	if n, err := result.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return ConfigurationConflict("group %s has no access row to hold credential %s", group.ID, name)
	}
	return nil
}

// credentialOwner says who set a group's upstream credential: the document
// (rendered back as rpcCredential), an operator through the rotation endpoint
// (never rendered as source), or nobody.
func credentialOwner(access *rbac.GroupAccess) string {
	switch {
	case access == nil:
		return "none"
	case access.RPCAPIKeySource != nil && *access.RPCAPIKeySource != "":
		return "declared"
	case access.RPCAPIKey != nil && *access.RPCAPIKey != "":
		return "operational"
	}
	return "none"
}

// ConfigurationActorRoles resolves current scoped authority using the activation
// transaction rather than the HTTP middleware's earlier view.
func (tx *Tx) ConfigurationActorRoles(ctx context.Context, userID, orgID string) (full, readonly bool, err error) {
	err = tx.tx.QueryRowContext(ctx, `SELECT COALESCE(bool_or(g.is_org_admin),false),COALESCE(bool_or(g.is_org_readonly_admin),false)
        FROM users u JOIN user_memberships m ON m.user_id=u.id JOIN groups g ON g.id=m.group_id
        WHERE u.id=$1 AND g.org_id=$2 AND NOT u.banned AND (m.expires_at IS NULL OR m.expires_at>NOW())`, userID, orgID).Scan(&full, &readonly)
	return
}

func configurationAuditOrgID(scope configuration.Scope) *string {
	if scope.Kind == "platform" {
		return nil
	}
	return &scope.ID
}
