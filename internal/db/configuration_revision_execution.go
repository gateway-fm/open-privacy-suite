package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"

	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/policydsl"
)

func compileConfigurationExecution(ctx context.Context, q DBTX, doc *configuration.Document) ([]byte, error) {
	if doc.Kind != configuration.ExecutionRules {
		return nil, nil
	}
	view, err := executionCatalogView(ctx, q, doc.Scope, false)
	if err != nil {
		return nil, err
	}
	// A draft may compile against explicitly named sibling drafts. It cannot
	// borrow unsubmitted or unrelated future catalog state.
	for _, kind := range []configuration.Kind{configuration.Groups, configuration.ContractRegistry} {
		digest, declared := doc.Dependencies[kind]
		if !declared {
			continue
		}
		candidate, err := scanConfigurationRevision(q.QueryRowContext(ctx, `SELECT `+configurationRevisionColumns+` FROM configuration_revisions WHERE scope_kind=$1 AND org_id=$2 AND kind=$3 AND digest=$4 AND status IN ('draft','active') ORDER BY revision DESC LIMIT 1`, doc.Scope.Kind, doc.Scope.ID, kind, digest).Scan)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ConfigurationConflict("execution compiler dependency %s is unavailable", kind)
		}
		if err != nil {
			return nil, err
		}
		if candidate.Status == PolicyStatusActive {
			continue
		}
		sibling, err := configuration.Parse([]byte(candidate.Source))
		if err != nil {
			return nil, err
		}
		_, canonical, err := sibling.Canonical()
		if err != nil {
			return nil, err
		}
		if canonical != digest || sibling.Scope != doc.Scope || sibling.Kind != kind {
			return nil, ConfigurationConflict("execution compiler dependency source changed")
		}
		if kind == configuration.Groups {
			diff, err := configuration.DiffGroups(sibling, view.Groups)
			if err != nil {
				return nil, ConfigurationConflict("execution group dependency: %s", err)
			}
			view.GroupDiff = &diff
		} else {
			diff, err := configuration.DiffRegistry(sibling, view.Registry)
			if err != nil {
				return nil, ConfigurationConflict("execution registry dependency: %s", err)
			}
			view.RegistryDiff = &diff
		}
	}
	cat, err := executionCatalog(ctx, q, view)
	if err != nil {
		return nil, err
	}
	p, err := executionDocumentPolicy(doc)
	if err != nil {
		return nil, err
	}
	if _, err := validateExecutionMigration(ctx, q, doc); err != nil {
		return nil, err
	}
	validated, err := policydsl.Validate(p, cat)
	if err != nil {
		return nil, ConfigurationConflict("execution policy: %s", err)
	}
	// A deployment without the pinned compiler cannot produce an artifact, and
	// that is an operator problem with a known fix — not a server fault. Say so
	// instead of failing the request opaquely; capabilities.compiler already
	// reports the same condition before anyone drafts against it. The
	// underlying error names local paths, so it is logged, never returned.
	compiler := policydsl.NewCompiler()
	if err := compiler.Available(ctx); err != nil {
		slog.Warn("execution-rules submission refused: no usable pinned compiler", "pinned_version", policydsl.SolidityVersion, "err", err)
		return nil, ConfigurationUnavailable("execution rules are compiled with Solidity %s and this deployment has no usable compiler: install it and point POLICY_SOLC at it", policydsl.SolidityVersion)
	}
	artifact, err := compiler.BuildSet(ctx, validated)
	if errors.Is(err, policydsl.ErrPolicyTooLarge) {
		// The document is well formed; it just does not fit in a contract.
		// That is the author's to resolve, so say so rather than reporting a
		// fault they cannot act on.
		return nil, ConfigurationConflict("%s", strings.TrimPrefix(err.Error(), "policydsl: "))
	}
	if err != nil {
		return nil, err
	}
	return json.Marshal(artifact)
}

func executionCatalogView(ctx context.Context, q DBTX, scope configuration.Scope, lock bool) (ConfigurationActivation, error) {
	view := ConfigurationActivation{Scope: scope}
	groups, err := activeConfigurationRevision(ctx, q, scope, configuration.Groups)
	if err != nil {
		return view, err
	}
	view.Groups, err = configurationGroups(ctx, q, scope, groups, lock)
	if err != nil {
		return view, err
	}
	registry, err := activeConfigurationRevision(ctx, q, scope, configuration.ContractRegistry)
	if err != nil {
		return view, err
	}
	view.Registry, view.LegacyExecution, err = configurationRegistry(ctx, q, scope, registry, lock)
	return view, err
}

func executionCatalog(ctx context.Context, q DBTX, view ConfigurationActivation) (policydsl.Catalog, error) {
	cat := policydsl.Catalog{Org: view.Scope.ID, Groups: map[string]struct{}{}, Contracts: map[string]policydsl.ContractInfo{}}
	for _, group := range view.Groups.Groups {
		cat.Groups[group.Group.ID] = struct{}{}
	}
	if view.GroupDiff != nil {
		cat.Groups = map[string]struct{}{}
		for _, group := range view.GroupDiff.Projection {
			cat.Groups[group.ID] = struct{}{}
		}
	}
	rows, err := q.QueryContext(ctx, `SELECT lower(address),COALESCE(abi,'') FROM contracts WHERE org_id=$1 ORDER BY address`, view.Scope.ID)
	if err != nil {
		return cat, err
	}
	for rows.Next() {
		var address, abi string
		if err := rows.Scan(&address, &abi); err != nil {
			rows.Close()
			return cat, err
		}
		if _, exists := cat.Contracts[address]; exists {
			rows.Close()
			return cat, ConfigurationConflict("execution catalog has duplicate addresses")
		}
		cat.Contracts[address] = policydsl.ContractInfo{ABI: abi}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return cat, err
	}
	if view.RegistryDiff != nil {
		changed := map[string]bool{}
		for _, change := range view.RegistryDiff.Changes {
			if change.Resource == "contract" && change.Action != "delete" {
				changed[change.ID] = true
			}
		}
		projected := map[string]policydsl.ContractInfo{}
		for _, contract := range view.RegistryDiff.Projection {
			info, exists := cat.Contracts[contract.Address]
			if !exists || changed[contract.ID] {
				info = policydsl.ContractInfo{ABI: string(contract.ABI)}
			}
			projected[contract.Address] = info
		}
		cat.Contracts = projected
	}
	return cat, nil
}

func executionDocumentPolicy(doc *configuration.Document) (*policydsl.Policy, error) {
	spec, ok := doc.Spec.(configuration.ExecutionSpec)
	if !ok || doc.Kind != configuration.ExecutionRules || doc.Scope.Kind != "organization" || len(doc.Deletions) != 0 {
		return nil, ConfigurationConflict("execution-rules requires a complete organization policy without resource deletions")
	}
	p, err := policydsl.Parse(spec.Policy)
	if err != nil {
		return nil, ConfigurationConflict("execution policy: %s", err)
	}
	if p.Org != doc.Scope.ID {
		return nil, ConfigurationConflict("execution policy organization differs from revision scope")
	}
	expanded, err := policydsl.ApplyProxyPairs(p, spec.ProxyPairs)
	if err != nil {
		return nil, ConfigurationConflict("proxy pair migration: %w", err)
	}
	return expanded, nil
}

func activeExecutionProjection(ctx context.Context, q DBTX, scope configuration.Scope, lock bool) (*ExecutionPolicyRevision, error) {
	query := `SELECT ` + executionPolicyColumns + ` FROM execution_policy_revisions WHERE org_id=$1 AND status='active'`
	if lock {
		query += ` FOR UPDATE`
	}
	p, err := scanExecutionPolicy(q.QueryRowContext(ctx, query, scope.ID).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return p, err
}

func configurationExecutionContext(ctx context.Context, q DBTX, scope configuration.Scope, active *ConfigurationRevision) (configuration.Spec, error) {
	if active != nil {
		doc, err := configuration.Parse([]byte(active.Source))
		if err != nil {
			return nil, err
		}
		_, err = executionDocumentPolicy(doc)
		if err != nil {
			return nil, err
		}
		return doc.Spec.(configuration.ExecutionSpec), nil
	}
	// This is an editable RBAC baseline. Separate read-only migration evidence
	// carries any legacy restriction; no automatic intersection is implied.
	view, err := executionCatalogView(ctx, q, scope, false)
	if err != nil {
		return nil, err
	}
	p, err := importConfigurationExecution(ctx, q, view)
	if err != nil {
		return nil, err
	}
	if p.Org != scope.ID {
		return nil, ConfigurationConflict("execution source organization differs from scope")
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return configuration.ExecutionSpec{Policy: raw}, nil
}

func configurationExecutionMigration(ctx context.Context, q DBTX, scope configuration.Scope) (*configuration.ExecutionMigrationReview, error) {
	previous, err := activeExecutionProjection(ctx, q, scope, false)
	if err != nil {
		return nil, err
	}
	review := &configuration.ExecutionMigrationReview{Diagnostics: []policydsl.LegacyImportIssue{}}
	proxyReview := policydsl.LegacyImportIssue{Reason: "Ordinary proxy relationships cannot be inferred safely. Review deployed proxy implementations and declare spec.proxyPairs, or write explicit code/storage DELEGATECALL rules, before migration."}
	if previous == nil {
		review.Diagnostics = append(review.Diagnostics, proxyReview)
		return review, nil
	}
	var managed bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM configuration_revisions WHERE id=$1 AND org_id=$2 AND kind='execution-rules' AND status='active')`, previous.ID, scope.ID).Scan(&managed); err != nil {
		return nil, err
	}
	if !managed {
		review.Diagnostics = append(review.Diagnostics, proxyReview)
		review.LegacyRestriction = &configuration.LegacyRestrictionEvidence{RevisionID: previous.ID, Revision: previous.Revision, PolicyDigest: previous.PolicyDigest, Source: previous.Source, Artifact: policydsl.Artifact{Source: previous.SoliditySource, SourceDigest: previous.SolidityDigest, RuntimeBytecode: previous.RuntimeBytecode, RuntimeDigest: previous.RuntimeDigest, PolicyDigest: previous.PolicyDigest, Compiler: previous.Compiler}}
		review.Diagnostics = append(review.Diagnostics, policydsl.LegacyImportIssue{Reason: "Legacy policy was a restriction over RBAC. Review both sources and explicitly acknowledge legacyRestrictionDigest in the complete replacement; no automatic effective-policy intersection is claimed."})
	}
	return review, nil
}

func validateExecutionMigration(ctx context.Context, q DBTX, doc *configuration.Document) (*configuration.ExecutionMigrationReview, error) {
	review, err := configurationExecutionMigration(ctx, q, doc.Scope)
	if err != nil {
		return nil, err
	}
	spec := doc.Spec.(configuration.ExecutionSpec)
	if review.LegacyRestriction != nil {
		if spec.LegacyRestrictionDigest != review.LegacyRestriction.PolicyDigest {
			return nil, ConfigurationConflict("legacy restriction requires explicit matching legacyRestrictionDigest acknowledgement after reviewing the RBAC baseline and old policy")
		}
	} else if spec.LegacyRestrictionDigest != "" {
		// Keep the original acknowledgement when editing a generic stream, but
		// do not accept an invented acknowledgement during fresh adoption.
		active, err := activeConfigurationRevision(ctx, q, doc.Scope, configuration.ExecutionRules)
		if err != nil {
			return nil, err
		}
		if active == nil {
			return nil, ConfigurationConflict("legacyRestrictionDigest has no active legacy restriction")
		}
		previous, err := configuration.Parse([]byte(active.Source))
		if err != nil {
			return nil, err
		}
		if previous.Spec.(configuration.ExecutionSpec).LegacyRestrictionDigest != spec.LegacyRestrictionDigest {
			return nil, ConfigurationConflict("legacy restriction acknowledgement differs from active source")
		}
	}
	return review, nil
}

func importConfigurationExecution(ctx context.Context, q DBTX, view ConfigurationActivation) (*policydsl.Policy, error) {
	// The review baseline describes current permission, before any sibling
	// candidate changes the catalog. Never attribute future grants to the past.
	view.GroupDiff, view.RegistryDiff = nil, nil
	cat, err := executionCatalog(ctx, q, view)
	if err != nil {
		return nil, err
	}
	snapshot, err := executionLegacySnapshot(ctx, q, view)
	if err != nil {
		return nil, err
	}
	p, err := policydsl.ImportLegacy(snapshot, cat)
	if err != nil {
		return nil, ConfigurationConflict("execution import requires explicit repair: %w", err)
	}
	return p, nil
}

func executionLegacySnapshot(ctx context.Context, q DBTX, view ConfigurationActivation) (policydsl.LegacySnapshot, error) {
	snapshot := policydsl.LegacySnapshot{}
	index := map[string]int{}
	for _, state := range view.Groups.Groups {
		g := state.Group
		index[g.ID] = len(snapshot.Groups)
		snapshot.Groups = append(snapshot.Groups, policydsl.LegacyGroup{ID: g.ID, OrgAdmin: g.IsOrgAdmin, Claims: append([]string(nil), g.Claims...)})
	}
	for _, grant := range view.LegacyExecution {
		i, exists := index[grant.GroupID]
		if !exists {
			return snapshot, ConfigurationConflict("legacy grant references a missing organization group")
		}
		converted := policydsl.LegacyGrant{Address: grant.Address}
		if grant.Functions != nil {
			converted.Functions = []policydsl.LegacyFunction{}
			for _, function := range grant.Functions {
				f := policydsl.LegacyFunction{Selector: function.Selector}
				for _, param := range function.ParamRules {
					f.ParamRules = append(f.ParamRules, policydsl.LegacyParamRule{Index: param.Index, MustBe: param.MustBe})
				}
				converted.Functions = append(converted.Functions, f)
			}
		}
		snapshot.Groups[i].Grants = append(snapshot.Groups[i].Grants, converted)
	}
	for _, source := range []struct {
		query string
		dest  *[]string
	}{
		{`SELECT lower(address) FROM contracts WHERE org_id=$1 AND deployed_by_user_id IS NOT NULL ORDER BY address`, &snapshot.IndividualDeployerAddresses},
		{`SELECT lower(address) FROM preregistered_addresses WHERE org_id=$1 ORDER BY address`, &snapshot.PreregisteredAddresses},
	} {
		rows, err := q.QueryContext(ctx, source.query, view.Scope.ID)
		if err != nil {
			return snapshot, err
		}
		for rows.Next() {
			var address string
			if err := rows.Scan(&address); err != nil {
				rows.Close()
				return snapshot, err
			}
			*source.dest = append(*source.dest, address)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return snapshot, err
		}
	}
	return snapshot, nil
}

func prepareConfigurationExecution(ctx context.Context, q DBTX, view *ConfigurationActivation, doc *configuration.Document, lock bool) error {
	if view.Scope.Kind != "organization" {
		return nil
	}
	previous, err := activeExecutionProjection(ctx, q, view.Scope, lock)
	if err != nil {
		return err
	}
	if doc == nil && previous == nil {
		return nil
	}
	cat, err := executionCatalog(ctx, q, *view)
	if err != nil {
		return err
	}
	var before *policydsl.Policy
	if previous != nil {
		var managed bool
		if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM configuration_revisions WHERE id=$1 AND org_id=$2 AND kind='execution-rules' AND status='active')`, previous.ID, view.Scope.ID).Scan(&managed); err != nil {
			return err
		}
		if !managed {
			if doc == nil {
				return nil
			}
			before, err = importConfigurationExecution(ctx, q, *view)
		} else {
			before, err = policydsl.Parse([]byte(previous.Source))
		}
		if err != nil {
			// importConfigurationExecution also runs SQL: only a diagnostic
			// written for the author becomes a conflict, a driver error keeps
			// its type so the handler maps it to an opaque 500.
			var client clientMessenger
			if errors.As(err, &client) {
				return ConfigurationConflict("active execution source is invalid: %s", err)
			}
			return err
		}
	} else if doc != nil {
		before, err = importConfigurationExecution(ctx, q, *view)
		if err != nil {
			return err
		}
	}
	if doc == nil {
		if _, err := policydsl.Validate(before, cat); err != nil {
			return ConfigurationConflict("catalog change invalidates active execution rules; co-activate a matching policy: %s", err)
		}
		return nil
	}
	p, err := executionDocumentPolicy(doc)
	if err != nil {
		return err
	}
	migration, err := validateExecutionMigration(ctx, q, doc)
	if err != nil {
		return err
	}
	validated, err := policydsl.Validate(p, cat)
	if err != nil {
		return ConfigurationConflict("execution policy does not match final projected catalog: %s", err)
	}
	var candidate *ConfigurationRevision
	for _, revision := range view.Candidates {
		if revision.Kind == configuration.ExecutionRules {
			candidate = revision
		}
	}
	if candidate == nil {
		return ConfigurationConflict("execution candidate missing")
	}
	artifacts, err := verifyExecutionArtifacts(candidate.Artifact, validated)
	if err != nil {
		return err
	}
	sourceDigest, runtimeDigest := artifacts.Digests()
	diff := &configuration.ExecutionDiff{Before: before, After: p, Changes: configuration.ExecutionChanges(before, p), PolicyDigest: artifacts.PolicyDigest, RuntimeDigest: runtimeDigest, SourceDigest: sourceDigest, Artifacts: artifacts.Groups, Migration: migration}
	if previous != nil {
		diff.PreviousProjectionID = previous.ID
		diff.PreviousProjectionRevision = previous.Revision
	}
	if err := q.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision),0)+1 FROM execution_policy_revisions WHERE org_id=$1`, view.Scope.ID).Scan(&diff.ProjectionRevision); err != nil {
		return err
	}
	view.ExecutionDiff = diff
	return nil
}

func verifyExecutionArtifacts(raw []byte, validated *policydsl.Validated) (*policydsl.ArtifactSet, error) {
	set, err := policydsl.DecodeArtifactSet(raw)
	if err != nil {
		return nil, ConfigurationConflict("compiled execution artifact set is missing or invalid")
	}
	digest, err := policydsl.CanonicalDigest(validated.Policy())
	if err != nil {
		return nil, err
	}
	if digest != set.PolicyDigest {
		return nil, ConfigurationConflict("compiled execution document digest differs")
	}
	if set.Groups[""] == nil && len(set.Groups) != len(validated.Groups()) {
		return nil, ConfigurationConflict("compiled execution artifact group set differs")
	}
	for group, artifact := range set.Groups {
		v := validated
		if group != "" {
			v = validated.ForGroup(group)
		}
		if v == nil {
			return nil, ConfigurationConflict("compiled execution artifact has an unknown group")
		}
		encoded, err := json.Marshal(artifact)
		if err != nil {
			return nil, err
		}
		if _, err := verifyExecutionArtifact(encoded, v); err != nil {
			return nil, err
		}
	}
	return set, nil
}

func verifyExecutionArtifact(raw []byte, validated *policydsl.Validated) (*policydsl.Artifact, error) {
	var artifact policydsl.Artifact
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&artifact); err != nil {
		return nil, ConfigurationConflict("compiled execution artifact is missing or invalid")
	}
	source, err := policydsl.GenerateSolidity(validated)
	if err != nil {
		return nil, err
	}
	policyDigest, err := policydsl.CanonicalDigest(validated.Policy())
	if err != nil {
		return nil, err
	}
	sourceSum, runtimeSum := sha256.Sum256([]byte(source)), sha256.Sum256(artifact.RuntimeBytecode)
	if source != artifact.Source || artifact.SourceDigest != hex.EncodeToString(sourceSum[:]) || artifact.PolicyDigest != policyDigest || len(artifact.RuntimeBytecode) == 0 || len(artifact.RuntimeBytecode) > policydsl.MaxRuntimeBytecode || artifact.RuntimeDigest != hex.EncodeToString(runtimeSum[:]) || !strings.HasPrefix(artifact.Compiler.Version, policydsl.SolidityVersion+"+") || artifact.Compiler.OptimizerRuns != policydsl.OptimizerRuns || artifact.Compiler.EVMVersion != policydsl.EVMVersion {
		return nil, ConfigurationConflict("approved execution artifact differs from its source or compiler contract")
	}
	return &artifact, nil
}

func projectConfigurationExecution(ctx context.Context, tx *Tx, view *ConfigurationActivation) error {
	if view.ExecutionDiff == nil {
		return nil
	}
	diff := view.ExecutionDiff
	var candidate *ConfigurationRevision
	for _, revision := range view.Candidates {
		if revision.Kind == configuration.ExecutionRules {
			candidate = revision
		}
	}
	if candidate == nil {
		return ConfigurationConflict("execution projection candidate missing")
	}
	set, err := policydsl.DecodeArtifactSet(candidate.Artifact)
	if err != nil {
		return err
	}
	// Retain legacy columns for previously approved single-artifact revisions.
	// Grouped revisions carry their complete immutable set in artifact_set;
	// empty runtime bytes must never be mistaken for a runnable org contract.
	artifact := set.Groups[""]
	var artifactSet any
	if artifact == nil {
		sourceDigest, runtimeDigest := set.Digests()
		artifact = &policydsl.Artifact{PolicyDigest: set.PolicyDigest, SourceDigest: sourceDigest, RuntimeDigest: runtimeDigest, RuntimeBytecode: []byte{}}
		artifactSet = []byte(candidate.Artifact)
	}
	compiler, err := json.Marshal(artifact.Compiler)
	if err != nil {
		return err
	}
	source, err := json.Marshal(diff.After)
	if err != nil {
		return err
	}
	if _, err := tx.tx.ExecContext(ctx, `UPDATE execution_policy_revisions SET status='superseded' WHERE org_id=$1 AND status='active'`, view.Scope.ID); err != nil {
		return err
	}
	_, err = tx.tx.ExecContext(ctx, `INSERT INTO execution_policy_revisions(id,org_id,revision,base_revision,status,source,policy_digest,solidity_source,solidity_digest,runtime_bytecode,runtime_digest,compiler,created_by,created_at,activated_by,activated_at,artifact_set)
 VALUES($1,$2,$3,$4,'active',$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NOW(),$15)`, candidate.ID, view.Scope.ID, diff.ProjectionRevision, diff.PreviousProjectionRevision, string(source), artifact.PolicyDigest, artifact.Source, artifact.SourceDigest, artifact.RuntimeBytecode, artifact.RuntimeDigest, compiler, candidate.CreatedBy, candidate.CreatedAt, view.Actor.UserID, artifactSet)
	return err
}
