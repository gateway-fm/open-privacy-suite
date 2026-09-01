package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jackc/tern/v2/migrate"

	"privacy-proxy/internal/db/migrations"
)

// RBACAuditChain is the minimal HashChain surface CreateAuditLog needs.
// Defined here (rather than importing internal/audit directly) to avoid
// an import cycle: internal/audit/retention.go imports internal/db, so
// the chain must reach the DB from above. Server startup constructs
// the concrete audit.HashChain, seeds it via GetLatestRBACAuditLogHash,
// and calls SetRBACAuditChain on the DB.
//
// The Append contract matches audit.HashChain.Append exactly — see that
// method's doc-comment for the build/write semantics.
type RBACAuditChain interface {
	Append(build func(prevHash string) (content string, write func(hash string) error, err error)) (string, error)
}

const (
	// dbMaxRetries is the number of connection attempts before giving up.
	dbMaxRetries = 15
	// dbRetryInterval is the delay between connection attempts.
	dbRetryInterval = 2 * time.Second
)

// ErrAddressLinkRevoked is returned when an ETH address link was revoked by an administrator
// and the user attempts to re-link it. Requires explicit admin action to un-revoke.
var ErrAddressLinkRevoked = errors.New("ETH address link has been revoked by an administrator")

// ErrNotFound is returned when the requested resource does not exist.
var ErrNotFound = errors.New("not found")

// ErrRecordAlreadyUsed is returned when attempting to delete a travel rule record that has already been used.
var ErrRecordAlreadyUsed = errors.New("travel rule record already used")

type DB struct {
	conn        *sql.DB
	databaseURL string

	// rbacAuditChain is the in-process hash chain for rbac_audit_log
	// (RD-858). nil until SetRBACAuditChain is called by server
	// startup; CreateAuditLog falls back to chain-less writes in that
	// case (legacy behaviour preserved for tests and bootstrap).
	rbacAuditChainMu sync.RWMutex
	rbacAuditChain   RBACAuditChain
}

// SetRBACAuditChain installs the rbac_audit_log hash chain on the DB.
// Server startup is responsible for seeding the chain via
// GetLatestRBACAuditLogHash and constructing audit.NewHashChain before
// calling this. Once set, every CreateAuditLog call advances the chain
// and writes the row's entry_hash in a single SQL statement (RD-858).
//
// Idempotent: replacing the chain is supported (e.g. for test
// re-initialization) but should not be done while another goroutine
// is mid-write.
func (d *DB) SetRBACAuditChain(chain RBACAuditChain) {
	d.rbacAuditChainMu.Lock()
	defer d.rbacAuditChainMu.Unlock()
	d.rbacAuditChain = chain
}

// getRBACAuditChain returns the installed chain or nil. Read-locks the
// mutex so reads coexist with each other; SetRBACAuditChain takes the
// write lock.
func (d *DB) getRBACAuditChain() RBACAuditChain {
	d.rbacAuditChainMu.RLock()
	defer d.rbacAuditChainMu.RUnlock()
	return d.rbacAuditChain
}

// Conn returns the underlying database connection (for testing)
func (d *DB) Conn() *sql.DB {
	return d.conn
}

// parseConfigUTC parses a Postgres URL and pins the session timezone to UTC.
//
// Plain TIMESTAMP (without time zone) columns store wall-clock components, so a
// non-UTC session would skew NOW()/CURRENT_TIMESTAMP comparisons against
// Go-written values and silently honour expired RBAC memberships (RD-1005).
// Pinning timezone=UTC on every connection removes the dependency on the
// server's default timezone GUC.
func parseConfigUTC(databaseURL string) (*pgx.ConnConfig, error) {
	cfg, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}
	cfg.RuntimeParams["timezone"] = "UTC"
	return cfg, nil
}

// openPostgres opens a pgx-backed *sql.DB with the session timezone pinned to
// UTC (see parseConfigUTC).
func openPostgres(databaseURL string) (*sql.DB, error) {
	cfg, err := parseConfigUTC(databaseURL)
	if err != nil {
		return nil, err
	}
	return stdlib.OpenDB(*cfg), nil
}

// connectPgxUTC opens a single pgx connection (used for migrations) with the
// session timezone pinned to UTC (see parseConfigUTC).
func (d *DB) connectPgxUTC(ctx context.Context) (*pgx.Conn, error) {
	cfg, err := parseConfigUTC(d.databaseURL)
	if err != nil {
		return nil, err
	}
	return pgx.ConnectConfig(ctx, cfg)
}

// poolConfig holds connection-pool sizing for a database handle.
type poolConfig struct {
	maxOpenConns    int
	maxIdleConns    int
	connMaxLifetime time.Duration
}

// defaultPoolConfig returns the default pool sizing. MaxIdle equals MaxOpen so
// idle connections are retained rather than churned under bursty load
// (RD-1112). Size MaxOpen so N replicas stay under Postgres max_connections.
func defaultPoolConfig() poolConfig {
	return poolConfig{maxOpenConns: 50, maxIdleConns: 50, connMaxLifetime: 5 * time.Minute}
}

// Option configures a database handle (currently connection-pool sizing).
type Option func(*poolConfig)

// WithPool sets the connection-pool sizing. maxIdle should normally equal
// maxOpen to avoid connection churn; non-positive values keep the default.
func WithPool(maxOpen, maxIdle int, connMaxLifetime time.Duration) Option {
	return func(p *poolConfig) {
		if maxOpen > 0 {
			p.maxOpenConns = maxOpen
		}
		if maxIdle > 0 {
			p.maxIdleConns = maxIdle
		}
		if connMaxLifetime > 0 {
			p.connMaxLifetime = connMaxLifetime
		}
	}
}

func applyPool(conn *sql.DB, opts ...Option) {
	p := defaultPoolConfig()
	for _, o := range opts {
		o(&p)
	}
	conn.SetMaxOpenConns(p.maxOpenConns)
	conn.SetMaxIdleConns(p.maxIdleConns)
	conn.SetConnMaxLifetime(p.connMaxLifetime)
}

func New(databaseURL string, opts ...Option) (*DB, error) {
	conn, err := openPostgres(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool (RD-1112: env-tunable, MaxIdle defaults to MaxOpen).
	applyPool(conn, opts...)

	// Retry initial connection — Postgres may not be ready at startup
	// (e.g. external database still booting, or built-in Postgres starting in parallel).
	ctx := context.Background()
	var lastErr error
	for attempt := 1; attempt <= dbMaxRetries; attempt++ {
		if err := conn.PingContext(ctx); err != nil {
			lastErr = err
			if attempt < dbMaxRetries {
				slog.Warn("postgres not ready, retrying",
					"attempt", attempt,
					"max", dbMaxRetries,
					"next_retry_in", dbRetryInterval,
					"error", err)
				time.Sleep(dbRetryInterval)
			}
			continue
		}
		lastErr = nil
		break
	}
	if lastErr != nil {
		conn.Close()
		return nil, fmt.Errorf("postgres connection failed after %d attempts: %w", dbMaxRetries, lastErr)
	}

	db := &DB{conn: conn, databaseURL: databaseURL}

	if err := db.Migrate(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return db, nil
}

// NewWithoutMigrate creates a database connection without running migrations.
// Use this when you need to check migration status or run migrations manually.
func NewWithoutMigrate(databaseURL string, opts ...Option) (*DB, error) {
	conn, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool (RD-1112: env-tunable, MaxIdle defaults to MaxOpen).
	applyPool(conn, opts...)

	// Test connection
	ctx := context.Background()
	if err := conn.PingContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return &DB{conn: conn, databaseURL: databaseURL}, nil
}

func (d *DB) Close() error {
	return d.conn.Close()
}

// Migrate runs all pending database migrations using tern.
func (d *DB) Migrate(ctx context.Context) error {
	return d.migrateFS(ctx, migrations.FS, "schema_version")
}

// MigrateAuditOnly applies the LEAN, STANDALONE audit-database migration set
// (RD-1147) against the audit database's admin/owner pool. It builds the entire
// audit schema from an EMPTY database — the roles, access_logs (+ its hash-chain
// tables), and the append-only seal — and does NOT run the main migration FS, so
// the audit DB never gets users / contracts / groups / rbac_audit_log / etc.
//
// It uses a SEPARATE tern version table (schema_version_audit) so its sequence
// is independent of the main schema. Call it against the audit DSN only; never
// against the main DATABASE_URL (that would seal access_logs to INSERT-only in
// the main DB and break the main-DB retention worker — but under RD-1147 the
// main DB no longer even has access_logs, so this simply must not point at main).
func (d *DB) MigrateAuditOnly(ctx context.Context, auditFS fs.FS) error {
	return d.migrateFS(ctx, auditFS, "schema_version_audit")
}

// migrateFS runs the pending migrations in fsys, tracking applied versions in
// the given tern version table. Kept private; callers use Migrate /
// MigrateAuditOnly which pin the FS + version table together.
func (d *DB) migrateFS(ctx context.Context, fsys fs.FS, versionTable string) error {
	pgxConn, err := d.connectPgxUTC(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect for migrations: %w", err)
	}
	defer pgxConn.Close(ctx)

	migrator, err := newMigrator(ctx, pgxConn, versionTable)
	if err != nil {
		return err
	}

	if err := migrator.LoadMigrations(fsys); err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	if err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

// newMigrator builds a tern migrator, refusing up front when the connected role
// could not run the DDL tern is about to attempt.
func newMigrator(ctx context.Context, conn *pgx.Conn, versionTable string) (*migrate.Migrator, error) {
	if err := checkVersionTableOwnership(ctx, conn, versionTable); err != nil {
		return nil, err
	}
	migrator, err := migrate.NewMigrator(ctx, conn, versionTable)
	if err != nil {
		return nil, fmt.Errorf("failed to create migrator: %w", err)
	}
	return migrator, nil
}

// checkVersionTableOwnership turns tern's opaque "must be owner of table"
// failure into an error carrying the fix.
//
// tern >= 2.4 retro-fits a PRIMARY KEY onto a version table created by an older
// tern, which is an ALTER TABLE and so requires ownership. The audit database
// reaches that state by following its documented lifecycle: the derived DSNs
// create schema_version_audit as DATABASE_URL's owner, then
// AUDIT_ADMIN_DATABASE_URL is pointed at privacy_proxy_admin, which audit/001
// grants privileges to without making it the owner.
//
// pg_has_role(..., 'USAGE') mirrors the has_privs_of_role check Postgres itself
// uses, so membership in the owning role counts. Identifiers come back through
// regclass/quote_ident so the suggested SQL survives roles like "deploy-admin".
// The check trips only on the combination tern itself fails on.
func checkVersionTableOwnership(ctx context.Context, conn *pgx.Conn, versionTable string) error {
	const q = `
		SELECT c.oid::regclass::text,
		       quote_ident(pg_get_userbyid(c.relowner)),
		       quote_ident(current_user),
		       pg_has_role(current_user, c.relowner, 'USAGE'),
		       EXISTS (SELECT 1 FROM pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'p')
		  FROM pg_class c
		 WHERE c.oid = to_regclass($1)`

	var table, owner, currentUser string
	var canActAsOwner, hasPrimaryKey bool
	err := conn.QueryRow(ctx, q, versionTable).Scan(&table, &owner, &currentUser, &canActAsOwner, &hasPrimaryKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // fresh database: tern creates the table, primary key included
	}
	if err != nil {
		return fmt.Errorf("failed to inspect migration version table %q: %w", versionTable, err)
	}
	if hasPrimaryKey || canActAsOwner {
		return nil
	}

	return fmt.Errorf(
		"cannot migrate %[1]s: it is owned by %[2]s but this connection is %[3]s, and tern needs "+
			"ALTER TABLE on it. As a superuser: ALTER TABLE %[1]s OWNER TO %[3]s; As %[2]s the transfer "+
			"also needs membership in %[3]s, which must not outlive it, so run it as one transaction: "+
			"BEGIN; GRANT %[3]s TO %[2]s; ALTER TABLE %[1]s OWNER TO %[3]s; REVOKE %[3]s FROM %[2]s; COMMIT; "+
			"For an audit database whose AUDIT_ADMIN_DATABASE_URL moved to a dedicated role, use "+
			"REASSIGN OWNED BY %[2]s TO %[3]s in place of the ALTER TABLE to move the whole schema.",
		table, owner, currentUser)
}

// MigrateWithProgress runs migrations with a progress callback for CLI usage.
// The callback receives: sequence number, migration name, direction ("up"/"down"), and SQL.
func (d *DB) MigrateWithProgress(ctx context.Context, onStart func(sequence int32, name, direction, sql string)) error {
	pgxConn, err := d.connectPgxUTC(ctx)
	if err != nil {
		return fmt.Errorf("failed to connect for migrations: %w", err)
	}
	defer pgxConn.Close(ctx)

	migrator, err := newMigrator(ctx, pgxConn, "schema_version")
	if err != nil {
		return err
	}

	if err := migrator.LoadMigrations(migrations.FS); err != nil {
		return fmt.Errorf("failed to load migrations: %w", err)
	}

	if onStart != nil {
		migrator.OnStart = onStart
	}

	if err := migrator.Migrate(ctx); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	return nil
}

// GetMigrationStatus returns the current migration version and pending migrations.
func (d *DB) GetMigrationStatus(ctx context.Context) (currentVersion int32, pendingCount int, err error) {
	pgxConn, err := d.connectPgxUTC(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to connect for migrations: %w", err)
	}
	defer pgxConn.Close(ctx)

	migrator, err := newMigrator(ctx, pgxConn, "schema_version")
	if err != nil {
		return 0, 0, err
	}

	if err := migrator.LoadMigrations(migrations.FS); err != nil {
		return 0, 0, fmt.Errorf("failed to load migrations: %w", err)
	}

	version, err := migrator.GetCurrentVersion(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get current version: %w", err)
	}

	pending := len(migrator.Migrations) - int(version)
	if pending < 0 {
		pending = 0
	}

	return version, pending, nil
}

func (d *DB) LogAccess(ctx context.Context, externalID, method string, statusCode int, ipAddress string) error {
	query := `INSERT INTO access_logs (external_id, method, status_code, ip_address)
	          VALUES ($1, $2, $3, $4)`

	_, err := d.conn.ExecContext(ctx, query, externalID, method, statusCode, ipAddress)
	return err
}

type AccessLog struct {
	ID                int              `json:"id"`
	ExternalID        string           `json:"external_id"`
	Method            string           `json:"method"`
	StatusCode        int              `json:"status_code"`
	ResponseStatus    *int             `json:"response_status,omitempty"`
	IPAddress         string           `json:"ip_address"`
	CorrelationID     *string          `json:"correlation_id,omitempty"`
	RequestParams     *json.RawMessage `json:"request_params,omitempty"`
	EntryHash         *string          `json:"entry_hash,omitempty"`
	HashFormatVersion int              `json:"hash_format_version"`
	CreatedAt         string           `json:"created_at"`
	// OrgID is the organization the entry-point access decision resolved
	// against (RD-1135). NULL for pre-migration rows and for requests with
	// no resolved org (anonymous / org-free metadata methods); such rows are
	// visible only to super-admin callers.
	OrgID *string `json:"org_id,omitempty"`
	// DenialReason is the curated reason code for a denied request (RD-1137;
	// see server.denial_reasons). NULL for successful or unclassified requests.
	DenialReason *string `json:"denial_reason,omitempty"`
}

// AccessLogFilter narrows GetAccessLogs / CountAccessLogs results. Every field
// is optional — zero values mean "no constraint on this field". Filters are
// always applied as parameterised SQL (no string concatenation of inputs).
type AccessLogFilter struct {
	ExternalID    string
	Method        string
	StatusCode    int    // 0 = unset; exact match
	StatusClass   string // "" = unset; "2xx" / "4xx" / "5xx" — range match (status_code BETWEEN N00 AND N99)
	CorrelationID string
	From          time.Time // zero = unset
	To            time.Time // zero = unset
	Limit         int       // <=0 = default 100; clamped to 1000
	Offset        int
	// OrgIDs scopes results to these organizations (RD-1135). The nil-vs-empty
	// distinction is load-bearing and mirrors ListAuditLogsScoped:
	//   - nil          → no org constraint (super-admin / dev: fleet-wide).
	//   - non-nil empty → caller is a JWT org admin with zero orgs → ZERO rows
	//                      (fail closed). buildAccessLogWhere emits an
	//                      always-false predicate so every consumer
	//                      (GetAccessLogs AND CountAccessLogs) agrees.
	//   - non-empty     → org_id = ANY(OrgIDs). NULL org_id never matches, so
	//                      unattributed rows stay super-admin-only.
	OrgIDs []string
}

// statusClassRange returns the [low, high] inclusive bounds for a status class
// string. Returns ok=false for unknown values; the caller should treat that as
// "no class filter applied" (the handler validates and rejects unknowns up front).
func statusClassRange(class string) (low, high int, ok bool) {
	switch class {
	case "2xx":
		return 200, 299, true
	case "4xx":
		return 400, 499, true
	case "5xx":
		return 500, 599, true
	}
	return 0, 0, false
}

// MaxAccessLogQueryLimit is the server-side cap on `limit` for the access-log
// admin endpoint. Limits above this are clamped down silently.
const MaxAccessLogQueryLimit = 1000

// buildAccessLogWhere returns the WHERE clause (without the leading "WHERE")
// and the positional args for the supplied filter. The first arg index is 1.
// Returns ("", nil) when no constraints apply.
func buildAccessLogWhere(f AccessLogFilter) (string, []any) {
	clauses := make([]string, 0, 6)
	args := make([]any, 0, 6)
	idx := 1

	if f.ExternalID != "" {
		clauses = append(clauses, fmt.Sprintf("external_id = $%d", idx))
		args = append(args, f.ExternalID)
		idx++
	}
	if f.Method != "" {
		clauses = append(clauses, fmt.Sprintf("method = $%d", idx))
		args = append(args, f.Method)
		idx++
	}
	if f.StatusCode != 0 {
		clauses = append(clauses, fmt.Sprintf("status_code = $%d", idx))
		args = append(args, f.StatusCode)
		idx++
	} else if low, high, ok := statusClassRange(f.StatusClass); ok {
		// Range filter — drives the admin UI's outcome dropdown ("Denied (4xx)" etc.).
		// Mutually exclusive with StatusCode (the handler enforces that); the
		// "else if" here is a safety net so a misuse silently picks one branch.
		clauses = append(clauses, fmt.Sprintf("status_code BETWEEN $%d AND $%d", idx, idx+1))
		args = append(args, low, high)
		idx += 2
	}
	if f.CorrelationID != "" {
		clauses = append(clauses, fmt.Sprintf("correlation_id = $%d", idx))
		args = append(args, f.CorrelationID)
		idx++
	}
	if !f.From.IsZero() {
		clauses = append(clauses, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, f.From)
		idx++
	}
	if !f.To.IsZero() {
		clauses = append(clauses, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, f.To)
		idx++
	}
	// RD-1135 cross-org scoping. Applied here (not in the handler) so both
	// GetAccessLogs and CountAccessLogs fail closed identically. See
	// AccessLogFilter.OrgIDs for the nil-vs-empty contract.
	if f.OrgIDs != nil {
		if len(f.OrgIDs) == 0 {
			clauses = append(clauses, "1=0")
		} else {
			clauses = append(clauses, fmt.Sprintf("org_id = ANY($%d)", idx))
			args = append(args, f.OrgIDs)
			idx++
		}
	}
	if len(clauses) == 0 {
		return "", nil
	}
	return strings.Join(clauses, " AND "), args
}

// GetAccessLogs returns access log rows ordered by created_at DESC, applying
// the supplied filter. Limit is clamped to [1, MaxAccessLogQueryLimit].
func (d *DB) GetAccessLogs(ctx context.Context, f AccessLogFilter) ([]*AccessLog, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > MaxAccessLogQueryLimit {
		limit = MaxAccessLogQueryLimit
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	where, args := buildAccessLogWhere(f)
	query := `SELECT id, external_id, method, status_code, response_status, ip_address,
	          correlation_id, request_params, entry_hash, hash_format_version, created_at, org_id, denial_reason
	          FROM access_logs`
	if where != "" {
		query += " WHERE " + where
	}
	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d OFFSET $%d", len(args)+1, len(args)+2)
	args = append(args, limit, offset)

	rows, err := d.conn.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to get logs: %w", err)
	}
	defer rows.Close()

	logs := make([]*AccessLog, 0)

	for rows.Next() {
		var log AccessLog
		var correlationID, entryHash, orgID, denialReason sql.NullString
		var responseStatus sql.NullInt32
		var requestParams []byte

		if err := rows.Scan(
			&log.ID,
			&log.ExternalID,
			&log.Method,
			&log.StatusCode,
			&responseStatus,
			&log.IPAddress,
			&correlationID,
			&requestParams,
			&entryHash,
			&log.HashFormatVersion,
			&log.CreatedAt,
			&orgID,
			&denialReason,
		); err != nil {
			return nil, fmt.Errorf("failed to scan log: %w", err)
		}

		if correlationID.Valid {
			log.CorrelationID = &correlationID.String
		}
		if responseStatus.Valid {
			rs := int(responseStatus.Int32)
			log.ResponseStatus = &rs
		}
		if len(requestParams) > 0 {
			raw := json.RawMessage(requestParams)
			log.RequestParams = &raw
		}
		if entryHash.Valid {
			log.EntryHash = &entryHash.String
		}
		if orgID.Valid {
			log.OrgID = &orgID.String
		}
		if denialReason.Valid {
			log.DenialReason = &denialReason.String
		}

		logs = append(logs, &log)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate logs: %w", err)
	}

	return logs, nil
}

// CountAccessLogs returns the number of access log rows matching the supplied
// filter (ignoring Limit/Offset). Used by the admin API to render pagination.
func (d *DB) CountAccessLogs(ctx context.Context, f AccessLogFilter) (int64, error) {
	where, args := buildAccessLogWhere(f)
	query := "SELECT COUNT(*) FROM access_logs"
	if where != "" {
		query += " WHERE " + where
	}
	var n int64
	if err := d.conn.QueryRowContext(ctx, query, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("failed to count access logs: %w", err)
	}
	return n, nil
}

// LogAccessEnhanced inserts an access log entry with correlation ID, optional request params, and returns the ID and created_at for hash chain computation.
// responseStatus is the HTTP status returned to the client (may differ from statusCode for opaque denials).
// orgID is the resolved organization for RD-1135 scoping; "" stores NULL
// (unattributed → super-admin-only on read). denialReason is the curated
// RD-1137 reason code; "" stores NULL (success / unclassified).
func (d *DB) LogAccessEnhanced(ctx context.Context, externalID, method string, statusCode int, ipAddress, correlationID string, params []byte, responseStatus *int, orgID string, denialReason string) (int64, time.Time, error) {
	query := `INSERT INTO access_logs (external_id, method, status_code, ip_address, correlation_id, request_params, response_status, hash_format_version, org_id, denial_reason)
	          VALUES ($1, $2, $3, $4, $5, $6, $7, 2, $8, $9)
	          RETURNING id, created_at`

	var id int64
	var createdAt time.Time
	var corrID *string
	if correlationID != "" {
		corrID = &correlationID
	}

	err := d.conn.QueryRowContext(ctx, query, externalID, method, statusCode, ipAddress, corrID, params, responseStatus, nullableText(orgID), nullableText(denialReason)).Scan(&id, &createdAt)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("failed to log enhanced access: %w", err)
	}
	return id, createdAt, nil
}

// nullableText maps "" to a nil *string so an empty value is stored as SQL
// NULL rather than an empty string.
func nullableText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// UpdateAccessLogHash sets the entry_hash for an access log entry after hash chain computation.
//
// Deprecated: callers writing audit-integrity-sensitive rows should use
// LogAccessChained instead, which combines the INSERT + UPDATE in a
// single transaction and advances the hash chain only after the commit
// succeeds. UpdateAccessLogHash is retained for tests that seed rows
// without chain participation.
func (d *DB) UpdateAccessLogHash(ctx context.Context, id int64, hash string) error {
	_, err := d.conn.ExecContext(ctx, `UPDATE access_logs SET entry_hash = $2 WHERE id = $1`, id, hash)
	return err
}

// AccessLogChainContent builds the canonical hash-chain content for an
// access_logs row at format version 2. **Exported because the verifier
// uses it** to recompute hashes when walking the chain, and the verifier
// must agree byte-for-byte with the writer or every row would look
// tampered.
//
// The format must NEVER change in place — bump hash_format_version
// (column on access_logs) and add a new builder if fields are added /
// reordered.
//
// Argument order mirrors the column order in LogAccessChained.
func AccessLogChainContent(id int64, externalID, method, ipAddress string, statusCode, responseStatus int, createdAt time.Time, correlationID string, paramsDigest string) string {
	return fmt.Sprintf("v2|%d|%s|%s|%s|%d|%d|%s|%s|%s",
		id, externalID, method, ipAddress, statusCode, responseStatus,
		createdAt.UTC().Format(time.RFC3339Nano),
		correlationID,
		paramsDigest,
	)
}

// LogAccessChained writes an access_logs row AND its hash-chain link
// atomically (RD-858: closes the two-step write race where a crash
// between INSERT and UpdateAccessLogHash left entry_hash NULL — a
// state the verifier cannot distinguish from tampering).
//
// Mechanism:
//  1. Reserve the row id via nextval('access_logs_id_seq'). created_at
//     is set on the Go side (UTC, nanosecond precision) so that the
//     hash content is known BEFORE the INSERT.
//  2. Build the canonical content via AccessLogChainContent.
//  3. Ask the chain for the next hash. The chain mutex stays held
//     through the row write — if INSERT fails, the chain rolls back
//     and the next call uses the same prev hash, preserving
//     id-ordered = chain-ordered semantics.
//  4. INSERT the row with id, created_at, entry_hash all set in one
//     statement.
//
// The chain head advances only when INSERT returns nil. A process
// crash anywhere before the INSERT commits leaves no row and no chain
// advance — the verifier never sees a NULL-hash row from this writer.
//
// chain must implement RBACAuditChain.Append's contract — the
// audit.HashChain returned by audit.NewHashChain satisfies it. Pass
// nil to skip the chain entirely (fallback for tests / startup paths
// where the chain isn't installed yet); the row is written via
// LogAccessEnhanced + UpdateAccessLogHash legacy path so behaviour
// matches the pre-RD-858 default.
func (d *DB) LogAccessChained(
	ctx context.Context,
	chain RBACAuditChain,
	externalID, method string,
	statusCode int,
	ipAddress, correlationID string,
	params []byte,
	responseStatus *int,
	orgID string,
	denialReason string,
) (int64, time.Time, string, error) {
	if chain == nil {
		id, createdAt, err := d.LogAccessEnhanced(ctx, externalID, method, statusCode, ipAddress, correlationID, params, responseStatus, orgID, denialReason)
		return id, createdAt, "", err
	}

	var corrID *string
	if correlationID != "" {
		corrID = &correlationID
	}

	respStatus := statusCode
	if responseStatus != nil {
		respStatus = *responseStatus
	}

	var outID int64
	var outCreatedAt time.Time

	hash, err := chain.Append(func(prev string) (string, func(string) error, error) {
		var id int64
		if scanErr := d.conn.QueryRowContext(ctx,
			`SELECT nextval('access_logs_id_seq')`,
		).Scan(&id); scanErr != nil {
			return "", nil, fmt.Errorf("reserve access_logs id: %w", scanErr)
		}
		// Postgres TIMESTAMP stores microsecond precision; Go's
		// time.Now() carries nanoseconds. Truncate so the hash content
		// (computed before write) matches the value the verifier reads
		// back. Without this, every chain would look tampered on
		// re-read because the last three digits of the format string
		// disagree.
		createdAt := time.Now().UTC().Truncate(time.Microsecond)
		paramsDigest := ""
		if len(params) > 0 {
			paramsDigest = string(params)
		}
		content := AccessLogChainContent(id, externalID, method, ipAddress, statusCode, respStatus, createdAt, correlationID, paramsDigest)

		write := func(hash string) error {
			// org_id (RD-1135) is appended to the row but is deliberately
			// absent from `content` above — it is a confidentiality-scoping
			// attribute for reads, not part of the tamper-evident hash. The
			// chain content + verifier therefore stay at format v2.
			res, execErr := d.conn.ExecContext(ctx,
				`INSERT INTO access_logs
					(id, external_id, method, status_code, ip_address, correlation_id, request_params, response_status, hash_format_version, created_at, entry_hash, org_id, denial_reason)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 2, $9, $10, $11, $12)`,
				id, externalID, method, statusCode, ipAddress, corrID, params, responseStatus, createdAt, hash, nullableText(orgID), nullableText(denialReason),
			)
			if execErr != nil {
				return fmt.Errorf("insert access_logs: %w", execErr)
			}
			if affected, _ := res.RowsAffected(); affected != 1 {
				return fmt.Errorf("insert access_logs: expected 1 row, got %d", affected)
			}
			outID = id
			outCreatedAt = createdAt
			return nil
		}
		_ = prev
		return content, write, nil
	})
	if err != nil {
		return 0, time.Time{}, "", err
	}
	return outID, outCreatedAt, hash, nil
}

// AccessLogRecord is the buffered form of an access-log entry (RD-1112). The
// hot path serializes this into the durable audit buffer and returns; the
// sealer deserializes it and seals it into the chain via SealBufferedAccessLog.
type AccessLogRecord struct {
	ExternalID     string `json:"e"`
	Method         string `json:"m"`
	StatusCode     int    `json:"s"`
	IPAddress      string `json:"ip,omitempty"`
	CorrelationID  string `json:"c,omitempty"`
	Params         []byte `json:"p,omitempty"`
	ResponseStatus *int   `json:"rs,omitempty"`
	// OrgID is the resolved org for RD-1135 scoping; "" → NULL on seal
	// (unattributed → super-admin-only on read). Not part of the hashed chain
	// content.
	OrgID string `json:"o,omitempty"`
	// DenialReason is the curated RD-1137 reason code for a denied request;
	// "" → NULL on seal. Also not part of the hashed chain content.
	DenialReason string `json:"dr,omitempty"`
}

// GetMaxAccessLogBufferSeq returns the highest buffer_seq already sealed into
// access_logs (0 if none) — the sealer's crash-safe resume high-water
// (RD-1112). Entries at or below it are already durably sealed.
func (d *DB) GetMaxAccessLogBufferSeq(ctx context.Context, chainName string) (uint64, error) {
	var seq sql.NullInt64
	if err := d.conn.QueryRowContext(ctx,
		`SELECT MAX(buffer_seq) FROM access_logs WHERE chain_name = $1`, chainName).Scan(&seq); err != nil {
		return 0, fmt.Errorf("max access_logs buffer_seq: %w", err)
	}
	if !seq.Valid || seq.Int64 < 0 {
		return 0, nil
	}
	return uint64(seq.Int64), nil
}

// SealBufferedAccessLog seals one buffered access-log record into the chain,
// tagged with its buffer sequence. It mirrors LogAccessChained's canonical
// content exactly (buffer_seq is NOT part of the hashed content), so the
// verifier and existing rows are unaffected. buffer_seq is UNIQUE, so a
// double-seal surfaces as a loud constraint error rather than a silent
// duplicate; the sealer's high-water resume normally prevents that from ever
// happening.
func (d *DB) SealBufferedAccessLog(ctx context.Context, chain RBACAuditChain, rec AccessLogRecord, bufferSeq uint64, chainName string) (string, error) {
	if chain == nil {
		return "", fmt.Errorf("seal access log: nil chain")
	}

	var corrID *string
	if rec.CorrelationID != "" {
		corrID = &rec.CorrelationID
	}
	respStatus := rec.StatusCode
	if rec.ResponseStatus != nil {
		respStatus = *rec.ResponseStatus
	}

	hash, err := chain.Append(func(prev string) (string, func(string) error, error) {
		var id int64
		if scanErr := d.conn.QueryRowContext(ctx,
			`SELECT nextval('access_logs_id_seq')`,
		).Scan(&id); scanErr != nil {
			return "", nil, fmt.Errorf("reserve access_logs id: %w", scanErr)
		}
		createdAt := time.Now().UTC().Truncate(time.Microsecond)
		paramsDigest := ""
		if len(rec.Params) > 0 {
			paramsDigest = string(rec.Params)
		}
		content := AccessLogChainContent(id, rec.ExternalID, rec.Method, rec.IPAddress, rec.StatusCode, respStatus, createdAt, rec.CorrelationID, paramsDigest)

		write := func(hash string) error {
			res, execErr := d.conn.ExecContext(ctx,
				`INSERT INTO access_logs
					(id, external_id, method, status_code, ip_address, correlation_id, request_params, response_status, hash_format_version, created_at, entry_hash, buffer_seq, chain_name, org_id, denial_reason)
				 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 2, $9, $10, $11, $12, $13, $14)`,
				id, rec.ExternalID, rec.Method, rec.StatusCode, rec.IPAddress, corrID, rec.Params, rec.ResponseStatus, createdAt, hash, int64(bufferSeq), chainName, nullableText(rec.OrgID), nullableText(rec.DenialReason),
			)
			if execErr != nil {
				return fmt.Errorf("insert access_logs (seal): %w", execErr)
			}
			if affected, _ := res.RowsAffected(); affected != 1 {
				return fmt.Errorf("insert access_logs (seal): expected 1 row, got %d", affected)
			}
			return nil
		}
		_ = prev
		return content, write, nil
	})
	if err != nil {
		return "", err
	}
	return hash, nil
}

// AuditChainCheckpointRow is a persisted signed checkpoint (RD-1112 #8),
// exchanged as primitives so the db package need not import internal/audit
// (the audit package reconstructs its signed Checkpoint from this).
type AuditChainCheckpointRow struct {
	ChainName string
	HeadID    int64
	HeadHash  string
	RowCount  int64
	KeyID     string
	Signature string
	CreatedAt time.Time
}

// WriteAuditChainCheckpoint appends a signed truncation-detection checkpoint.
func (d *DB) WriteAuditChainCheckpoint(ctx context.Context, c AuditChainCheckpointRow) error {
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO audit_chain_checkpoint (chain_name, head_id, head_hash, row_count, key_id, signature, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		c.ChainName, c.HeadID, c.HeadHash, c.RowCount, c.KeyID, c.Signature, c.CreatedAt.UTC())
	if err != nil {
		return fmt.Errorf("write audit chain checkpoint: %w", err)
	}
	return nil
}

// GetLatestAuditChainCheckpoint returns the most recent checkpoint for
// chainName, or (nil, nil) if none exist.
func (d *DB) GetLatestAuditChainCheckpoint(ctx context.Context, chainName string) (*AuditChainCheckpointRow, error) {
	var c AuditChainCheckpointRow
	err := d.conn.QueryRowContext(ctx,
		`SELECT chain_name, head_id, head_hash, row_count, key_id, signature, created_at
		 FROM audit_chain_checkpoint WHERE chain_name = $1 ORDER BY id DESC LIMIT 1`, chainName,
	).Scan(&c.ChainName, &c.HeadID, &c.HeadHash, &c.RowCount, &c.KeyID, &c.Signature, &c.CreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get latest audit chain checkpoint: %w", err)
	}
	return &c, nil
}

// GetAccessLogChainStats returns the row count and current head (id + entry_hash)
// for the named chain — the inputs the checkpoint worker signs (RD-1112 #8).
// rowCount=0 (zero head) when the chain is empty.
func (d *DB) GetAccessLogChainStats(ctx context.Context, chainName string) (rowCount, headID int64, headHash string, err error) {
	if e := d.conn.QueryRowContext(ctx,
		`SELECT count(*) FROM access_logs WHERE chain_name = $1`, chainName).Scan(&rowCount); e != nil {
		return 0, 0, "", fmt.Errorf("count access_logs: %w", e)
	}
	if rowCount == 0 {
		return 0, 0, "", nil
	}
	var hh sql.NullString
	if e := d.conn.QueryRowContext(ctx,
		`SELECT id, entry_hash FROM access_logs WHERE chain_name = $1 ORDER BY id DESC LIMIT 1`, chainName,
	).Scan(&headID, &hh); e != nil {
		return 0, 0, "", fmt.Errorf("head access_logs: %w", e)
	}
	return rowCount, headID, hh.String, nil
}

// WriteAuditChainReAnchor appends a signed break-glass re-anchor record — the
// permanent, attributable trail of an authorized chain discontinuity (RD-1112
// #8). Append-only; rows are never updated or deleted.
func (d *DB) WriteAuditChainReAnchor(ctx context.Context, chainName, reason, actor string, fromHeadID int64, fromHash string, toHeadID int64, toHash, keyID, signature string, createdAt time.Time) error {
	_, err := d.conn.ExecContext(ctx,
		`INSERT INTO audit_chain_reanchor (chain_name, reason, actor, from_head_id, from_hash, to_head_id, to_hash, key_id, signature, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		chainName, reason, actor, fromHeadID, fromHash, toHeadID, toHash, keyID, signature, createdAt.UTC())
	if err != nil {
		return fmt.Errorf("write audit chain re-anchor: %w", err)
	}
	return nil
}

// GetLatestRBACAuditLogHash returns the seed for the rbac_audit_log hash
// chain (RD-858). Resolution order mirrors GetLatestAccessLogHash:
//  1. The entry_hash of the most recent surviving rbac_audit_log row.
//  2. If no row has an entry_hash, audit_chain_anchor.last_pruned_entry_hash
//     for chain "rbac_audit_log".
//  3. Otherwise the empty string (fresh chain).
func (d *DB) GetLatestRBACAuditLogHash(ctx context.Context) (string, error) {
	var hash sql.NullString
	err := d.conn.QueryRowContext(ctx,
		`SELECT entry_hash FROM rbac_audit_log WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1`,
	).Scan(&hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("failed to get latest rbac audit log hash: %w", err)
	}
	if hash.Valid && hash.String != "" {
		return hash.String, nil
	}
	anchor, err := d.GetAuditChainAnchor(ctx, ChainNameRBACAuditLog)
	if err != nil {
		return "", err
	}
	if anchor != nil {
		return anchor.LastPrunedEntryHash, nil
	}
	return "", nil
}

// GetLatestAccessLogHash returns the seed for the access_logs hash chain.
// Resolution order:
//  1. The entry_hash of the most recent surviving access_logs row.
//  2. If no surviving rows have an entry_hash, the last_pruned_entry_hash from
//     the audit_chain_anchor table for chain "access_logs". This keeps the
//     chain verifiable when retention has trimmed every previous row.
//  3. Otherwise the empty string (fresh chain).
func (d *DB) GetLatestAccessLogHash(ctx context.Context) (string, error) {
	var hash sql.NullString
	err := d.conn.QueryRowContext(ctx,
		`SELECT entry_hash FROM access_logs WHERE entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1`,
	).Scan(&hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("failed to get latest access log hash: %w", err)
	}
	if hash.Valid && hash.String != "" {
		return hash.String, nil
	}
	// Fallback: anchor table preserves the seed across pruning cuts.
	anchor, err := d.GetAuditChainAnchor(ctx, ChainNameAccessLogs)
	if err != nil {
		return "", err
	}
	if anchor != nil {
		return anchor.LastPrunedEntryHash, nil
	}
	return "", nil
}

// GetLatestAccessLogHashForChain is GetLatestAccessLogHash scoped to one
// chain_name — the seed a per-instance sealer resumes from on restart, so it
// continues ITS chain rather than linking to whichever instance wrote the
// global tail (RD-1112 #8, prevents the multi-writer fork). For the default
// chain_name ('access_logs') this is equivalent to the global query.
func (d *DB) GetLatestAccessLogHashForChain(ctx context.Context, chainName string) (string, error) {
	var hash sql.NullString
	err := d.conn.QueryRowContext(ctx,
		`SELECT entry_hash FROM access_logs WHERE chain_name = $1 AND entry_hash IS NOT NULL ORDER BY id DESC LIMIT 1`,
		chainName,
	).Scan(&hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("get latest access log hash for chain %q: %w", chainName, err)
	}
	if hash.Valid && hash.String != "" {
		return hash.String, nil
	}
	anchor, err := d.GetAuditChainAnchor(ctx, chainName)
	if err != nil {
		return "", err
	}
	if anchor != nil {
		return anchor.LastPrunedEntryHash, nil
	}
	return "", nil
}

// CleanupAccessLogs deletes access log entries older than the given time AND
// updates the access_logs chain anchor with the (id, entry_hash) of the last
// row to be deleted in this batch. The anchor write + delete run inside a
// single transaction so the chain stays verifiable even if the prune is
// interrupted between rows.
//
// If no rows match the cutoff, the anchor is left unchanged. If the row about
// to be deleted has a NULL entry_hash (e.g. the row never received an
// UpdateAccessLogHash because the process crashed between insert and update),
// the anchor still records the row's id but uses the previous anchor hash —
// that is the latest known good seed for downstream verification.
func (d *DB) CleanupAccessLogs(ctx context.Context, olderThan time.Time) (PruneResult, error) {
	var res PruneResult
	err := d.WithTx(ctx, func(wtx *Tx) error {
		tx := wtx.tx

		// Pick the row with the lowest id among those about to be deleted —
		// surfaced via PruneResult.LowestID so the audit-of-the-audit row can
		// describe the full deleted range, not just its endpoint.
		var firstID sql.NullInt64
		err := tx.QueryRowContext(ctx, `
			SELECT id FROM access_logs
			WHERE created_at < $1
			ORDER BY id ASC
			LIMIT 1`, olderThan).Scan(&firstID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("failed to read prune lowest id for access_logs: %w", err)
		}

		// Pick the row with the highest id among those about to be deleted.
		var lastID sql.NullInt64
		var lastHash sql.NullString
		err = tx.QueryRowContext(ctx, `
			SELECT id, entry_hash FROM access_logs
			WHERE created_at < $1
			ORDER BY id DESC
			LIMIT 1`, olderThan).Scan(&lastID, &lastHash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("failed to read prune cut for access_logs: %w", err)
		}

		result, err := tx.ExecContext(ctx, `DELETE FROM access_logs WHERE created_at < $1`, olderThan)
		if err != nil {
			return fmt.Errorf("failed to cleanup access logs: %w", err)
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to count deleted access logs: %w", err)
		}

		res = PruneResult{Deleted: deleted}
		if deleted > 0 && lastID.Valid {
			anchorHash := lastHash.String
			if !lastHash.Valid || anchorHash == "" {
				// The row had no entry_hash — fall back to the previous anchor so
				// downstream verifiers still have a valid seed. If there is no
				// previous anchor either, write the empty string (chain restarts
				// from genesis).
				prev, perr := getAnchorHashTx(ctx, tx, ChainNameAccessLogs)
				if perr != nil {
					return perr
				}
				anchorHash = prev
			}
			if err := upsertAuditChainAnchorTx(ctx, tx, ChainNameAccessLogs, lastID.Int64, anchorHash); err != nil {
				return err
			}
			res.HighestID = lastID.Int64
			res.AnchorHash = anchorHash
			if firstID.Valid {
				res.LowestID = firstID.Int64
			}
		}
		return nil
	})
	if err != nil {
		return PruneResult{}, err
	}
	return res, nil
}

// getAnchorHashTx is a tx-scoped helper that returns the last_pruned_entry_hash
// for chainName, or "" if no row exists.
func getAnchorHashTx(ctx context.Context, tx *sql.Tx, chainName string) (string, error) {
	var hash string
	err := tx.QueryRowContext(ctx,
		`SELECT last_pruned_entry_hash FROM audit_chain_anchor WHERE chain_name = $1`,
		chainName).Scan(&hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", fmt.Errorf("failed to read existing anchor hash for %q: %w", chainName, err)
	}
	return hash, nil
}

// CountAccessLogsTotal returns the total number of access_logs rows.
// Used by the FIFO sweeper to decide whether to trim.
func (d *DB) CountAccessLogsTotal(ctx context.Context) (int64, error) {
	var n int64
	if err := d.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_logs`).Scan(&n); err != nil {
		return 0, fmt.Errorf("failed to count access_logs: %w", err)
	}
	return n, nil
}

// TrimAccessLogsFIFOBatch deletes the oldest rows from access_logs, capping
// the deletion at batchSize, until at most maxRows remain. It writes the
// chain anchor in the same transaction (highest id + its entry_hash among the
// rows being deleted in this batch). Returns the number of rows actually
// deleted in this call. Callers loop until 0 is returned to drain the backlog
// in batches.
func (d *DB) TrimAccessLogsFIFOBatch(ctx context.Context, maxRows int64, batchSize int) (PruneResult, error) {
	if maxRows < 0 {
		maxRows = 0
	}
	if batchSize <= 0 {
		batchSize = 1000
	}

	var res PruneResult
	err := d.WithTx(ctx, func(wtx *Tx) error {
		tx := wtx.tx

		var total int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM access_logs`).Scan(&total); err != nil {
			return fmt.Errorf("failed to count access_logs in trim: %w", err)
		}
		excess := total - maxRows
		if excess <= 0 {
			return nil
		}
		toDelete := excess
		if toDelete > int64(batchSize) {
			toDelete = int64(batchSize)
		}

		// Capture the lowest id about to be deleted in this batch — surfaced in
		// PruneResult so the retention manager can record the deleted range.
		var firstID sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT id FROM access_logs ORDER BY id ASC LIMIT 1`).Scan(&firstID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return fmt.Errorf("failed to read FIFO lowest id: %w", err)
		}

		// Identify the highest id among the oldest `toDelete` rows. We delete by
		// id range (id <= cutId) inside the same transaction.
		var cutID sql.NullInt64
		var cutHash sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT id, entry_hash FROM access_logs
			ORDER BY id ASC
			LIMIT 1 OFFSET $1`, toDelete-1).Scan(&cutID, &cutHash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// Race: rows disappeared between the COUNT and the OFFSET probe.
				return nil
			}
			return fmt.Errorf("failed to read FIFO cut: %w", err)
		}

		result, err := tx.ExecContext(ctx, `DELETE FROM access_logs WHERE id <= $1`, cutID.Int64)
		if err != nil {
			return fmt.Errorf("failed to trim access_logs: %w", err)
		}
		deleted, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to count trimmed rows: %w", err)
		}

		res = PruneResult{Deleted: deleted}
		if deleted > 0 && cutID.Valid {
			anchorHash := cutHash.String
			if !cutHash.Valid || anchorHash == "" {
				prev, perr := getAnchorHashTx(ctx, tx, ChainNameAccessLogs)
				if perr != nil {
					return perr
				}
				anchorHash = prev
			}
			if err := upsertAuditChainAnchorTx(ctx, tx, ChainNameAccessLogs, cutID.Int64, anchorHash); err != nil {
				return err
			}
			res.HighestID = cutID.Int64
			res.AnchorHash = anchorHash
			if firstID.Valid {
				res.LowestID = firstID.Int64
			}
		}
		return nil
	})
	if err != nil {
		return PruneResult{}, err
	}
	return res, nil
}

// CleanupComplianceLogs deletes compliance log entries older than the given time.
func (d *DB) CleanupComplianceLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := d.conn.ExecContext(ctx, `DELETE FROM compliance_logs WHERE created_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup compliance logs: %w", err)
	}
	return result.RowsAffected()
}

// CleanupRBACAuditLogs deletes RBAC audit log entries older than the given time.
func (d *DB) CleanupRBACAuditLogs(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := d.conn.ExecContext(ctx, `DELETE FROM rbac_audit_log WHERE created_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup RBAC audit logs: %w", err)
	}
	return result.RowsAffected()
}

// CleanupUsedTravelRecords deletes used travel rule records older than the given time.
// Only deletes records that have been used (used_at IS NOT NULL).
func (d *DB) CleanupUsedTravelRecords(ctx context.Context, olderThan time.Time) (int64, error) {
	result, err := d.conn.ExecContext(ctx,
		`DELETE FROM travel_rule_records WHERE used_at IS NOT NULL AND created_at < $1`, olderThan)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup used travel records: %w", err)
	}
	return result.RowsAffected()
}

// RefreshToken represents a refresh token in the database
type RefreshToken struct {
	TokenHash string
	Subject   string
	CreatedAt string
	ExpiresAt string
	Revoked   bool
	RevokedAt *string
}

// SaveRefreshToken saves a refresh token to the database
func (d *DB) SaveRefreshToken(ctx context.Context, tokenHash, subject string, expiresAt time.Time) error {
	query := `INSERT INTO refresh_tokens (token_hash, subject, expires_at)
	          VALUES ($1, $2, $3)
	          ON CONFLICT(token_hash) DO UPDATE SET
	          expires_at = excluded.expires_at,
	          revoked = false,
	          revoked_at = NULL`

	// expires_at is a plain TIMESTAMP; store UTC so the wall-clock pgx writes
	// matches the UTC session used for comparisons (RD-1005).
	_, err := d.conn.ExecContext(ctx, query, tokenHash, subject, expiresAt.UTC())
	return err
}

// GetRefreshToken retrieves a refresh token by hash
func (d *DB) GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	query := `SELECT token_hash, subject, created_at, expires_at, revoked, revoked_at
	          FROM refresh_tokens WHERE token_hash = $1`

	var token RefreshToken
	var revokedAt sql.NullString

	err := d.conn.QueryRowContext(ctx, query, tokenHash).Scan(
		&token.TokenHash,
		&token.Subject,
		&token.CreatedAt,
		&token.ExpiresAt,
		&token.Revoked,
		&revokedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token: %w", err)
	}

	if revokedAt.Valid {
		revokedAtStr := revokedAt.String
		token.RevokedAt = &revokedAtStr
	}

	return &token, nil
}

// RevokeRefreshToken marks a refresh token as revoked
func (d *DB) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	query := `UPDATE refresh_tokens
	          SET revoked = true, revoked_at = CURRENT_TIMESTAMP
	          WHERE token_hash = $1`

	_, err := d.conn.ExecContext(ctx, query, tokenHash)
	return err
}

// RevokeRefreshTokensBySubject revokes all active refresh tokens for a given subject.
// Used when banning a user to force immediate session termination.
func (d *DB) RevokeRefreshTokensBySubject(ctx context.Context, subject string) (int64, error) {
	query := `UPDATE refresh_tokens
	          SET revoked = true, revoked_at = CURRENT_TIMESTAMP
	          WHERE subject = $1 AND revoked = false`

	result, err := d.conn.ExecContext(ctx, query, subject)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// RevokeAccessToken stores a revoked access token (for blacklist checking)
func (d *DB) RevokeAccessToken(ctx context.Context, tokenID, subject string, expiresAt time.Time) error {
	query := `INSERT INTO revoked_tokens (token_id, subject, expires_at)
	          VALUES ($1, $2, $3)
	          ON CONFLICT(token_id) DO NOTHING`

	// expires_at is a plain TIMESTAMP; store UTC so it stays consistent with
	// the UTC session and the UTC cleanup comparison (RD-1005).
	_, err := d.conn.ExecContext(ctx, query, tokenID, subject, expiresAt.UTC())
	return err
}

// IsAccessTokenRevoked checks if an access token is revoked
func (d *DB) IsAccessTokenRevoked(ctx context.Context, tokenID string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE token_id = $1)`

	var exists bool
	err := d.conn.QueryRowContext(ctx, query, tokenID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check revoked token: %w", err)
	}

	return exists, nil
}

// IsUserBannedBySubject reports whether the user identified by subject
// (DID / JWT subject claim) is banned. Used by OptionalJWTAuthMiddleware
// (security audit L5) to fail-closed at the auth boundary rather than
// relying on every downstream consumer to call CheckAccess.
//
// Returns (false, nil) for "no such user" so we don't leak account
// existence to the caller via timing.
func (d *DB) IsUserBannedBySubject(ctx context.Context, subject string) (bool, error) {
	const query = `SELECT banned FROM users WHERE external_id = $1 LIMIT 1`
	var banned bool
	err := d.conn.QueryRowContext(ctx, query, subject).Scan(&banned)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("failed to check banned status: %w", err)
	}
	return banned, nil
}

// CleanupExpiredTokens removes expired tokens from the database
func (d *DB) CleanupExpiredTokens(ctx context.Context) error {
	// Use current time from Go (UTC) to ensure consistency with how tokens are
	// stored. UTC matters for the plain TIMESTAMP column — see RD-1005.
	now := time.Now().UTC()

	// Clean up expired refresh tokens
	_, err := d.conn.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired refresh tokens: %w", err)
	}

	// Clean up expired revoked tokens
	_, err = d.conn.ExecContext(ctx, `DELETE FROM revoked_tokens WHERE expires_at < $1`, now)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired revoked tokens: %w", err)
	}

	return nil
}

// EthAddressLink represents a link between an Ethereum address and a DID
type EthAddressLink struct {
	ID            int     `json:"id"`
	DID           string  `json:"did"`
	EthAddress    string  `json:"eth_address"`
	Signature     string  `json:"signature"`
	MessageHash   string  `json:"message_hash"`
	VerifiedAt    string  `json:"verified_at"`
	Revoked       bool    `json:"revoked"`
	RevokedAt     *string `json:"revoked_at,omitempty"`
	ENSName       *string `json:"ens_name,omitempty"`
	ENSResolvedAt *string `json:"ens_resolved_at,omitempty"`
	LinkType      string  `json:"link_type"`
}

// LinkEthAddress creates a new user-initiated link between an ETH address and a DID.
// If the (did, eth_address) pair already exists and is not revoked, it refreshes the signature
// and upgrades a system link to a user link.
// If the (did, eth_address) pair exists but is revoked, it returns ErrAddressLinkRevoked.
func (d *DB) LinkEthAddress(ctx context.Context, did, ethAddress, signature, messageHash string) error {
	query := `INSERT INTO eth_address_links (did, eth_address, signature, message_hash, link_type)
	          VALUES ($1, $2, $3, $4, 'user')
	          ON CONFLICT (did, eth_address) DO UPDATE SET
	          signature = excluded.signature,
	          message_hash = excluded.message_hash,
	          link_type = 'user',
	          verified_at = CURRENT_TIMESTAMP,
	          ens_name = NULL,
	          ens_resolved_at = NULL
	          WHERE eth_address_links.revoked = false`

	result, err := d.conn.ExecContext(ctx, query, did, ethAddress, signature, messageHash)
	if err != nil {
		return fmt.Errorf("failed to link ETH address: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check link result: %w", err)
	}
	if rowsAffected == 0 {
		// The (did, eth_address) pair exists but is revoked.
		return ErrAddressLinkRevoked
	}
	return nil
}

// isValidEthAddress returns true for 0x-prefixed 40-hex-character addresses.
func isValidEthAddress(address string) bool {
	if len(address) != 42 {
		return false
	}
	if address[0] != '0' || (address[1] != 'x' && address[1] != 'X') {
		return false
	}
	for _, c := range address[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// SystemLinkEthAddress records a system-level address→DID link when a user submits
// a transaction through the proxy. Unlike user-initiated links there is no signature.
// If the (did, eth_address) pair already exists (any link_type), this is a no-op.
func (d *DB) SystemLinkEthAddress(ctx context.Context, did, ethAddress string) error {
	if did == "" || ethAddress == "" {
		return nil
	}
	if !isValidEthAddress(ethAddress) {
		return fmt.Errorf("invalid ethereum address: %q", ethAddress)
	}
	_, err := d.conn.ExecContext(ctx, `
		INSERT INTO eth_address_links (did, eth_address, link_type)
		VALUES ($1, $2, 'system')
		ON CONFLICT (did, eth_address) DO NOTHING`,
		did, strings.ToLower(ethAddress),
	)
	return err
}

// GetAllLinkedEOAAddresses returns all active ETH addresses linked to any user DID.
// Used for bulk visibility filtering to identify which addresses belong to users.
func (d *DB) GetAllLinkedEOAAddresses(ctx context.Context) ([]string, error) {
	query := `SELECT DISTINCT LOWER(eth_address) FROM eth_address_links WHERE revoked = false`
	rows, err := d.conn.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to get all linked EOAs: %w", err)
	}
	defer rows.Close()

	var addrs []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		addrs = append(addrs, addr)
	}
	return addrs, rows.Err()
}

// GetEthAddressesByDID retrieves all ETH addresses linked to a DID
func (d *DB) GetEthAddressesByDID(ctx context.Context, did string) ([]*EthAddressLink, error) {
	query := `SELECT id, did, eth_address, signature, message_hash, verified_at, revoked, revoked_at, ens_name, ens_resolved_at, link_type
	          FROM eth_address_links
	          WHERE did = $1 AND revoked = false
	          ORDER BY verified_at DESC`

	rows, err := d.conn.QueryContext(ctx, query, did)
	if err != nil {
		return nil, fmt.Errorf("failed to get ETH addresses: %w", err)
	}
	defer rows.Close()

	links := make([]*EthAddressLink, 0)
	for rows.Next() {
		var link EthAddressLink
		var signature, messageHash, revokedAt, ensName, ensResolvedAt sql.NullString

		if err := rows.Scan(
			&link.ID,
			&link.DID,
			&link.EthAddress,
			&signature,
			&messageHash,
			&link.VerifiedAt,
			&link.Revoked,
			&revokedAt,
			&ensName,
			&ensResolvedAt,
			&link.LinkType,
		); err != nil {
			return nil, fmt.Errorf("failed to scan ETH address link: %w", err)
		}

		if signature.Valid {
			link.Signature = signature.String
		}
		if messageHash.Valid {
			link.MessageHash = messageHash.String
		}
		if revokedAt.Valid {
			link.RevokedAt = &revokedAt.String
		}
		if ensName.Valid {
			link.ENSName = &ensName.String
		}
		if ensResolvedAt.Valid {
			link.ENSResolvedAt = &ensResolvedAt.String
		}
		links = append(links, &link)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate ETH address links: %w", err)
	}

	return links, nil
}

// GetDIDByEthAddress retrieves the DID linked to an ETH address.
// With multiple DIDs per address now possible, prefers user-linked over system-linked,
// most recent first.
func (d *DB) GetDIDByEthAddress(ctx context.Context, ethAddress string) (string, error) {
	query := `SELECT did FROM eth_address_links
	          WHERE eth_address = $1 AND revoked = false
	          ORDER BY CASE WHEN link_type = 'user' THEN 0 ELSE 1 END, verified_at DESC
	          LIMIT 1`

	var did string
	err := d.conn.QueryRowContext(ctx, query, ethAddress).Scan(&did)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("failed to get DID by ETH address: %w", err)
	}
	return did, nil
}

// GetDIDsByEthAddress returns all non-revoked DIDs linked to an ETH address.
// Used for collision detection (same address claimed by multiple identities).
func (d *DB) GetDIDsByEthAddress(ctx context.Context, ethAddress string) ([]string, error) {
	rows, err := d.conn.QueryContext(ctx,
		`SELECT did FROM eth_address_links
		 WHERE eth_address = $1 AND revoked = false
		 ORDER BY CASE WHEN link_type = 'user' THEN 0 ELSE 1 END, verified_at DESC`,
		strings.ToLower(ethAddress),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get DIDs by ETH address: %w", err)
	}
	defer rows.Close()
	var dids []string
	for rows.Next() {
		var did string
		if err := rows.Scan(&did); err != nil {
			return nil, fmt.Errorf("failed to scan DID: %w", err)
		}
		dids = append(dids, did)
	}
	return dids, rows.Err()
}

// AddressLinkCollision represents an ETH address claimed by more than one DID.
type AddressLinkCollision struct {
	EthAddress string   `json:"eth_address"`
	DIDs       []string `json:"dids"`
	LinkTypes  []string `json:"link_types"`
}

// GetAddressLinkCollisions returns all ETH addresses that are linked to more
// than one non-revoked DID. Used by the admin dashboard to surface potential
// key-sharing or key-compromise events.
func (d *DB) GetAddressLinkCollisions(ctx context.Context) ([]*AddressLinkCollision, error) {
	rows, err := d.conn.QueryContext(ctx, `
		SELECT eth_address, did, link_type
		FROM eth_address_links
		WHERE revoked = false
		  AND eth_address IN (
		      SELECT eth_address FROM eth_address_links
		      WHERE revoked = false
		      GROUP BY eth_address HAVING COUNT(DISTINCT did) > 1
		  )
		ORDER BY eth_address, CASE WHEN link_type = 'user' THEN 0 ELSE 1 END, verified_at DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to query address collisions: %w", err)
	}
	defer rows.Close()

	byAddr := make(map[string]*AddressLinkCollision)
	var order []string
	for rows.Next() {
		var addr, did, linkType string
		if err := rows.Scan(&addr, &did, &linkType); err != nil {
			return nil, fmt.Errorf("failed to scan collision row: %w", err)
		}
		if _, ok := byAddr[addr]; !ok {
			byAddr[addr] = &AddressLinkCollision{EthAddress: addr}
			order = append(order, addr)
		}
		byAddr[addr].DIDs = append(byAddr[addr].DIDs, did)
		byAddr[addr].LinkTypes = append(byAddr[addr].LinkTypes, linkType)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	result := make([]*AddressLinkCollision, 0, len(order))
	for _, addr := range order {
		result = append(result, byAddr[addr])
	}
	return result, nil
}

// RevokeEthAddressLink revokes a link between an ETH address and a DID
// Only the DID owner can revoke their own links
func (d *DB) RevokeEthAddressLink(ctx context.Context, did, ethAddress string) error {
	query := `UPDATE eth_address_links
	          SET revoked = true, revoked_at = CURRENT_TIMESTAMP
	          WHERE did = $1 AND eth_address = $2`

	result, err := d.conn.ExecContext(ctx, query, did, ethAddress)
	if err != nil {
		return fmt.Errorf("failed to revoke ETH address link: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("no matching link found")
	}

	return nil
}

// UpdateENSName updates the ENS name for an ETH address
func (d *DB) UpdateENSName(ctx context.Context, ethAddress string, ensName *string) error {
	query := `UPDATE eth_address_links
	          SET ens_name = $2, ens_resolved_at = CURRENT_TIMESTAMP
	          WHERE eth_address = $1 AND revoked = false`

	_, err := d.conn.ExecContext(ctx, query, ethAddress, ensName)
	if err != nil {
		return fmt.Errorf("failed to update ENS name: %w", err)
	}
	return nil
}

// GetEthAddressLink retrieves a specific ETH address link.
// With multiple DIDs per address now possible, returns the best match
// (user-linked preferred over system-linked, most recent first).
func (d *DB) GetEthAddressLink(ctx context.Context, ethAddress string) (*EthAddressLink, error) {
	query := `SELECT id, did, eth_address, signature, message_hash, verified_at, revoked, revoked_at, ens_name, ens_resolved_at, link_type
	          FROM eth_address_links
	          WHERE eth_address = $1 AND revoked = false
	          ORDER BY CASE WHEN link_type = 'user' THEN 0 ELSE 1 END, verified_at DESC
	          LIMIT 1`

	var link EthAddressLink
	var signature, messageHash, revokedAt, ensName, ensResolvedAt sql.NullString

	err := d.conn.QueryRowContext(ctx, query, ethAddress).Scan(
		&link.ID,
		&link.DID,
		&link.EthAddress,
		&signature,
		&messageHash,
		&link.VerifiedAt,
		&link.Revoked,
		&revokedAt,
		&ensName,
		&ensResolvedAt,
		&link.LinkType,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ETH address link: %w", err)
	}

	if signature.Valid {
		link.Signature = signature.String
	}
	if messageHash.Valid {
		link.MessageHash = messageHash.String
	}
	if revokedAt.Valid {
		link.RevokedAt = &revokedAt.String
	}
	if ensName.Valid {
		link.ENSName = &ensName.String
	}
	if ensResolvedAt.Valid {
		link.ENSResolvedAt = &ensResolvedAt.String
	}

	return &link, nil
}

// GetEthAddressLinkForDID retrieves the ETH address link for a specific (did, eth_address) pair.
// Unlike GetEthAddressLink, this is scoped to a single DID and is not affected by
// multiple DIDs sharing the same address.
func (d *DB) GetEthAddressLinkForDID(ctx context.Context, did, ethAddress string) (*EthAddressLink, error) {
	query := `SELECT id, did, eth_address, signature, message_hash, verified_at, revoked, revoked_at, ens_name, ens_resolved_at, link_type
	          FROM eth_address_links
	          WHERE did = $1 AND eth_address = $2 AND revoked = false
	          LIMIT 1`

	var link EthAddressLink
	var signature, messageHash, revokedAt, ensName, ensResolvedAt sql.NullString

	err := d.conn.QueryRowContext(ctx, query, did, ethAddress).Scan(
		&link.ID,
		&link.DID,
		&link.EthAddress,
		&signature,
		&messageHash,
		&link.VerifiedAt,
		&link.Revoked,
		&revokedAt,
		&ensName,
		&ensResolvedAt,
		&link.LinkType,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get ETH address link for DID: %w", err)
	}

	if signature.Valid {
		link.Signature = signature.String
	}
	if messageHash.Valid {
		link.MessageHash = messageHash.String
	}
	if revokedAt.Valid {
		link.RevokedAt = &revokedAt.String
	}
	if ensName.Valid {
		link.ENSName = &ensName.String
	}
	if ensResolvedAt.Valid {
		link.ENSResolvedAt = &ensResolvedAt.String
	}

	return &link, nil
}
