package rbac_test

// DB-backed benchmark for the permission-compute cache-miss path (RD-1263).
// Lives in the external test package so it can import internal/db (which
// itself implements rbac.Store) without creating an import cycle.
//
// Run with:
//
//	go test ./internal/rbac/ -bench BenchmarkResolvePermissionsCacheMiss -benchtime 20x -run '^$'
//
// Requires Docker (testcontainers) unless E2E_DATABASE_URL points at a
// harness-owned PostgreSQL.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"privacy-proxy/internal/db"
	"privacy-proxy/internal/rbac"
)

const (
	benchGroups         = 50
	benchGrantsPerGroup = 3
)

func startBenchPostgres(b *testing.B) string {
	b.Helper()
	ctx := context.Background()

	container, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("benchdb"),
		postgres.WithUsername("benchuser"),
		postgres.WithPassword("benchpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		b.Fatalf("failed to start PostgreSQL testcontainer (Docker required): %v", err)
	}
	b.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			b.Logf("failed to terminate container: %v", err)
		}
	})

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		b.Fatalf("failed to get connection string: %v", err)
	}
	return connStr
}

// seedBenchOrg creates one org with benchGroups groups; the user is a member
// of every group, each group has an access row and benchGrantsPerGroup
// contract grants — the worst-case flat-path fan-out shape.
func seedBenchOrg(b *testing.B, database *db.DB) (userID, orgID string) {
	b.Helper()
	ctx := context.Background()

	org := &rbac.Organization{
		ID:       uuid.New().String(),
		Slug:     "bench-org",
		Name:     "Bench Org",
		Settings: map[string]interface{}{},
	}
	if err := database.CreateOrganization(ctx, org); err != nil {
		b.Fatalf("create org: %v", err)
	}

	user := &rbac.User{
		ID:         uuid.New().String(),
		ExternalID: "did:test:bench-user",
		KYC:        true,
	}
	if err := database.CreateUser(ctx, user); err != nil {
		b.Fatalf("create user: %v", err)
	}

	for i := 0; i < benchGroups; i++ {
		group := &rbac.Group{
			ID:    uuid.New().String(),
			OrgID: org.ID,
			Slug:  fmt.Sprintf("bench-group-%03d", i),
			Name:  fmt.Sprintf("Bench Group %03d", i),
		}
		if err := database.CreateGroup(ctx, group); err != nil {
			b.Fatalf("create group %d: %v", i, err)
		}
		access := &rbac.GroupAccess{
			ID:             uuid.New().String(),
			GroupID:        group.ID,
			AllowedMethods: []string{"eth_call", fmt.Sprintf("bench_method_%03d", i)},
			Claims:         []rbac.Claim{rbac.ClaimDeploy},
		}
		if err := database.CreateGroupAccess(ctx, access); err != nil {
			b.Fatalf("create group access %d: %v", i, err)
		}
		membership := &rbac.UserMembership{
			ID:      uuid.New().String(),
			UserID:  user.ID,
			GroupID: group.ID,
			Source:  rbac.MembershipSourceAdmin,
		}
		if err := database.CreateMembership(ctx, membership); err != nil {
			b.Fatalf("create membership %d: %v", i, err)
		}
		for j := 0; j < benchGrantsPerGroup; j++ {
			contract := &rbac.Contract{
				ID:       uuid.New().String(),
				OrgID:    org.ID,
				Address:  fmt.Sprintf("0x%040x", i*benchGrantsPerGroup+j+1),
				Name:     fmt.Sprintf("Bench Contract %03d-%d", i, j),
				Metadata: map[string]interface{}{},
			}
			if err := database.CreateContract(ctx, contract); err != nil {
				b.Fatalf("create contract %d-%d: %v", i, j, err)
			}
			grant := &rbac.ContractGrant{
				ID:         uuid.New().String(),
				ContractID: contract.ID,
				GroupID:    group.ID,
			}
			if err := database.CreateContractGrant(ctx, grant); err != nil {
				b.Fatalf("create grant %d-%d: %v", i, j, err)
			}
		}
	}
	return user.ID, org.ID
}

// BenchmarkResolvePermissionsCacheMiss measures a full cache-miss resolution
// against real PostgreSQL for a user in benchGroups groups. The cache is
// invalidated every iteration so each pass exercises the compute path.
func BenchmarkResolvePermissionsCacheMiss(b *testing.B) {
	connStr := startBenchPostgres(b)
	database, err := db.New(connStr)
	if err != nil {
		b.Fatalf("db.New: %v", err)
	}
	b.Cleanup(func() { database.Close() })

	userID, orgID := seedBenchOrg(b, database)
	resolver := rbac.NewResolver(database, 5*time.Minute)
	ctx := context.Background()

	// Warm-up + sanity: the resolved permissions must actually contain the
	// seeded grants, otherwise the benchmark measures the wrong thing.
	perms, err := resolver.ResolvePermissions(ctx, userID, orgID)
	if err != nil {
		b.Fatalf("warm-up resolve: %v", err)
	}
	if want := benchGroups * benchGrantsPerGroup; len(perms.ContractAccess) != want {
		b.Fatalf("warm-up resolve returned %d contracts; want %d", len(perms.ContractAccess), want)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := database.InvalidateCacheForUser(ctx, userID); err != nil {
			b.Fatalf("invalidate: %v", err)
		}
		if _, err := resolver.ResolvePermissions(ctx, userID, orgID); err != nil {
			b.Fatalf("resolve: %v", err)
		}
	}
}
