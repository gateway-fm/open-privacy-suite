package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"privacy-proxy/internal/crypto"
)

// runReencryptRPCKeys implements `privacy-cli reencrypt-rpc-keys` (RD-1164).
//
// The only value encrypted at rest is group_access.rpc_api_key. Rotating
// RPC_API_KEY_ENCRYPTION_KEY orphans every existing ciphertext, so operators
// need to decrypt each row with the OLD key and re-encrypt it with the NEW key.
// This subcommand does exactly that, one row at a time, and is safe to re-run:
//   - A row that already matches the new key produces identical ciphertext
//     (short-circuited as skipped-unchanged... except AES-GCM uses a random
//     nonce, so a re-encrypt normally differs; see the loop for the exact rule).
//   - A versioned value that fails to authenticate under --old-key is treated as
//     already-migrated (or corrupt) and SKIPPED with a warning — it is never
//     written, so a wrong --old-key cannot destroy data.
//
// The CLI reads env directly (like audit.go) rather than importing
// internal/config, which panics on prod-required vars.
func runReencryptRPCKeys(args []string) {
	fs := flag.NewFlagSet("reencrypt-rpc-keys", flag.ExitOnError)
	databaseURL := fs.String("database-url", "",
		"Postgres connection string. Falls back to DATABASE_URL env var. Connect with a credential allowed to UPDATE group_access.")
	oldKeyHex := fs.String("old-key", "",
		"Current encryption key as hex. Falls back to RPC_API_KEY_ENCRYPTION_KEY env var. Empty means existing values are plaintext (encryption was disabled).")
	newKeyHex := fs.String("new-key", "",
		"New encryption key as hex (REQUIRED). Must decode to exactly 32 bytes (AES-256).")
	dryRun := fs.Bool("dry-run", false,
		"Report what would change without writing any rows.")
	fs.Parse(args)

	dsn := *databaseURL
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		fmt.Fprintln(os.Stderr, "missing --database-url (or DATABASE_URL env)")
		os.Exit(2)
	}

	oldHex := *oldKeyHex
	if oldHex == "" {
		oldHex = os.Getenv("RPC_API_KEY_ENCRYPTION_KEY")
	}

	// Old key may be empty: that means current values are plaintext, and
	// crypto.Decrypt returns them unchanged. A non-empty key must be valid hex.
	var oldKey []byte
	if oldHex != "" {
		decoded, err := hex.DecodeString(oldHex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --old-key: not valid hex: %v\n", err)
			os.Exit(2)
		}
		oldKey = decoded
	}

	// New key is required and must be exactly 32 bytes after hex-decoding.
	if *newKeyHex == "" {
		fmt.Fprintln(os.Stderr, "missing --new-key (required, hex-encoded 32-byte AES-256 key)")
		os.Exit(2)
	}
	newKey, err := hex.DecodeString(*newKeyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --new-key: not valid hex: %v\n", err)
		os.Exit(2)
	}
	if len(newKey) != 32 {
		fmt.Fprintf(os.Stderr, "invalid --new-key: must be 32 bytes (AES-256), got %d\n", len(newKey))
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()
	if err := conn.PingContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ping database: %v\n", err)
		os.Exit(1)
	}

	// Declared credentials (rpc_api_key_source set by a reviewed groups
	// document) are skipped: the projection barrier refuses key-only writes
	// to them, and the next activation of the stream re-encrypts them under
	// the key the server runs with.
	rows, err := conn.QueryContext(ctx,
		`SELECT id, rpc_api_key FROM group_access WHERE rpc_api_key IS NOT NULL AND rpc_api_key <> '' AND rpc_api_key_source IS NULL`)
	if err != nil {
		fmt.Fprintf(os.Stderr, "query group_access: %v\n", err)
		os.Exit(1)
	}

	// Collect rows first so we don't hold the SELECT cursor open while issuing
	// UPDATEs on the same connection.
	type keyRow struct {
		id     string
		stored string
	}
	var toProcess []keyRow
	for rows.Next() {
		var r keyRow
		if err := rows.Scan(&r.id, &r.stored); err != nil {
			rows.Close()
			fmt.Fprintf(os.Stderr, "scan row: %v\n", err)
			os.Exit(1)
		}
		toProcess = append(toProcess, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		fmt.Fprintf(os.Stderr, "iterate rows: %v\n", err)
		os.Exit(1)
	}
	rows.Close()

	var (
		scanned          int
		reencrypted      int
		skippedUnchanged int
		skippedErrors    int
	)

	for _, r := range toProcess {
		scanned++

		// Determine the plaintext to re-encrypt, fail-CLOSED (Copilot + mandrigin
		// review). Two modes, by whether an old key was supplied:
		//   - Empty --old-key: the operator asserts values are plaintext
		//     (encryption was off). Refuse to touch anything already in the
		//     versioned ciphertext form (crypto.IsEncrypted) — re-encrypting it
		//     would double-encrypt. Otherwise treat the value as plaintext.
		//   - Non-empty --old-key: the value MUST authenticate under it. Use a
		//     STRICT decrypt (never fail-open): a wrong key — or a legacy
		//     unversioned ciphertext that does not authenticate — errors and is
		//     SKIPPED, rather than being returned verbatim (as fail-open Decrypt
		//     would) and re-encrypted, which would irreversibly double-encrypt
		//     legacy ciphertext. Works for both versioned (encv1:) and legacy
		//     unversioned base64(nonce||ciphertext) values.
		var plain string
		if len(oldKey) == 0 {
			if crypto.IsEncrypted(r.stored) {
				fmt.Fprintf(os.Stderr, "WARNING: group %s: value is already encrypted (encv1:) but no --old-key was supplied; skipping to avoid double-encryption — pass the current key via --old-key or RPC_API_KEY_ENCRYPTION_KEY\n", r.id)
				skippedErrors++
				continue
			}
			plain = r.stored // asserted plaintext (encryption was disabled)
		} else {
			p, err := crypto.DecryptStrict(r.stored, oldKey)
			if err != nil {
				fmt.Fprintf(os.Stderr, "WARNING: group %s: value does not authenticate under --old-key (%v); skipping — a wrong old key or a non-ciphertext value is left untouched to avoid corruption\n", r.id, err)
				skippedErrors++
				continue
			}
			plain = p
		}

		reenc, err := crypto.Encrypt(plain, newKey)
		if err != nil {
			// Encryption under the new key should not fail once the key is
			// validated as 32 bytes; treat as an error and skip.
			fmt.Fprintf(os.Stderr, "WARNING: group %s: re-encrypt with new key failed (%v); skipping\n", r.id, err)
			skippedErrors++
			continue
		}

		if reenc == r.stored {
			// No change needed. (AES-GCM's random nonce normally makes reenc
			// differ from the stored value, so this mostly covers the empty-key
			// / plaintext-unchanged case.)
			skippedUnchanged++
			continue
		}

		if *dryRun {
			reencrypted++
			continue
		}

		if _, err := conn.ExecContext(ctx,
			`UPDATE group_access SET rpc_api_key = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`,
			reenc, r.id); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: group %s: update failed (%v); skipping\n", r.id, err)
			skippedErrors++
			continue
		}
		reencrypted++
	}

	verb := "re-encrypted"
	if *dryRun {
		verb = "would-re-encrypt"
	}
	fmt.Printf("reencrypt-rpc-keys: scanned=%d %s=%d skipped-unchanged=%d skipped-errors=%d\n",
		scanned, verb, reencrypted, skippedUnchanged, skippedErrors)

	if skippedErrors > 0 {
		os.Exit(1)
	}
}
