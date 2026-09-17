package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"privacy-proxy/internal/policydsl"
)

// One probe per TTL, shared by every reader; a changed compiler path re-probes.
func TestCompilerProbeSharesOneProbePerTTL(t *testing.T) {
	dir := t.TempDir()
	counter := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "solc")
	require.NoError(t, os.WriteFile(fake, []byte("#!/bin/sh\necho x >> "+counter+"\necho 'Version: "+policydsl.SolidityVersion+"+commit.test'\n"), 0o755))
	calls := func() int {
		raw, err := os.ReadFile(counter)
		if os.IsNotExist(err) {
			return 0
		}
		require.NoError(t, err)
		return strings.Count(string(raw), "x")
	}

	var probe compilerProbe
	compiler := &policydsl.Compiler{Path: fake}
	start := time.Now()
	require.True(t, probe.check(context.Background(), compiler, start))
	require.True(t, probe.check(context.Background(), compiler, start.Add(compilerProbeTTL/2)))
	require.Equal(t, 1, calls(), "the second reader within the TTL shares the first probe")

	require.True(t, probe.check(context.Background(), compiler, start.Add(compilerProbeTTL+time.Second)))
	require.Equal(t, 2, calls(), "an expired entry is probed again")

	missing := &policydsl.Compiler{Path: filepath.Join(dir, "missing-solc")}
	require.False(t, probe.check(context.Background(), missing, start.Add(compilerProbeTTL+time.Second)))
	require.Equal(t, 2, calls(), "a changed path is probed on its own, not served from the old entry")
}
