package server

import (
	"context"
	"sync"
	"time"

	"privacy-proxy/internal/apimodels"
	"privacy-proxy/internal/configuration"
	"privacy-proxy/internal/policydsl"
)

// compilerProbeTimeout bounds the `solc --version` probe behind the compiler
// capability. A hung compiler must not hang an admin read.
const compilerProbeTimeout = 5 * time.Second

// compilerProbeTTL is how long one probe result is shared. Every context read
// reports the capability, the admin group has no request limiter, and each
// probe forks a process, so concurrent readers must not each start one.
const compilerProbeTTL = 30 * time.Second

// compilerProbe memoizes the pinned-compiler availability check for
// compilerProbeTTL. Readers arriving during a probe wait for it instead of
// starting their own; a changed compiler path invalidates the entry.
type compilerProbe struct {
	mu        sync.Mutex
	path      string
	checkedAt time.Time
	available bool
}

func (p *compilerProbe) check(ctx context.Context, compiler *policydsl.Compiler, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.path == compiler.Path && !p.checkedAt.IsZero() && now.Sub(p.checkedAt) < compilerProbeTTL {
		return p.available
	}
	ctx, cancel := context.WithTimeout(ctx, compilerProbeTimeout)
	defer cancel()
	p.path, p.checkedAt, p.available = compiler.Path, now, compiler.Available(ctx) == nil
	return p.available
}

// configurationCapabilities describes the configuration API for a headless
// client. Everything except the compiler probe is static; the probe runs the
// pinned compiler's version check so the answer reflects this process now, not
// the build that produced it (the ARM image ships without solc, for example).
func (s *Server) configurationCapabilities(ctx context.Context) apimodels.ConfigurationCapabilities {
	result := apimodels.ConfigurationCapabilities{
		APIVersion:       configuration.APIVersion,
		Kinds:            kindNames(configuration.OrganizationKinds()),
		HumanOnlyKinds:   kindNames(configuration.HumanAuthorKinds()),
		ApprovalModes:    configuration.ApprovalModes(),
		MaxDocumentBytes: configuration.MaxDocumentBytes,
		Compiler:         apimodels.ConfigurationCompiler{Version: policydsl.SolidityVersion},
	}
	if s.policyCompiler != nil {
		result.Compiler.Available = s.compilerProbe.check(ctx, s.policyCompiler, time.Now())
	}
	return result
}

func kindNames(kinds []configuration.Kind) []string {
	names := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		names = append(names, string(kind))
	}
	return names
}
