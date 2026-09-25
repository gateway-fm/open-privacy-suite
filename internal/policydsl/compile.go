package policydsl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Build settings are pinned, not ranged. An approved policy is approved as
// specific bytecode, and the same source under a different compiler or different
// optimiser settings is different bytecode.
const (
	// OptimizerRuns is the optimiser setting the artifact is built with.
	OptimizerRuns = 200
	// EVMVersion is the target the artifact is built for. It is chosen to be
	// executable by both this process and the node that will later run it.
	EVMVersion = "shanghai"
	// MaxRuntimeBytecode matches the signed fact protocol's policy size bound.
	// Reject before approval so one oversized policy cannot block publication
	// of the complete directory snapshot for every organization.
	MaxRuntimeBytecode = 24576
)

// buildTimeout bounds a compiler invocation. Compilation happens when a policy
// is prepared, never while a request is being served, so this is generous.
const buildTimeout = 60 * time.Second

// ArtifactSetBuildTimeout bounds compilation of the complete reviewed set.
// HTTP submission gives this work its own deadline: large sets legitimately
// take longer than the ordinary API write timeout.
const ArtifactSetBuildTimeout = 5 * time.Minute

// Artifact is a built policy: the source that was generated, the bytecode it
// produced, and everything needed to reproduce and review the pair.
//
// A reviewer approves this whole record. Nothing here is derived at runtime, so
// what was reviewed is exactly what runs.
type Artifact struct {
	// Source is the generated Solidity.
	Source string `json:"source"`
	// SourceDigest is the lowercase hex sha256 of Source.
	SourceDigest string `json:"source_digest"`

	// RuntimeBytecode is the deployed code, which is what an evaluator executes.
	RuntimeBytecode []byte `json:"runtime_bytecode"`
	// RuntimeDigest is the lowercase hex sha256 of RuntimeBytecode.
	RuntimeDigest string `json:"runtime_digest"`

	// CreationBytecode is the constructor output, kept for the case where the
	// artifact is ever deployed rather than executed directly.
	CreationBytecode []byte `json:"creation_bytecode"`

	// PolicyDigest is the lowercase hex sha256 of the canonical policy document
	// this was generated from, binding the artifact to its source of truth.
	PolicyDigest string `json:"policy_digest"`

	// Compiler records the exact build, so the artifact can be rebuilt and
	// compared rather than trusted.
	Compiler CompilerSettings `json:"compiler"`
}

// CompilerSettings is the pinned build configuration.
type CompilerSettings struct {
	Version       string `json:"version"`
	OptimizerRuns int    `json:"optimizer_runs"`
	EVMVersion    string `json:"evm_version"`
}

// Compiler builds generated Solidity into an artifact.
type Compiler struct {
	// Path is the solc executable. Empty means "solc" on PATH.
	Path string
}

// NewCompiler returns a compiler using the solc named by POLICY_SOLC, or solc on
// PATH when that is unset.
func NewCompiler() *Compiler {
	return &Compiler{Path: os.Getenv("POLICY_SOLC")}
}

func (c *Compiler) binary() string {
	if c.Path != "" {
		return c.Path
	}
	return "solc"
}

// Version returns the compiler's reported version string.
func (c *Compiler) Version(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, c.binary(), "--version").Output()
	if err != nil {
		return "", fmt.Errorf("policydsl: running %s --version: %w", c.binary(), err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Version: "); ok {
			return v, nil
		}
	}
	return "", fmt.Errorf("policydsl: %s --version did not report a version", c.binary())
}

// Available reports whether a usable, correctly pinned compiler is present.
// ErrPolicyTooLarge means the policy is valid but compiles to more code than a
// contract may hold. The author can act on it — split or simplify the policy —
// so callers must not report it as a server fault.
var ErrPolicyTooLarge = errors.New("policydsl: policy is too large to compile")

func (c *Compiler) Available(ctx context.Context) error {
	version, err := c.Version(ctx)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(version, SolidityVersion+"+") {
		return fmt.Errorf("policydsl: solc is %s, but policy artifacts are built with exactly %s; a different compiler produces different bytecode", version, SolidityVersion)
	}
	return nil
}

// solcOutput is the shape of solc's --combined-json result.
type solcOutput struct {
	Contracts map[string]struct {
		Bin        string `json:"bin"`
		BinRuntime string `json:"bin-runtime"`
	} `json:"contracts"`
}

// BuildPerGroup compiles one artifact per bound group.
//
// A frame is decided by the groups its signer belongs to, so an artifact that
// carries every group makes both its size and the per-frame check grow with
// the organisation rather than with the group being checked. Compiling each
// group on its own keeps a group's code the same whether the organisation has
// three groups or three hundred.
//
// Every artifact uses the pinned compiler. A partially built set is never
// returned, because publishing part of a policy would leave frames
// decided by rules nobody approved together.
func (c *Compiler) BuildPerGroup(ctx context.Context, v *Validated) (map[string]*Artifact, error) {
	if v == nil {
		return nil, fmt.Errorf("policydsl: no validated policy to compile")
	}
	ctx, cancel := context.WithTimeout(ctx, ArtifactSetBuildTimeout)
	defer cancel()
	if err := c.Available(ctx); err != nil {
		return nil, err
	}
	artifacts := make(map[string]*Artifact, len(v.byGroup))
	for _, group := range v.Groups() {
		artifact, err := c.Build(ctx, v.ForGroup(group))
		if err != nil {
			return nil, fmt.Errorf("group %s: %w", group, err)
		}
		artifacts[group] = artifact
	}
	return artifacts, nil
}

// Build generates Solidity from a validated policy and compiles it.
//
// The compiler is checked before use: a build that silently used a different
// solc would produce bytecode nobody reviewed.
func (c *Compiler) Build(ctx context.Context, v *Validated) (*Artifact, error) {
	if err := c.Available(ctx); err != nil {
		return nil, err
	}

	source, err := GenerateSolidity(v)
	if err != nil {
		return nil, err
	}

	dir, err := os.MkdirTemp("", "policydsl-build-")
	if err != nil {
		return nil, fmt.Errorf("policydsl: creating a build directory: %w", err)
	}
	defer os.RemoveAll(dir)

	path := filepath.Join(dir, ContractName+".sol")
	if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
		return nil, fmt.Errorf("policydsl: writing generated source: %w", err)
	}

	buildCtx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()

	cmd := exec.CommandContext(buildCtx, c.binary(),
		"--combined-json", "bin,bin-runtime",
		// Source-unit names are included in Solidity's bytecode metadata. Strip
		// the temporary build directory so identical source has identical bytes.
		"--base-path", dir,
		"--optimize", "--optimize-runs", fmt.Sprint(OptimizerRuns),
		"--evm-version", EVMVersion,
		path,
	)
	out, err := cmd.Output()
	if err != nil {
		detail := ""
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			detail = ": " + strings.TrimSpace(string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("policydsl: compiling the generated policy failed%s", detail)
	}

	var parsed solcOutput
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, fmt.Errorf("policydsl: could not read the compiler's output: %w", err)
	}

	var runtimeHex, creationHex string
	for name, contract := range parsed.Contracts {
		if strings.HasSuffix(name, ":"+ContractName) {
			runtimeHex, creationHex = contract.BinRuntime, contract.Bin
			break
		}
	}
	if runtimeHex == "" {
		return nil, fmt.Errorf("policydsl: the compiler produced no runtime bytecode for %s", ContractName)
	}

	runtimeCode, err := hex.DecodeString(runtimeHex)
	if err != nil {
		return nil, fmt.Errorf("policydsl: the compiler's runtime bytecode is not valid hex: %w", err)
	}
	if len(runtimeCode) > MaxRuntimeBytecode {
		return nil, fmt.Errorf("%w: %d bytes compiled, the limit is %d; split or simplify the policy", ErrPolicyTooLarge, len(runtimeCode), MaxRuntimeBytecode)
	}
	creationCode, err := hex.DecodeString(creationHex)
	if err != nil {
		return nil, fmt.Errorf("policydsl: the compiler's creation bytecode is not valid hex: %w", err)
	}

	policyDigest, err := CanonicalDigest(v.Policy())
	if err != nil {
		return nil, err
	}

	version, err := c.Version(ctx)
	if err != nil {
		return nil, err
	}

	sourceSum := sha256.Sum256([]byte(source))
	runtimeSum := sha256.Sum256(runtimeCode)

	return &Artifact{
		Source:           source,
		SourceDigest:     hex.EncodeToString(sourceSum[:]),
		RuntimeBytecode:  runtimeCode,
		RuntimeDigest:    hex.EncodeToString(runtimeSum[:]),
		CreationBytecode: creationCode,
		PolicyDigest:     policyDigest,
		Compiler: CompilerSettings{
			Version:       version,
			OptimizerRuns: OptimizerRuns,
			EVMVersion:    EVMVersion,
		},
	}, nil
}

// CanonicalDigest is the lowercase hex sha256 of a policy's canonical JSON.
//
// It identifies the document a reviewer approved, so that an artifact, an
// approval and a stored revision can all be shown to be about the same policy.
//
// It is taken over the normalised model rather than the submitted bytes, so two
// documents differing only in whitespace or key order share a digest and
// therefore compile to the same artifact. The consequence worth stating: this
// is not sha256 of the stored source text, and an operator checking the two
// against each other will find they differ.
func CanonicalDigest(p *Policy) (string, error) {
	encoded, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("policydsl: could not canonicalise the policy: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// asExitError unwraps an exec error, keeping the import surface small.
func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

// ABIDigest is the lowercase hex sha256 of a registered ABI's exact text.
//
// A rule pins this so that replacing a contract's ABI is detected rather than
// silently changing what the rule's selector and argument positions mean.
func ABIDigest(abiText string) string {
	sum := sha256.Sum256([]byte(abiText))
	return hex.EncodeToString(sum[:])
}
