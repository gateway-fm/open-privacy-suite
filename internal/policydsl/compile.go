package policydsl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
)

// buildTimeout bounds a compiler invocation. Compilation happens when a policy
// is prepared, never while a request is being served, so this is generous.
const buildTimeout = 60 * time.Second

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
