// api-spec-postprocess applies schema corrections that the swag generator
// cannot express, directly after `swag init` in `make api-spec` (the CI
// drift gate re-runs the same pipeline, so a spec missing these patches
// fails CI).
//
// Today that is JSON-Schema nullability (RD-1201): `functions` on a contract
// grant is a deliberate tri-state — null means "all functions", [] means
// "none (events-only)", a non-empty array means "only these" — and the
// server really emits `functions: null`. swag v2 has no nullable struct tag,
// so the generated schema said `"type": "array"` and a generated client
// could reject a valid response. OpenAPI 3.1 expresses nullability as
// `"type": ["array", "null"]`.
//
// The tool fails loudly when a target schema/property disappears, so a model
// rename cannot silently drop a patch.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// nullableProperties lists properties whose declared type additionally
// admits JSON null. Keyed by component schema name.
var nullableProperties = map[string][]string{
	// Response model: ContractGrant.functions serializes nil as null ("all
	// functions") — distinguishable from [] ("no functions", events-only).
	"privacy-proxy_internal_rbac.ContractGrant": {"functions"},
	// Request models: an explicit null is how a client asks for "all
	// functions" (create) or clears the rules back to "all" (update).
	"internal_server.contractGrantCreateRequest": {"functions"},
	"internal_server.contractGrantUpdateRequest": {"functions"},
}

// subjectSchema is the policy-check subject, rewritten to mutually exclusive
// oneOf alternatives: exactly one of did or address is required. swag cannot
// express the either/or runtime contract from the two optional Go fields, so
// generated clients otherwise see both as optional and combinable.
const subjectSchema = "internal_server.policyCheckSubject"

var subjectOneOf = []any{
	map[string]any{
		"type":       "object",
		"properties": map[string]any{"did": map[string]any{"type": "string"}},
		"required":   []any{"did"},
	},
	map[string]any{
		"type":       "object",
		"properties": map[string]any{"address": map[string]any{"type": "string"}},
		"required":   []any{"address"},
	},
}

func main() {
	jsonPath := "internal/server/apispec/swagger.json"
	yamlPath := "internal/server/apispec/swagger.yaml"
	if err := patchJSON(jsonPath); err != nil {
		fmt.Fprintf(os.Stderr, "api-spec-postprocess: %s: %v\n", jsonPath, err)
		os.Exit(1)
	}
	if err := patchYAML(yamlPath); err != nil {
		fmt.Fprintf(os.Stderr, "api-spec-postprocess: %s: %v\n", yamlPath, err)
		os.Exit(1)
	}
	fmt.Printf("api-spec-postprocess: %d schema(s) made nullable, subject oneOf applied in %s + %s\n",
		len(nullableProperties), jsonPath, yamlPath)
}

func patchJSON(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return err
	}

	schemas, err := dig[map[string]any](doc, "components", "schemas")
	if err != nil {
		return err
	}
	for schemaName, props := range nullableProperties {
		schema, err := dig[map[string]any](schemas, schemaName)
		if err != nil {
			return err
		}
		properties, err := dig[map[string]any](schema, "properties")
		if err != nil {
			return fmt.Errorf("schema %q: %w", schemaName, err)
		}
		for _, propName := range props {
			prop, err := dig[map[string]any](properties, propName)
			if err != nil {
				return fmt.Errorf("schema %q: %w", schemaName, err)
			}
			typ, ok := prop["type"].(string)
			if !ok {
				// Already a list (idempotent re-run) is fine; anything else is not.
				if list, isList := prop["type"].([]any); isList && containsNull(list) {
					continue
				}
				return fmt.Errorf("schema %q property %q: expected string type, got %T", schemaName, propName, prop["type"])
			}
			prop["type"] = []any{typ, "null"}
		}
	}

	// Subject oneOf rewrite (idempotent: a schema already carrying oneOf is
	// left alone).
	subject, err := dig[map[string]any](schemas, subjectSchema)
	if err != nil {
		return err
	}
	if _, already := subject["oneOf"]; !already {
		delete(subject, "properties")
		delete(subject, "type")
		subject["oneOf"] = subjectOneOf
	}

	// Canonical serialization: sorted keys, 4-space indent, HTML-escaped —
	// the same shape swag's own marshaling produces for nested objects.
	out, err := json.MarshalIndent(doc, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

// patchYAML performs the same nullability patch on swagger.yaml via line
// surgery rather than a YAML round-trip: yaml.v3 re-encoding rewrites the
// whole document (line wrapping, sequence indentation), which would bury the
// three-line change under tens of thousands of formatting diffs. The swag
// layout is fixed — schema names at 4 spaces, properties at 8, their fields
// at 10 — and every anchor is asserted, so a generator format change fails
// loudly here instead of silently skipping the patch.
func patchYAML(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")

	for schemaName, props := range nullableProperties {
		for _, propName := range props {
			if err := patchYAMLProperty(lines, schemaName, propName); err != nil {
				return err
			}
		}
	}
	lines, err = patchYAMLSubjectOneOf(lines)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

// patchYAMLSubjectOneOf replaces the policyCheckSubject object body with its
// mutually exclusive oneOf alternatives and returns the updated line slice.
// The generated block is fixed (schema key at 4 spaces, "properties:" at 8,
// address/did at 10, "type: object" closing at 6), so the replacement is an
// exact anchored swap that fails loudly if swag changes its layout.
func patchYAMLSubjectOneOf(lines []string) ([]string, error) {
	anchor := "    " + subjectSchema + ":"
	at := -1
	for i, line := range lines {
		if line == anchor {
			at = i
			break
		}
	}
	if at == -1 {
		return nil, fmt.Errorf("yaml: schema %q not found", subjectSchema)
	}
	// Idempotent re-run: already rewritten.
	if at+1 < len(lines) && strings.HasPrefix(lines[at+1], "      oneOf:") {
		return lines, nil
	}
	want := []string{
		"      properties:",
		"        address:",
		"          type: string",
		"        did:",
		"          type: string",
		"      type: object",
	}
	for j, w := range want {
		if at+1+j >= len(lines) || lines[at+1+j] != w {
			return nil, fmt.Errorf("yaml: schema %q: unexpected generated body at line %d (got %q, want %q)", subjectSchema, at+2+j, lines[at+1+j], w)
		}
	}
	replacement := []string{
		"      oneOf:",
		"      - properties:",
		"          did:",
		"            type: string",
		"        required:",
		"        - did",
		"        type: object",
		"      - properties:",
		"          address:",
		"            type: string",
		"        required:",
		"        - address",
		"        type: object",
	}
	out := make([]string, 0, len(lines)-len(want)+len(replacement))
	out = append(out, lines[:at+1]...)
	out = append(out, replacement...)
	out = append(out, lines[at+1+len(want):]...)
	return out, nil
}

// patchYAMLProperty rewrites `type: <scalar>` to a [<scalar>, "null"] block
// sequence for one schema property, in place. Sequence items sit at the same
// indent as the key, matching swag's own sequence style (see `required:`).
func patchYAMLProperty(lines []string, schemaName, propName string) error {
	schemaAnchor := "    " + schemaName + ":"
	propAnchor := "        " + propName + ":"

	schemaAt := -1
	for i, line := range lines {
		if line == schemaAnchor {
			schemaAt = i
			break
		}
	}
	if schemaAt == -1 {
		return fmt.Errorf("yaml: schema %q not found", schemaName)
	}

	for i := schemaAt + 1; i < len(lines); i++ {
		line := lines[i]
		// Left the schema block (next 4-space or shallower key).
		if line != "" && !strings.HasPrefix(line, "      ") && !strings.HasPrefix(line, "        ") {
			break
		}
		if line != propAnchor {
			continue
		}
		// Inside the property block: find its `type:` field (10-space indent)
		// before the property block ends (next 8-space or shallower key).
		for j := i + 1; j < len(lines); j++ {
			inner := lines[j]
			if inner != "" && !strings.HasPrefix(inner, "          ") {
				break
			}
			if strings.HasPrefix(inner, "          type: ") {
				scalar := strings.TrimPrefix(inner, "          type: ")
				lines[j] = "          type:\n          - " + scalar + "\n          - \"null\""
				return nil
			}
		}
		return fmt.Errorf("yaml: schema %q property %q: scalar type line not found", schemaName, propName)
	}
	return fmt.Errorf("yaml: schema %q: property %q not found", schemaName, propName)
}

// dig fetches a nested value of type T from a string-keyed map chain,
// failing with the full path on any miss.
func dig[T any](m map[string]any, path ...string) (T, error) {
	var zero T
	cur := any(m)
	for i, key := range path {
		asMap, ok := cur.(map[string]any)
		if !ok {
			return zero, fmt.Errorf("path %v: element %d is not an object", path[:i+1], i)
		}
		cur, ok = asMap[key]
		if !ok {
			return zero, fmt.Errorf("path %v: key %q not found", path[:i+1], key)
		}
	}
	typed, ok := cur.(T)
	if !ok {
		return zero, fmt.Errorf("path %v: unexpected type %T", path, cur)
	}
	return typed, nil
}

// containsNull reports whether a JSON-Schema type list already admits null.
func containsNull(types []any) bool {
	for _, t := range types {
		if s, ok := t.(string); ok && s == "null" {
			return true
		}
	}
	return false
}
