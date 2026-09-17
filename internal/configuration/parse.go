package configuration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
	"privacy-proxy/internal/rbac"
)

const MaxDocumentBytes = 1 << 20

type wireDocument struct {
	APIVersion   string          `json:"apiVersion"`
	Kind         Kind            `json:"kind"`
	Scope        Scope           `json:"scope"`
	BaseRevision int64           `json:"baseRevision"`
	Dependencies map[Kind]string `json:"dependencies"`
	Deletions    []Deletion      `json:"deletions"`
	Spec         json.RawMessage `json:"spec"`
}

// A non-nil error is a *SourceError.
func Parse(source []byte) (*Document, error) {
	v0, err := parseDocument(source)
	if err != nil {
		return v0, sourceError(err)
	}
	return v0, nil
}

// parseDocument is Parse before its error is typed.
func parseDocument(source []byte) (*Document, error) {
	if len(source) == 0 || len(source) > MaxDocumentBytes {
		return nil, fmt.Errorf("document must be 1..%d bytes", MaxDocumentBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("document has trailing JSON")
	}
	var wire wireDocument
	if err := exactDecode(value, &wire); err != nil {
		return nil, err
	}
	if wire.APIVersion != APIVersion {
		return nil, fmt.Errorf("unsupported apiVersion")
	}
	if wire.BaseRevision < 0 {
		return nil, fmt.Errorf("baseRevision must be nonnegative")
	}
	if err := validateScope(wire.Scope, wire.Kind); err != nil {
		return nil, err
	}
	for kind, digest := range wire.Dependencies {
		if !isOrgKind(kind) || kind == wire.Kind || wire.Scope.Kind != "organization" {
			return nil, fmt.Errorf("dependencies must name sibling streams in the same scope")
		}
		if !validDigest(digest) {
			return nil, fmt.Errorf("dependency %s requires a sha256 digest", kind)
		}
	}
	seenDeletes := map[string]bool{}
	for _, deletion := range wire.Deletions {
		if !canonicalUUID(deletion.ID) || seenDeletes[deletion.ID] {
			return nil, fmt.Errorf("deletions contain an invalid or duplicate id")
		}
		seenDeletes[deletion.ID] = true
		if deletion.LiveMemberships != nil && (*deletion.LiveMemberships < 0 || wire.Kind != Groups) {
			return nil, fmt.Errorf("liveMemberships is a nonnegative group deletion acknowledgement")
		}
	}
	var specValue any
	specDecoder := json.NewDecoder(bytes.NewReader(wire.Spec))
	specDecoder.UseNumber()
	if err := specDecoder.Decode(&specValue); err != nil {
		return nil, fmt.Errorf("invalid spec")
	}
	d := &Document{APIVersion: wire.APIVersion, Kind: wire.Kind, Scope: wire.Scope, BaseRevision: wire.BaseRevision, Dependencies: wire.Dependencies, Deletions: wire.Deletions}
	switch wire.Kind {
	case Groups:
		var spec GroupsSpec
		if err := exactDecode(specValue, &spec); err != nil {
			return nil, err
		}
		if err := normalizeGroups(&spec); err != nil {
			return nil, err
		}
		d.Spec = spec
	case ContractRegistry:
		var spec RegistrySpec
		if err := exactDecode(specValue, &spec); err != nil {
			return nil, err
		}
		if err := normalizeRegistry(&spec); err != nil {
			return nil, err
		}
		d.Spec = spec
	case Compliance:
		var spec ComplianceSpec
		if err := exactDecode(specValue, &spec); err != nil {
			return nil, err
		}
		if err := validateComplianceWireNumbers(specValue); err != nil {
			return nil, err
		}
		if err := normalizeCompliance(&spec); err != nil {
			return nil, err
		}
		d.Spec = spec
	case Approvers:
		var spec ApproversSpec
		if err := exactDecode(specValue, &spec); err != nil {
			return nil, err
		}
		if err := normalizeApprovers(&spec); err != nil {
			return nil, err
		}
		d.Spec = spec
	case ExecutionRules:
		var spec ExecutionSpec
		if err := exactDecode(specValue, &spec); err != nil {
			return nil, err
		}
		if err := normalizeExecution(&spec); err != nil {
			return nil, err
		}
		d.Spec = spec
	case Platform:
		var spec PlatformSpec
		if err := exactDecode(specValue, &spec); err != nil {
			return nil, err
		}
		if err := normalizePlatform(&spec); err != nil {
			return nil, err
		}
		d.Spec = spec
	default:
		return nil, fmt.Errorf("configuration kind %q is not supported yet", wire.Kind)
	}
	sort.Slice(d.Deletions, func(i, j int) bool { return d.Deletions[i].ID < d.Deletions[j].ID })
	return d, nil
}

func (d *Document) Canonical() ([]byte, string, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return nil, "", err
	}
	validated, err := Parse(b)
	if err != nil {
		return nil, "", err
	}
	b, err = json.Marshal(validated)
	if err != nil {
		return nil, "", err
	}
	digest := sha256.Sum256(b)
	return b, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateScope(scope Scope, kind Kind) error {
	if kind == Platform {
		if scope.Kind != "platform" || scope.ID != "" {
			return fmt.Errorf("platform document requires platform scope without id")
		}
		return nil
	}
	if !isOrgKind(kind) {
		return fmt.Errorf("unknown configuration kind")
	}
	if scope.Kind != "organization" || !canonicalUUID(scope.ID) {
		return fmt.Errorf("document requires organization scope with canonical UUID")
	}
	return nil
}

func isOrgKind(kind Kind) bool {
	switch kind {
	case Groups, ContractRegistry, Compliance, Approvers, ExecutionRules:
		return true
	}
	return false
}
func canonicalUUID(id string) bool {
	parsed, err := uuid.Parse(id)
	return err == nil && parsed != uuid.Nil && parsed.String() == id
}
func validDigest(s string) bool {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "sha256:"))
	return strings.HasPrefix(s, "sha256:") && len(b) == 32 && err == nil && strings.ToLower(s) == s
}

// Parse with tokens first: encoding/json alone accepts duplicate keys and
// case-insensitive field aliases, neither of which belongs in reviewed source.
func readValue(d *json.Decoder, depth int) (any, error) {
	if depth > 64 {
		return nil, fmt.Errorf("document nesting is too deep")
	}
	token, err := d.Token()
	if err != nil {
		return nil, fmt.Errorf("invalid document JSON")
	}
	delim, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delim {
	case '{':
		object := map[string]any{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return nil, fmt.Errorf("invalid object key")
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("invalid object key")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON key %q", key)
			}
			value, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		if _, err := d.Token(); err != nil {
			return nil, fmt.Errorf("invalid object")
		}
		return object, nil
	case '[':
		items := []any{}
		for d.More() {
			value, err := readValue(d, depth+1)
			if err != nil {
				return nil, err
			}
			items = append(items, value)
		}
		if _, err := d.Token(); err != nil {
			return nil, fmt.Errorf("invalid array")
		}
		return items, nil
	default:
		return nil, fmt.Errorf("invalid JSON delimiter")
	}
}

func exactDecode(value any, target any) error {
	if err := exactShape(value, reflect.TypeOf(target).Elem(), "document"); err != nil {
		return err
	}
	b, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("document field cannot be serialized")
	}
	if err := json.Unmarshal(b, target); err != nil {
		return fmt.Errorf("document field has an invalid type")
	}
	return nil
}

func exactShape(value any, typ reflect.Type, path string) error {
	if value == nil {
		return fmt.Errorf("%s must not be null", path)
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be an object", path)
		}
		fields := map[string]reflect.StructField{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = field.Name
			}
			fields[name] = field
			if _, found := object[name]; !found && field.Tag.Get("optional") != "true" {
				return fmt.Errorf("%s.%s is required", path, name)
			}
		}
		for key, child := range object {
			field, found := fields[key]
			if !found {
				return fmt.Errorf("%s.%s is not a supported field", path, key)
			}
			if err := exactShape(child, field.Type, path+"."+key); err != nil {
				return err
			}
		}
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s must be an explicit array", path)
		}
		for i, item := range items {
			if err := exactShape(item, typ.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be an object", path)
		}
		for key, child := range object {
			if err := exactShape(child, typ.Elem(), path+"."+key); err != nil {
				return err
			}
		}
	}
	return nil
}

var slugPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,99}$`)
var methodPattern = regexp.MustCompile(`^(\*|[a-zA-Z][a-zA-Z0-9]*_(\*|[a-zA-Z][a-zA-Z0-9_]*))$`)

func normalizeGroups(spec *GroupsSpec) error {
	ids, slugs, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i := range spec.Groups {
		g := &spec.Groups[i]
		if !canonicalUUID(g.ID) || ids[g.ID] {
			return fmt.Errorf("groups contain an invalid or duplicate id")
		}
		ids[g.ID] = true
		if !slugPattern.MatchString(g.Slug) || slugs[g.Slug] {
			return fmt.Errorf("groups contain an invalid or duplicate slug")
		}
		slugs[g.Slug] = true
		if strings.TrimSpace(g.Name) == "" || names[g.Name] {
			return fmt.Errorf("groups require unique nonempty names")
		}
		names[g.Name] = true
		if g.IsOrgAdmin && g.IsOrgReadonlyAdmin {
			return fmt.Errorf("group admin roles are mutually exclusive")
		}
		if g.IsOrgAdmin && (len(g.Claims) != 0 || len(g.AllowedMethods) == 0) {
			return fmt.Errorf("org-admin groups require methods and no claims")
		}
		if err := normalizeClaims(g.Claims); err != nil {
			return err
		}
		if err := sortUnique(g.AllowedMethods); err != nil {
			return err
		}
		for _, method := range g.AllowedMethods {
			if !methodPattern.MatchString(method) {
				return fmt.Errorf("invalid RPC method allowlist entry")
			}
		}
		g.AllowedMethods = rbac.ExpandWildcardMethods(g.AllowedMethods)
		sort.Strings(g.AllowedMethods)
		claims := []rbac.Claim{}
		for _, claim := range g.Claims {
			claims = append(claims, rbac.Claim(claim))
		}
		claims = rbac.ExpandClaims(claims)
		g.Claims = []string{}
		for _, claim := range claims {
			g.Claims = append(g.Claims, string(claim))
		}
		if !g.IsOrgAdmin {
			if err := rbac.ValidateMethodsMatchClaims(g.AllowedMethods, claims); err != nil {
				return err
			}
		}
	}
	sort.Slice(spec.Groups, func(i, j int) bool { return spec.Groups[i].ID < spec.Groups[j].ID })
	return nil
}
func sortUnique(values []string) error {
	sort.Strings(values)
	for i, value := range values {
		if value == "" || (i > 0 && values[i-1] == value) {
			return fmt.Errorf("arrays contain an empty or duplicate value")
		}
	}
	return nil
}
func normalizeClaims(claims []string) error {
	if err := sortUnique(claims); err != nil {
		return err
	}
	for _, claim := range claims {
		switch claim {
		case "admin", "deploy", "upgrade":
		default:
			return fmt.Errorf("unsupported claim %q", claim)
		}
	}
	return nil
}
func normalizeRegistry(spec *RegistrySpec) error {
	ids, addresses := map[string]bool{}, map[string]bool{}
	for i := range spec.Contracts {
		c := &spec.Contracts[i]
		if !canonicalUUID(c.ID) || ids[c.ID] {
			return fmt.Errorf("contracts contain an invalid or duplicate id")
		}
		ids[c.ID] = true
		if !common.IsHexAddress(c.Address) {
			return fmt.Errorf("contract requires an Ethereum address")
		}
		c.Address = strings.ToLower(c.Address)
		if addresses[c.Address] {
			return fmt.Errorf("duplicate contract address")
		}
		addresses[c.Address] = true
		if len(c.ABI) == 0 || c.ABI[0] != '[' {
			return fmt.Errorf("abi must be an array")
		}
		contractABI, err := abi.JSON(bytes.NewReader(c.ABI))
		if err != nil {
			return fmt.Errorf("invalid contract ABI")
		}
		var abiValue any
		decoder := json.NewDecoder(bytes.NewReader(c.ABI))
		decoder.UseNumber()
		if err := decoder.Decode(&abiValue); err != nil {
			return fmt.Errorf("invalid ABI JSON")
		}
		c.ABI, _ = json.Marshal(abiValue)
		groups := map[string]bool{}
		for j := range c.ReadGrants {
			grant := &c.ReadGrants[j]
			if !canonicalUUID(grant.ID) || ids[grant.ID] {
				return fmt.Errorf("readGrants contain an invalid or duplicate resource id")
			}
			ids[grant.ID] = true
			if !canonicalUUID(grant.GroupID) || groups[grant.GroupID] {
				return fmt.Errorf("readGrants contain an invalid or duplicate groupId")
			}
			groups[grant.GroupID] = true
			if err := sortUnique(grant.LegacyClaims); err != nil {
				return err
			}
			switch grant.EventRules.Mode {
			case "none", "all":
				if len(grant.EventRules.Rules) != 0 {
					return fmt.Errorf("eventRules mode requires empty rules")
				}
			case "allowlist":
				if len(grant.EventRules.Rules) == 0 {
					return fmt.Errorf("eventRules allowlist requires rules")
				}
				if err := normalizeEventRules(&grant.EventRules, contractABI); err != nil {
					return err
				}
			default:
				return fmt.Errorf("unsupported eventRules mode")
			}
		}
		sort.Slice(c.ReadGrants, func(a, b int) bool { return c.ReadGrants[a].GroupID < c.ReadGrants[b].GroupID })
	}
	sort.Slice(spec.Contracts, func(i, j int) bool { return spec.Contracts[i].ID < spec.Contracts[j].ID })
	return nil
}

func normalizeEventRules(rules *EventRules, contractABI abi.ABI) error {
	seen := map[string]bool{}
	for i := range rules.Rules {
		rule := &rules.Rules[i]
		topic, err := hex.DecodeString(strings.TrimPrefix(rule.Topic0, "0x"))
		if err != nil || len(topic) != 32 || !strings.HasPrefix(rule.Topic0, "0x") {
			return fmt.Errorf("event topic0 requires 32-byte hex")
		}
		rule.Topic0 = strings.ToLower(rule.Topic0)
		if seen[rule.Topic0] {
			return fmt.Errorf("duplicate event topic0")
		}
		seen[rule.Topic0] = true
		event, err := contractABI.EventByID(common.BytesToHash(topic))
		if err != nil || event.Anonymous {
			return fmt.Errorf("event topic0 must match a non-anonymous ABI event")
		}
		if rule.Name != event.RawName {
			return fmt.Errorf("event name must match ABI")
		}
		indexes := map[int]bool{}
		for j := range rule.ParamRules {
			param := &rule.ParamRules[j]
			if param.Index < 0 || param.Index >= len(event.Inputs) || indexes[param.Index] {
				return fmt.Errorf("invalid or duplicate event parameter index")
			}
			indexes[param.Index] = true
			typ := event.Inputs[param.Index].Type
			if param.MustBe == "self" {
				if typ.T != abi.AddressTy {
					return fmt.Errorf("self event predicate requires address parameter")
				}
				continue
			}
			value, err := hex.DecodeString(strings.TrimPrefix(param.MustBe, "0x"))
			if !strings.HasPrefix(param.MustBe, "0x") || err != nil {
				return fmt.Errorf("event predicates require self or canonical hex")
			}
			size := 32
			switch typ.T {
			case abi.AddressTy:
				size = 20
			case abi.FixedBytesTy:
				size = typ.Size
			case abi.IntTy, abi.UintTy, abi.BoolTy:
			default:
				return fmt.Errorf("event predicate requires a static scalar ABI parameter")
			}
			if len(value) != size {
				return fmt.Errorf("event predicate hex length does not match ABI parameter")
			}
			param.MustBe = strings.ToLower(param.MustBe)
		}
		sort.Slice(rule.ParamRules, func(i, j int) bool { return rule.ParamRules[i].Index < rule.ParamRules[j].Index })
	}
	sort.Slice(rules.Rules, func(i, j int) bool { return rules.Rules[i].Topic0 < rules.Rules[j].Topic0 })
	return nil
}
