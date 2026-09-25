// Package nodepolicy defines authenticated messages exchanged between OPS and
// the execution node. Identity messages attest who submitted a request, never
// whether that request is allowed to execute.
package nodepolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
)

const (
	ProtocolVersion    = 1
	MaxEnvelopeBytes   = 64 << 20
	MaxIdentityBytes   = 16 << 10
	MaxMessageLifetime = 10 * time.Minute
	ClockSkew          = 5 * time.Second
)

var (
	ErrEnvelope  = errors.New("invalid node policy envelope")
	ErrSignature = errors.New("untrusted node policy signature")
	ErrNetwork   = errors.New("node policy network mismatch")
	ErrExpired   = errors.New("node policy message outside validity window")
	ErrIdentity  = errors.New("invalid execution identity")
)

type Network struct {
	ChainID      uint64 `json:"chain_id"`
	DeploymentID string `json:"deployment_id"`
}

type Header struct {
	Network   Network `json:"network"`
	IssuedAt  int64   `json:"issued_at"`
	ExpiresAt int64   `json:"expires_at"`
}

type Identity struct {
	Header
	Scope              string `json:"scope"`
	ContextID          string `json:"context_id"`
	PrincipalID        string `json:"principal_id"`
	OrgID              string `json:"org_id"`
	Signer             string `json:"signer"`
	BindingHash        string `json:"binding_hash"`
	MinSnapshotVersion uint64 `json:"min_snapshot_version"`
}

type Envelope struct {
	Version   int    `json:"version"`
	Kind      string `json:"kind"`
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type Signer struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

func (s Signer) Seal(kind string, payload any) ([]byte, error) {
	if len(s.PrivateKey) != ed25519.PrivateKeySize || !identifier(s.KeyID) || !validKind(kind) {
		return nil, ErrEnvelope
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: payload encoding", ErrEnvelope)
	}
	if len(b) > MaxEnvelopeBytes/2 {
		return nil, ErrEnvelope
	}
	e := Envelope{Version: ProtocolVersion, Kind: kind, KeyID: s.KeyID, Payload: b}
	e.Signature = ed25519.Sign(s.PrivateKey, signingBytes(kind, s.KeyID, b))
	return json.Marshal(e)
}

type Verifier struct {
	Network Network
	// Keys is immutable for this verifier's lifetime. Rotation publishes a new
	// verifier; mutating a map concurrently with verification is not supported.
	Keys map[string]ed25519.PublicKey
	Now  func() time.Time
}

func (v Verifier) clock() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Open authenticates exact payload bytes. Callers must strictly decode the
// returned payload and validate its Header before using any of its fields.
func (v Verifier) Open(kind string, wire []byte) ([]byte, error) {
	if len(wire) == 0 || len(wire) > MaxEnvelopeBytes || !validKind(kind) {
		return nil, ErrEnvelope
	}
	var encoded struct {
		Version   int    `json:"version"`
		Kind      string `json:"kind"`
		KeyID     string `json:"key_id"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := decodeStrict(wire, &encoded); err != nil {
		return nil, fmt.Errorf("%w: ambiguous envelope", ErrEnvelope)
	}
	if encoded.Version != ProtocolVersion || encoded.Kind != kind || !identifier(encoded.KeyID) {
		return nil, ErrEnvelope
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(encoded.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != encoded.Payload {
		return nil, ErrEnvelope
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(encoded.Signature)
	if err != nil || base64.StdEncoding.EncodeToString(sig) != encoded.Signature {
		return nil, ErrEnvelope
	}
	key := v.Keys[encoded.KeyID]
	if len(key) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, signingBytes(kind, encoded.KeyID, payload), sig) {
		return nil, ErrSignature
	}
	return payload, nil
}

func (v Verifier) OpenIdentity(wire []byte) (Identity, error) {
	var i Identity
	if len(wire) > MaxIdentityBytes {
		return i, ErrEnvelope
	}
	b, err := v.Open("identity", wire)
	if err != nil {
		return i, err
	}
	if err := decodeStrict(b, &i); err != nil {
		return Identity{}, ErrIdentity
	}
	if err := v.ValidateHeader(i.Header); err != nil {
		return Identity{}, err
	}
	if (i.Scope != "transaction" && i.Scope != "simulation") || !identifier(i.ContextID) || !identifier(i.PrincipalID) || !identifier(i.OrgID) || !hexField(i.Signer, 20) || !hexField(i.BindingHash, 32) || i.MinSnapshotVersion == 0 {
		return Identity{}, ErrIdentity
	}
	return i, nil
}

func (v Verifier) ValidateHeader(h Header) error {
	if h.Network != v.Network || h.Network.ChainID == 0 || !identifier(h.Network.DeploymentID) {
		return ErrNetwork
	}
	now := v.clock().Unix()
	if h.IssuedAt < 0 || h.ExpiresAt <= h.IssuedAt || h.ExpiresAt-h.IssuedAt > int64(MaxMessageLifetime/time.Second) || h.IssuedAt > now+int64(ClockSkew/time.Second) || h.ExpiresAt <= now {
		return ErrExpired
	}
	return nil
}

func signingBytes(kind, keyID string, payload []byte) []byte {
	b := []byte("OPS_NODE_POLICY_V1\x00")
	for _, part := range [][]byte{[]byte(kind), []byte(keyID), payload} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(part)))
		b = append(b, part...)
	}
	return b
}

func validKind(kind string) bool {
	switch kind {
	case "identity", "snapshot", "delta", "heartbeat":
		return true
	}
	return false
}

func identifier(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

func hexField(s string, size int) bool {
	if len(s) != 2+size*2 || !strings.HasPrefix(s, "0x") || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s[2:])
	return err == nil
}

// encoding/json alone accepts duplicate keys. Reject them, including nested
// objects, before decoding into a schema that rejects unknown fields.
func decodeStrict(b []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := uniqueValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrEnvelope
	}
	if err := exactFields(b, reflect.TypeOf(out)); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return err
	}
	return nil
}

// Go accepts case-insensitive matches for struct fields, unlike the Rust wire
// decoder. Require exact JSON names so every implementation sees one meaning.
func exactFields(b []byte, t reflect.Type) error {
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return ErrEnvelope
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(b, &fields); err != nil {
			return err
		}
		allowed := map[string]reflect.Type{}
		optional := map[string]bool{}
		var collect func(reflect.Type)
		collect = func(st reflect.Type) {
			for i := 0; i < st.NumField(); i++ {
				f := st.Field(i)
				if f.Anonymous {
					collect(f.Type)
					continue
				}
				name := strings.Split(f.Tag.Get("json"), ",")[0]
				if name != "" && name != "-" {
					allowed[name] = f.Type
					optional[name] = f.Tag.Get("wireoptional") == "true"
				}
			}
		}
		collect(t)
		for name := range allowed {
			if _, ok := fields[name]; !ok && !optional[name] {
				return ErrEnvelope
			}
		}
		for name, value := range fields {
			ft, ok := allowed[name]
			if !ok {
				return ErrEnvelope
			}
			// Explicit pointer fields model nullable values (for example a
			// pending transaction's block). The field itself remains required;
			// non-pointer facts and the root document still reject null.
			// Only explicitly tagged protocol extensions may be absent.
			if ft.Kind() == reflect.Pointer && bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				continue
			}
			if err := exactFields(value, ft); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var values []json.RawMessage
		if err := json.Unmarshal(b, &values); err != nil {
			return err
		}
		for _, value := range values {
			if err := exactFields(value, t.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrEnvelope
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok {
				return ErrEnvelope
			}
			if _, exists := seen[key]; exists {
				return ErrEnvelope
			}
			seen[key] = struct{}{}
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrEnvelope
		}
	case '[':
		for d.More() {
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrEnvelope
		}
	default:
		return ErrEnvelope
	}
	return nil
}
