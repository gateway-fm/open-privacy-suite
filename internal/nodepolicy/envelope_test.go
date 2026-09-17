package nodepolicy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func identityFixture() Identity {
	return Identity{Header: Header{Network: Network{ChainID: 31337, DeploymentID: "ops-test"}, IssuedAt: 1000, ExpiresAt: 1100},
		Scope: "transaction", ContextID: "context-1", PrincipalID: "user-a", OrgID: "org-a", Signer: "0x" + strings.Repeat("11", 20),
		BindingHash: "0x" + strings.Repeat("22", 32), MinSnapshotVersion: 7}
}

func testSigner() Signer {
	return Signer{KeyID: "ops-a", PrivateKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))}
}

func testVerifier() Verifier {
	s := testSigner()
	return Verifier{Network: identityFixture().Network, Keys: map[string]ed25519.PublicKey{s.KeyID: s.PrivateKey.Public().(ed25519.PublicKey)}, Now: func() time.Time { return time.Unix(1020, 0) }}
}

func TestIdentityEnvelopeRoundTripAndTampering(t *testing.T) {
	original := identityFixture()
	wire, err := testSigner().Seal("identity", original)
	if err != nil {
		t.Fatal(err)
	}
	v := testVerifier()
	got, err := v.OpenIdentity(wire)
	if err != nil || got != original {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	var e Envelope
	if err := json.Unmarshal(wire, &e); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"payload", "kind", "key_id", "signature", "version"} {
		t.Run(field, func(t *testing.T) {
			changed := e
			switch field {
			case "payload":
				changed.Payload = bytes.ReplaceAll(e.Payload, []byte("user-a"), []byte("user-b"))
			case "kind":
				changed.Kind = "snapshot"
			case "key_id":
				changed.KeyID = "other"
			case "signature":
				changed.Signature = append([]byte(nil), e.Signature...)
				changed.Signature[0] ^= 1
			case "version":
				changed.Version = 2
			}
			b, _ := json.Marshal(changed)
			if _, err := v.OpenIdentity(b); err == nil {
				t.Fatal("tampered identity was accepted")
			}
		})
	}
}

func TestIdentityRejectsWrongNetworkExpiryAndMalformedPayload(t *testing.T) {
	for _, name := range []string{"network", "deployment", "expired", "future", "unbounded", "missing_principal", "invalid_signer", "invalid_binding", "scope", "zero_version"} {
		t.Run(name, func(t *testing.T) {
			i := identityFixture()
			switch name {
			case "network":
				i.Network.ChainID++
			case "deployment":
				i.Network.DeploymentID = "other"
			case "expired":
				i.ExpiresAt = 1020
			case "future":
				i.IssuedAt = 1080
			case "unbounded":
				i.ExpiresAt = 1000000
			case "missing_principal":
				i.PrincipalID = ""
			case "invalid_signer":
				i.Signer = "0x01"
			case "invalid_binding":
				i.BindingHash = "0x01"
			case "scope":
				i.Scope = "approval"
			case "zero_version":
				i.MinSnapshotVersion = 0
			}
			b, err := testSigner().Seal("identity", i)
			if err != nil {
				return
			}
			if _, err := testVerifier().OpenIdentity(b); err == nil {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}

func TestEnvelopeRejectsDuplicateAndUnknownJSONKeys(t *testing.T) {
	wire, err := testSigner().Seal("identity", identityFixture())
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range []string{`{"version":1,`, `{"Version":1,`, `{"surprise":true,`} {
		bad := append([]byte(prefix), wire[1:]...)
		if _, err := testVerifier().OpenIdentity(bad); err == nil {
			t.Fatal("ambiguous envelope accepted")
		}
	}
	var payload map[string]any
	b, _ := json.Marshal(identityFixture())
	if err := json.Unmarshal(b, &payload); err != nil {
		t.Fatal(err)
	}
	payload["permission"] = "allow"
	bad, err := testSigner().Seal("identity", payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testVerifier().OpenIdentity(bad); err == nil {
		t.Fatal("permission-bearing identity accepted")
	}
	delete(payload, "permission")
	payload["Principal_ID"] = "user-b"
	bad, err = testSigner().Seal("identity", payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testVerifier().OpenIdentity(bad); err == nil {
		t.Fatal("noncanonical identity field accepted")
	}
}

func TestSigningIsDeterministicAndDomainSeparated(t *testing.T) {
	a, err := testSigner().Seal("identity", identityFixture())
	if err != nil {
		t.Fatal(err)
	}
	b, err := testSigner().Seal("identity", identityFixture())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("same payload did not produce identical envelope")
	}
	var e Envelope
	if err := json.Unmarshal(a, &e); err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(testSigner().PrivateKey.Public().(ed25519.PublicKey), e.Payload, e.Signature) {
		t.Fatal("signature lacked protocol domain")
	}
	v := testVerifier()
	v.Keys["alias"] = v.Keys[e.KeyID]
	e.KeyID = "alias"
	changed, _ := json.Marshal(e)
	if _, err := v.Open("identity", changed); err == nil {
		t.Fatal("key id was not authenticated")
	}
	e.KeyID = testSigner().KeyID
	e.Kind = "snapshot"
	changed, _ = json.Marshal(e)
	if _, err := v.Open("snapshot", changed); err == nil {
		t.Fatal("message kind was not authenticated")
	}
}

func TestRequiredWireFieldsAndNulls(t *testing.T) {
	for _, field := range []string{"scope", "context_id", "principal_id", "signer", "binding_hash", "network", "issued_at", "expires_at", "min_snapshot_version"} {
		for _, mode := range []string{"missing", "null"} {
			t.Run(field+"/"+mode, func(t *testing.T) {
				b, _ := json.Marshal(identityFixture())
				var obj map[string]any
				if err := json.Unmarshal(b, &obj); err != nil {
					t.Fatal(err)
				}
				if mode == "missing" {
					delete(obj, field)
				} else {
					obj[field] = nil
				}
				wire, err := testSigner().Seal("identity", obj)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := testVerifier().OpenIdentity(wire); err == nil {
					t.Fatal("missing/null field accepted")
				}
			})
		}
	}
	i := identityFixture()
	i.IssuedAt = 0
	i.ExpiresAt = 100
	v := testVerifier()
	v.Now = func() time.Time { return time.Unix(20, 0) }
	b, _ := json.Marshal(i)
	var obj map[string]any
	_ = json.Unmarshal(b, &obj)
	delete(obj, "issued_at")
	wire, _ := testSigner().Seal("identity", obj)
	if _, err := v.OpenIdentity(wire); err == nil {
		t.Fatal("omitted zero-valued field accepted")
	}
}
