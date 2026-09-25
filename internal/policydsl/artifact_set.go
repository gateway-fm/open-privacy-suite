package policydsl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

// ArtifactSet is the immutable output of one reviewed organization document.
// An empty set denies all execution. The empty group key is reserved for an
// already approved legacy organization-wide artifact; new builds never use it.
type ArtifactSet struct {
	PolicyDigest string               `json:"policy_digest"`
	Groups       map[string]*Artifact `json:"groups"`
}

func (c *Compiler) BuildSet(ctx context.Context, v *Validated) (*ArtifactSet, error) {
	groups, err := c.BuildPerGroup(ctx, v)
	if err != nil {
		return nil, err
	}
	digest, err := CanonicalDigest(v.Policy())
	if err != nil {
		return nil, err
	}
	return &ArtifactSet{PolicyDigest: digest, Groups: groups}, nil
}

// DecodeArtifactSet accepts the previous single-artifact representation without
// recompiling it. Existing approvals continue to refer to their original bytes.
func DecodeArtifactSet(raw []byte) (*ArtifactSet, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	var set ArtifactSet
	if _, ok := fields["groups"]; ok {
		if err := d.Decode(&set); err != nil {
			return nil, err
		}
		if set.Groups == nil {
			return nil, fmt.Errorf("missing artifact groups")
		}
		if _, legacy := set.Groups[""]; legacy {
			return nil, fmt.Errorf("empty artifact group")
		}
	} else {
		var artifact Artifact
		if err := d.Decode(&artifact); err != nil {
			return nil, err
		}
		set = ArtifactSet{PolicyDigest: artifact.PolicyDigest, Groups: map[string]*Artifact{"": &artifact}}
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("trailing artifact data")
	}
	if len(set.PolicyDigest) != 64 {
		return nil, fmt.Errorf("missing artifact policy digest")
	}
	for _, artifact := range set.Groups {
		if artifact == nil || artifact.PolicyDigest != set.PolicyDigest {
			return nil, fmt.Errorf("artifact policy digest mismatch")
		}
	}
	return &set, nil
}

// Digests bind group identities to their exact source and runtime digests. JSON
// sorts map keys, so the manifest is stable regardless of compilation order.
func (s *ArtifactSet) Digests() (source, runtime string) {
	if a := s.Groups[""]; a != nil {
		return a.SourceDigest, a.RuntimeDigest
	}
	sources, runtimes := map[string]string{}, map[string]string{}
	for group, a := range s.Groups {
		sources[group], runtimes[group] = a.SourceDigest, a.RuntimeDigest
	}
	hash := func(value any) string {
		b, _ := json.Marshal(value)
		h := sha256.Sum256(b)
		return hex.EncodeToString(h[:])
	}
	return hash(sources), hash(runtimes)
}
