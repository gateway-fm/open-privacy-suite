package config

import "testing"

func TestNodePolicyModeRequiresCompleteBoundedConfiguration(t *testing.T) {
	if err := (NodePolicyConfig{}).Validate(); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"OPS_NODE_POLICY_MODE": "reth", "OPS_NODE_POLICY_URL": "http://reth:8555", "OPS_NODE_POLICY_TOKEN": "private-test-token", "OPS_NODE_POLICY_PRIVATE_KEY_FILE": "/run/secrets/ops-node-key", "OPS_NODE_POLICY_KEY_ID": "ops-a", "OPS_NODE_POLICY_CHAIN_ID": "31337", "OPS_NODE_POLICY_DEPLOYMENT_ID": "stack-a"}
	get := func(key string) string { return env[key] }
	c := loadNodePolicy(get)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if c.Mode != "reth" || c.FactTTL.String() != "30s" || c.PublishInterval.String() != "1s" || c.IdentityTTL.String() != "1m0s" {
		t.Fatalf("unexpected defaults %+v", c)
	}
	for _, key := range []string{"OPS_NODE_POLICY_URL", "OPS_NODE_POLICY_TOKEN", "OPS_NODE_POLICY_PRIVATE_KEY_FILE", "OPS_NODE_POLICY_KEY_ID", "OPS_NODE_POLICY_CHAIN_ID", "OPS_NODE_POLICY_DEPLOYMENT_ID"} {
		old := env[key]
		delete(env, key)
		if err := loadNodePolicy(get).Validate(); err == nil {
			t.Errorf("missing %s accepted", key)
		}
		env[key] = old
	}
	for _, pair := range [][2]string{{"OPS_NODE_POLICY_MODE", "besu"}, {"OPS_NODE_POLICY_FACT_TTL", "0s"}, {"OPS_NODE_POLICY_FACT_TTL", "11m"}, {"OPS_NODE_POLICY_PUBLISH_INTERVAL", "11s"}, {"OPS_NODE_POLICY_IDENTITY_TTL", "invalid"}, {"OPS_NODE_POLICY_CHAIN_ID", "not-a-number"}, {"OPS_NODE_POLICY_URL", "http://user:password@reth:8555"}} {
		old, exists := env[pair[0]]
		env[pair[0]] = pair[1]
		if err := loadNodePolicy(get).Validate(); err == nil {
			t.Errorf("invalid %v accepted", pair)
		}
		if exists {
			env[pair[0]] = old
		} else {
			delete(env, pair[0])
		}
	}
}
