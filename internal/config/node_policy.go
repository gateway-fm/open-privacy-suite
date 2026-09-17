package config

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type NodePolicyConfig struct {
	Mode            string
	URL             string
	Token           string
	PrivateKeyFile  string
	KeyID           string
	ChainID         uint64
	DeploymentID    string
	ConsumerID      string
	FactTTL         time.Duration
	PublishInterval time.Duration
	IdentityTTL     time.Duration
	parseError      error
}

func (c NodePolicyConfig) Enabled() bool { return c.Mode == "reth" }
func loadNodePolicy(get func(string) string) NodePolicyConfig {
	value := func(key, fallback string) string {
		if v := strings.TrimSpace(get(key)); v != "" {
			return v
		}
		return fallback
	}
	c := NodePolicyConfig{Mode: value("OPS_NODE_POLICY_MODE", "legacy"), URL: value("OPS_NODE_POLICY_URL", ""), Token: value("OPS_NODE_POLICY_TOKEN", ""), PrivateKeyFile: value("OPS_NODE_POLICY_PRIVATE_KEY_FILE", ""), KeyID: value("OPS_NODE_POLICY_KEY_ID", ""), DeploymentID: value("OPS_NODE_POLICY_DEPLOYMENT_ID", ""), ConsumerID: value("OPS_NODE_POLICY_CONSUMER_ID", "producer")}
	if !c.Enabled() {
		return c
	}
	var err error
	c.ChainID, err = strconv.ParseUint(value("OPS_NODE_POLICY_CHAIN_ID", "0"), 10, 64)
	if err != nil {
		c.parseError = fmt.Errorf("OPS_NODE_POLICY_CHAIN_ID must be an unsigned integer")
	}
	for _, duration := range []struct {
		key, fallback string
		dst           *time.Duration
	}{
		{"OPS_NODE_POLICY_FACT_TTL", "30s", &c.FactTTL}, {"OPS_NODE_POLICY_PUBLISH_INTERVAL", "1s", &c.PublishInterval}, {"OPS_NODE_POLICY_IDENTITY_TTL", "1m", &c.IdentityTTL},
	} {
		*duration.dst, err = time.ParseDuration(value(duration.key, duration.fallback))
		if err != nil {
			c.parseError = fmt.Errorf("%s must be a duration", duration.key)
		}
	}
	return c
}
func (c NodePolicyConfig) Validate() error {
	if c.Mode == "" || c.Mode == "legacy" {
		return nil
	}
	if c.Mode != "reth" {
		return fmt.Errorf("OPS_NODE_POLICY_MODE must be legacy or reth")
	}
	if c.parseError != nil {
		return c.parseError
	}
	u, err := url.Parse(c.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("OPS_NODE_POLICY_URL must be a private HTTP(S) endpoint without embedded credentials")
	}
	if len(c.Token) < 16 || strings.ContainsAny(c.Token, " \r\n\t") {
		return fmt.Errorf("OPS_NODE_POLICY_TOKEN requires at least 16 bytes without whitespace")
	}
	if c.PrivateKeyFile == "" || !nodePolicyIdentifier(c.KeyID) || c.ChainID == 0 || !nodePolicyIdentifier(c.DeploymentID) || !nodePolicyIdentifier(c.ConsumerID) {
		return fmt.Errorf("Reth policy mode requires a signing key file, key ID, chain ID, deployment ID and consumer ID")
	}
	if c.FactTTL < time.Second || c.FactTTL > 10*time.Minute || c.IdentityTTL < time.Second || c.IdentityTTL > 10*time.Minute || c.PublishInterval <= 0 || c.PublishInterval > c.FactTTL/3 {
		return fmt.Errorf("node policy lifetimes must be 1s..10m and publish interval at most one third of fact lifetime")
	}
	return nil
}
func nodePolicyIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.:", r)) {
			return false
		}
	}
	return true
}
