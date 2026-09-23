package configuration

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	"privacy-proxy/internal/crypto"
)

// SecretRef names where a secret lives. It is the only form a secret takes in
// a reviewed document: the variable's name is desired state, its value never
// is. A document that carried a value would put it into the revision text,
// the digest, the diff and the audit chain, so the parser refuses any other
// field on this object.
type SecretRef struct {
	FromEnv string `json:"fromEnv"`
}

// SecretResolver turns a declared variable name into the ciphertext to store.
// It is installed by the server, which owns the encryption key; the document
// layer never sees the plaintext. ErrSecretUnset means the variable is empty
// or absent; ErrSecretEncryptionUnavailable means the deployment cannot
// protect the value at rest and must not store it.
type SecretResolver func(name string) (ciphertext string, err error)

var (
	ErrSecretUnset                 = errors.New("secret variable is not set")
	ErrSecretEncryptionUnavailable = errors.New("secret encryption is not configured")
)

// NewEnvSecretResolver reads the process environment — the sanctioned place
// for values injected from the secrets store — and encrypts what it finds with
// the given key. With no key it refuses rather than storing plaintext, which
// is the one place this differs from the operational rotation endpoint.
// The lookup is os.Getenv on purpose: a configuration file must never be able
// to supply a credential.
func NewEnvSecretResolver(key []byte) SecretResolver {
	return func(name string) (string, error) {
		if len(key) == 0 {
			return "", ErrSecretEncryptionUnavailable
		}
		value := os.Getenv(name)
		if value == "" {
			return "", ErrSecretUnset
		}
		return crypto.Encrypt(value, key)
	}
}

// credentialVariablePrefix is the namespace a tenant may reference. Anything
// outside it is refused at parse time, so a groups document can never point a
// group at the process environment at large or at another tenant's variable.
const credentialVariablePrefix = "OPS_RPC_CREDENTIAL_"

var credentialVariableSuffix = regexp.MustCompile(`^[A-Z0-9_]{1,64}$`)

// CredentialVariablePrefix is the exact prefix a credential variable for this
// organisation must carry: the namespace, then the organisation id as upper
// hexadecimal without dashes, then an underscore.
func CredentialVariablePrefix(scope Scope) string {
	return credentialVariablePrefix + strings.ToUpper(strings.ReplaceAll(scope.ID, "-", "")) + "_"
}

func validateSecretRef(ref *SecretRef, scope Scope) error {
	if ref == nil {
		return nil
	}
	prefix := CredentialVariablePrefix(scope)
	if scope.Kind != "organization" || !strings.HasPrefix(ref.FromEnv, prefix) || !credentialVariableSuffix.MatchString(strings.TrimPrefix(ref.FromEnv, prefix)) {
		return fmt.Errorf("rpcCredential.fromEnv must name a variable in this organisation's namespace %s<NAME>", prefix)
	}
	return nil
}
