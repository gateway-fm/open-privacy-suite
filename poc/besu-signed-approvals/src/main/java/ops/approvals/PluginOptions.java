package ops.approvals;

import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.tuweni.bytes.Bytes;
import picocli.CommandLine.Option;

/** {@code --plugin-ops-approval-*} command line options. Same meanings as the Reth PoC env vars. */
final class PluginOptions {
  @Option(names = "--plugin-ops-approval-listen", description = "host:port for OPS approval delivery (required)")
  String listen;

  @Option(names = "--plugin-ops-approval-public-key", description = "hex Ed25519 public key of the OPS signer, trusted under key id 'default'")
  String publicKey;

  @Option(names = "--plugin-ops-approval-public-keys", description = "trusted OPS signing keys as id=hex[,id=hex...]; a batch names the id that signed it, so rotation is add-then-switch")
  String publicKeys;

  /** The trusted key set from both options; at least one key is required. */
  Map<String, byte[]> trustedKeys() {
    final Map<String, byte[]> keys = new LinkedHashMap<>();
    if (publicKey != null) {
      keys.put("default", Bytes.fromHexString(publicKey).toArrayUnsafe());
    }
    if (publicKeys != null) {
      keys.putAll(parseKeys(publicKeys));
    }
    return keys;
  }

  static Map<String, byte[]> parseKeys(final String spec) {
    final Map<String, byte[]> keys = new LinkedHashMap<>();
    for (final String entry : spec.split(",")) {
      final int eq = entry.indexOf('=');
      if (eq < 1) {
        throw new IllegalArgumentException("expected id=hex, got '" + entry + "'");
      }
      final String id = entry.substring(0, eq).trim();
      if (!validKeyId(id)) {
        throw new IllegalArgumentException("invalid key id '" + id + "'");
      }
      final byte[] key = Bytes.fromHexString(entry.substring(eq + 1).trim()).toArrayUnsafe();
      if (key.length != 32) {
        throw new IllegalArgumentException("key '" + id + "' must be 32 bytes");
      }
      keys.put(id, key);
    }
    return keys;
  }

  /** Mirrors nodeapproval.ValidKeyID: 1–64 characters of [A-Za-z0-9._:-]. */
  static boolean validKeyId(final String id) {
    if (id.isEmpty() || id.length() > 64) {
      return false;
    }
    for (int i = 0; i < id.length(); i++) {
      final char c = id.charAt(i);
      if (!(Character.isLetterOrDigit(c) && c < 128 || c == '.' || c == '_' || c == ':' || c == '-')) {
        return false;
      }
    }
    return true;
  }

  @Option(names = "--plugin-ops-approval-chain-id", description = "chain id approvals must be bound to (required)")
  Long chainId;

  @Option(names = "--plugin-ops-approval-wait-ms", description = "how long an unapproved tx waits in the pool (default: ${DEFAULT-VALUE})")
  long waitMs = 5_000;

  @Option(names = "--plugin-ops-approval-capacity", description = "max approvals held in memory (default: ${DEFAULT-VALUE})")
  int capacity = 100_000;

  @Option(names = "--plugin-ops-approval-max-connections", description = "max concurrent OPS delivery connections (default: ${DEFAULT-VALUE})")
  int maxConnections = 32;

  @Option(names = "--plugin-ops-approval-orphan-ttl-ms", description = "drop approvals with no pool transaction after this (default: ${DEFAULT-VALUE})")
  long orphanTtlMs = 300_000;
}
