package ops.approvals;

import java.net.InetSocketAddress;
import java.util.LinkedHashMap;
import java.util.Map;
import org.apache.tuweni.bytes.Bytes;
import picocli.CommandLine.Option;

/**
 * {@code --plugin-ops-approval-*} command line options: the receiver settings of the wire contract
 * §7, plus the delivery connection limits. Same meanings as the Reth node's settings.
 */
final class PluginOptions {
  @Option(names = "--plugin-ops-approval-listen", description = "host:port the gRPC approval delivery service listens on (required)")
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

  @Option(names = "--plugin-ops-approval-wait-ms", description = "how long a pooled transaction waits for its approval (default: ${DEFAULT-VALUE})")
  long waitMs = 5_000;

  @Option(names = "--plugin-ops-approval-capacity", description = "approvals the store holds (default: ${DEFAULT-VALUE})")
  int capacity = 100_000;

  @Option(names = "--plugin-ops-approval-max-ttl-ms", description = "longest expires_at - issued_at of a batch accepted, in ms (default: ${DEFAULT-VALUE})")
  long maxTtlMs = 3_600_000;

  @Option(names = "--plugin-ops-approval-allowed-sources", description = "comma-separated CIDR blocks allowed to connect for delivery (default: any; a network rule must still let only OPS reach the port)")
  String sources;

  @Option(names = "--plugin-ops-approval-max-connections", description = "open delivery connections at most, one per OPS instance is the norm (default: ${DEFAULT-VALUE})")
  int maxConnections = 32;

  @Option(names = "--plugin-ops-approval-max-concurrent-calls", description = "delivery calls in flight per connection (default: ${DEFAULT-VALUE})")
  int maxConcurrentCalls = 32;

  /** {@code host:port}, or {@code [v6-address]:port}. */
  InetSocketAddress listenAddress() {
    final int colon = listen == null ? -1 : listen.lastIndexOf(':');
    if (colon <= 0 || colon == listen.length() - 1) {
      throw new IllegalArgumentException("--plugin-ops-approval-listen must be host:port, got '" + listen + "'");
    }
    String host = listen.substring(0, colon);
    if (host.startsWith("[") != host.endsWith("]")) {
      throw new IllegalArgumentException("--plugin-ops-approval-listen: unbalanced brackets in '" + listen + "'");
    }
    if (host.startsWith("[")) {
      host = host.substring(1, host.length() - 1);
    }
    final int port;
    try {
      port = Integer.parseInt(listen.substring(colon + 1));
    } catch (final NumberFormatException e) {
      throw new IllegalArgumentException("--plugin-ops-approval-listen: invalid port in '" + listen + "'", e);
    }
    if (port < 0 || port > 65_535) {
      throw new IllegalArgumentException("--plugin-ops-approval-listen: invalid port in '" + listen + "'");
    }
    return new InetSocketAddress(host, port);
  }

  AllowedSources allowedSources() {
    return sources == null ? AllowedSources.ANY : AllowedSources.parse(sources);
  }
}
