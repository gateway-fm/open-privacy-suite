package ops.approvals;

import picocli.CommandLine.Option;

/** {@code --plugin-ops-approval-*} command line options. Same meanings as the Reth PoC env vars. */
final class PluginOptions {
  @Option(names = "--plugin-ops-approval-listen", description = "host:port for OPS approval delivery (required)")
  String listen;

  @Option(names = "--plugin-ops-approval-public-key", description = "hex Ed25519 public key of the OPS signer (required)")
  String publicKey;

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
