package ops.approvals;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

/**
 * Ed25519 batch signature check against the producer's set of trusted OPS keys, selected by the
 * key id the batch names. Uses Besu's Bouncy Castle library directly, without changing global JCA
 * providers. A batch under an unknown id verifies as false: refusal is the safe outcome for a key
 * the operator has not (or no longer) trusted.
 */
public final class ApprovalVerifier {
  private final Map<String, byte[]> keys;

  /** @param rawPublicKeys key id → 32-byte RFC 8032 public key encoding, as OPS prints it */
  public ApprovalVerifier(final Map<String, byte[]> rawPublicKeys) {
    if (rawPublicKeys.isEmpty()) {
      throw new IllegalArgumentException("at least one trusted OPS public key is required");
    }
    final Map<String, byte[]> copied = new HashMap<>();
    rawPublicKeys.forEach((id, raw) -> {
      if (raw.length != Ed25519.PUBLIC_KEY_SIZE) {
        throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
      }
      copied.put(id, raw.clone());
    });
    keys = Map.copyOf(copied);
  }

  /** Whether a key id is in the trusted set; checked before the signature (wire contract §3). */
  public boolean trusts(final String keyId) {
    return keys.containsKey(keyId);
  }

  /** The trusted key ids, sorted, as {@code Status} reports them. */
  public List<String> keyIds() {
    return keys.keySet().stream().sorted().toList();
  }

  public boolean verify(final ApprovalBatch.Decoded batch) {
    final byte[] key = keys.get(batch.keyId());
    // The decoder enforces this too. The low-level API reads a fixed-size slice, so reject
    // truncated or extended signatures explicitly rather than padding or ignoring bytes.
    if (key == null || batch.signature().length != Ed25519.SIGNATURE_SIZE) {
      return false;
    }
    return Ed25519.verify(batch.signature(), 0, key, 0, batch.message(), 0, batch.message().length);
  }
}
