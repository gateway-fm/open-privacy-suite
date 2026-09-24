package ops.approvals;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Ed25519 batch signature check against the producer's set of trusted OPS keys, selected by the
 * key id the batch names (JDK provider). A batch under an unknown id verifies as false: refusal is
 * the safe outcome for a key the operator has not (or no longer) trusted.
 */
public final class ApprovalVerifier {
  private final Map<String, PublicKey> keys;

  /** @param rawPublicKeys key id → 32-byte RFC 8032 public key encoding, as OPS prints it */
  public ApprovalVerifier(final Map<String, byte[]> rawPublicKeys) {
    if (rawPublicKeys.isEmpty()) {
      throw new IllegalArgumentException("at least one trusted OPS public key is required");
    }
    final Map<String, PublicKey> parsed = new HashMap<>();
    rawPublicKeys.forEach((id, raw) -> parsed.put(id, parse(raw)));
    keys = Map.copyOf(parsed);
  }

  private static PublicKey parse(final byte[] rawPublicKey) {
    if (rawPublicKey.length != 32) {
      throw new IllegalArgumentException("Ed25519 public key must be 32 bytes");
    }
    final byte[] littleEndian = rawPublicKey.clone();
    final boolean xOdd = (littleEndian[31] & 0x80) != 0;
    littleEndian[31] &= 0x7f;
    final byte[] bigEndian = new byte[32];
    for (int i = 0; i < 32; i++) {
      bigEndian[i] = littleEndian[31 - i];
    }
    try {
      return KeyFactory.getInstance("Ed25519")
          .generatePublic(
              new EdECPublicKeySpec(
                  NamedParameterSpec.ED25519,
                  new EdECPoint(xOdd, new BigInteger(1, bigEndian))));
    } catch (final GeneralSecurityException e) {
      throw new IllegalArgumentException("invalid Ed25519 public key", e);
    }
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
    final PublicKey key = keys.get(batch.keyId());
    return key != null && verify(key, batch.message(), batch.signature());
  }

  private static boolean verify(final PublicKey key, final byte[] message, final byte[] signature) {
    try {
      final Signature s = Signature.getInstance("Ed25519"); // instances are not thread-safe
      s.initVerify(key);
      s.update(message);
      return s.verify(signature);
    } catch (final GeneralSecurityException e) {
      return false;
    }
  }
}
