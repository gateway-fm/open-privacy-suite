package ops.approvals;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EdECPoint;
import java.security.spec.EdECPublicKeySpec;
import java.security.spec.NamedParameterSpec;

/** Ed25519 batch signature check against the single configured OPS public key (JDK provider). */
public final class ApprovalVerifier {
  private final PublicKey key;

  /** @param rawPublicKey the 32-byte RFC 8032 encoding, as OPS prints it */
  public ApprovalVerifier(final byte[] rawPublicKey) {
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
      key =
          KeyFactory.getInstance("Ed25519")
              .generatePublic(
                  new EdECPublicKeySpec(
                      NamedParameterSpec.ED25519,
                      new EdECPoint(xOdd, new BigInteger(1, bigEndian))));
    } catch (final GeneralSecurityException e) {
      throw new IllegalArgumentException("invalid Ed25519 public key", e);
    }
  }

  public boolean verify(final ApprovalBatch.Decoded batch) {
    return verify(batch.message(), batch.signature());
  }

  public boolean verify(final byte[] message, final byte[] signature) {
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
