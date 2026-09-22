package ops.approvals;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Delivery unit, byte-compatible with internal/nodeapproval.Batch: {@code OPS_APPROVAL_BATCH_V2\0}
 * ‖ u8 key-id length ‖ key id ‖ u32 count ‖ count × 120-byte items ‖ 64-byte Ed25519 signature over
 * everything before it. The key id names which of the producer's trusted keys signed, and is inside
 * the signed bytes. The 4-byte frame length prefix is handled by the listener.
 */
public final class ApprovalBatch {
  static final byte[] DOMAIN = "OPS_APPROVAL_BATCH_V2\0".getBytes(StandardCharsets.US_ASCII);
  static final int MAX_KEY_ID = 64;
  static final int MAX_APPROVALS = 32;
  static final int MAX_FRAME = 16384;
  static final int SIGNATURE_SIZE = 64;

  /** A structurally valid batch whose signature has not been checked yet. */
  public record Decoded(String keyId, List<Approval> approvals, byte[] message, byte[] signature) {}

  private ApprovalBatch() {}

  public static Decoded decode(final byte[] body) throws InvalidBatchException {
    if (body.length > MAX_FRAME) {
      throw new InvalidBatchException("frame exceeds " + MAX_FRAME + " bytes");
    }
    if (body.length < DOMAIN.length + 1 + 1 + 4 + Approval.ITEM_SIZE + SIGNATURE_SIZE) {
      throw new InvalidBatchException("frame too short");
    }
    if (!Arrays.equals(body, 0, DOMAIN.length, DOMAIN, 0, DOMAIN.length)) {
      throw new InvalidBatchException("unknown batch domain");
    }
    final ByteBuffer b = ByteBuffer.wrap(body);
    b.position(DOMAIN.length);
    final int keyLength = Byte.toUnsignedInt(b.get());
    if (keyLength < 1 || keyLength > MAX_KEY_ID || b.remaining() < keyLength + 4) {
      throw new InvalidBatchException("invalid key id length " + keyLength);
    }
    final byte[] keyBytes = new byte[keyLength];
    b.get(keyBytes);
    final String keyId = new String(keyBytes, StandardCharsets.US_ASCII);
    if (!PluginOptions.validKeyId(keyId)) {
      throw new InvalidBatchException("invalid key id");
    }
    final int header = DOMAIN.length + 1 + keyLength + 4;
    final long count = Integer.toUnsignedLong(b.getInt());
    if (count < 1 || count > MAX_APPROVALS) {
      throw new InvalidBatchException("invalid approval count " + count);
    }
    final int messageLength = header + (int) count * Approval.ITEM_SIZE;
    if (body.length != messageLength + SIGNATURE_SIZE) {
      throw new InvalidBatchException("frame length does not match approval count");
    }
    final List<Approval> approvals = new ArrayList<>((int) count);
    for (int i = 0; i < count; i++) {
      approvals.add(Approval.parse(b));
    }
    return new Decoded(
        keyId,
        List.copyOf(approvals),
        Arrays.copyOfRange(body, 0, messageLength),
        Arrays.copyOfRange(body, messageLength, body.length));
  }

  /** The signed bytes for a list of approvals (mirror of Go Batch.Message; used by tests). */
  static byte[] message(final String keyId, final List<Approval> approvals) {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(DOMAIN);
    final byte[] key = keyId.getBytes(StandardCharsets.US_ASCII);
    out.write(key.length);
    out.writeBytes(key);
    out.writeBytes(ByteBuffer.allocate(4).putInt(approvals.size()).array());
    approvals.forEach(a -> out.writeBytes(a.message()));
    return out.toByteArray();
  }
}
