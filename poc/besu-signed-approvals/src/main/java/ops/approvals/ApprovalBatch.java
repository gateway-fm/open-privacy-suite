package ops.approvals;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Delivery unit, byte-compatible with internal/nodeapproval.Batch: {@code OPS_APPROVAL_BATCH_V1\0}
 * ‖ u32 count ‖ count × 120-byte items ‖ 64-byte Ed25519 signature over everything before it. The
 * 4-byte frame length prefix is handled by the listener.
 */
public final class ApprovalBatch {
  static final byte[] DOMAIN = "OPS_APPROVAL_BATCH_V1\0".getBytes(StandardCharsets.US_ASCII);
  static final int MAX_APPROVALS = 32;
  static final int MAX_FRAME = 16384;
  static final int SIGNATURE_SIZE = 64;

  /** A structurally valid batch whose signature has not been checked yet. */
  public record Decoded(List<Approval> approvals, byte[] message, byte[] signature) {}

  private ApprovalBatch() {}

  public static Decoded decode(final byte[] body) throws InvalidBatchException {
    if (body.length > MAX_FRAME) {
      throw new InvalidBatchException("frame exceeds " + MAX_FRAME + " bytes");
    }
    final int header = DOMAIN.length + 4;
    if (body.length < header + Approval.ITEM_SIZE + SIGNATURE_SIZE) {
      throw new InvalidBatchException("frame too short");
    }
    if (!Arrays.equals(body, 0, DOMAIN.length, DOMAIN, 0, DOMAIN.length)) {
      throw new InvalidBatchException("unknown batch domain");
    }
    final ByteBuffer b = ByteBuffer.wrap(body);
    b.position(DOMAIN.length);
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
        List.copyOf(approvals),
        Arrays.copyOfRange(body, 0, messageLength),
        Arrays.copyOfRange(body, messageLength, body.length));
  }

  /** The signed bytes for a list of approvals (mirror of Go Batch.Message; used by tests). */
  static byte[] message(final List<Approval> approvals) {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(DOMAIN);
    out.writeBytes(ByteBuffer.allocate(4).putInt(approvals.size()).array());
    approvals.forEach(a -> out.writeBytes(a.message()));
    return out.toByteArray();
  }
}
