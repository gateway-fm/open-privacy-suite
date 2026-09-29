package ops.approvals;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Hash;

/**
 * Calls-V3 fingerprint. Byte-for-byte the encoding of internal/nodeapproval.CallFingerprint and
 * the Reth module's call_hash.rs: domain ‖ u32 count ‖ per record (u32 parent ‖ u8 kind ‖ from ‖
 * to ‖ storage ‖ code hash ‖ u256 value ‖ u8 failed ‖ u32 len ‖ input), keccak256.
 */
public final class CallsFingerprint {
  private static final byte[] DOMAIN = "OPS_CALLS_V3\0".getBytes(StandardCharsets.US_ASCII);
  static final int MAX_CALLS = 128;
  static final int MAX_BYTES = 1 << 20;
  private static final int FIXED_RECORD_BYTES = 4 + 1 + 20 * 3 + 32 + 32 + 1 + 4; // 134

  private CallsFingerprint() {}

  public static Hash of(final List<CallRecord> records) throws UnsupportedExecutionException {
    if (records.isEmpty()) {
      throw new UnsupportedExecutionException("no executed frames");
    }
    if (records.size() > MAX_CALLS) {
      throw new UnsupportedExecutionException("more than " + MAX_CALLS + " calls");
    }
    final ByteArrayOutputStream buf = new ByteArrayOutputStream(512);
    buf.writeBytes(DOMAIN);
    buf.writeBytes(u32(records.size()));
    for (final CallRecord r : records) {
      if (r.kind() < CallRecord.CALL || r.kind() > CallRecord.CALLCODE) {
        throw new UnsupportedExecutionException(
            "lifecycle/unknown operation under call-only approval: " + CallRecord.typeName(r.kind()));
      }
      if (buf.size() + FIXED_RECORD_BYTES + r.input().size() > MAX_BYTES) {
        throw new UnsupportedExecutionException("call fingerprint exceeds 1 MiB");
      }
      buf.writeBytes(u32(r.parent() == CallRecord.ROOT_PARENT ? 0xffffffff : r.parent()));
      buf.write(r.kind());
      buf.writeBytes(r.from().getBytes().toArrayUnsafe());
      buf.writeBytes(r.to().getBytes().toArrayUnsafe());
      buf.writeBytes(r.storage().getBytes().toArrayUnsafe());
      buf.writeBytes(r.codeHash().getBytes().toArrayUnsafe());
      buf.writeBytes(r.value().toBytes().toArrayUnsafe());
      buf.write(r.failed() ? 1 : 0);
      buf.writeBytes(u32(r.input().size()));
      buf.writeBytes(r.input().toArrayUnsafe());
    }
    return Hash.hash(Bytes.wrap(buf.toByteArray()));
  }

  private static byte[] u32(final int v) {
    return ByteBuffer.allocate(4).putInt(v).array();
  }
}
