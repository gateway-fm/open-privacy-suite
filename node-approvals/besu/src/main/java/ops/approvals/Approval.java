package ops.approvals;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.hyperledger.besu.datatypes.Hash;

/**
 * One signed-approval item, byte-compatible with internal/nodeapproval.Approval.Message(): 16-byte
 * mode domain, u64 chain id, tx hash, execution fingerprint, 32 reserved bytes. Senders write zeros
 * into the reserved field; it is signed over and otherwise ignored (wire contract §2).
 */
public record Approval(int hashMode, long chainId, Hash txHash, Hash fingerprint, Hash reserved) {
  public static final int HASH_STRICT = 0;
  public static final int HASH_CALLS = 3;
  static final int ITEM_SIZE = 120;
  private static final byte[] DOMAIN_STRICT = "OPS_APPROVAL_V1\0".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] DOMAIN_CALLS = "OPS_APPROVAL_V3\0".getBytes(StandardCharsets.US_ASCII);

  public Approval {
    if (!validMode(hashMode)) {
      throw new IllegalArgumentException("unknown approval hash mode " + hashMode);
    }
  }

  static boolean validMode(final int mode) {
    return mode == HASH_STRICT || mode == HASH_CALLS;
  }

  public byte[] message() {
    final ByteBuffer b = ByteBuffer.allocate(ITEM_SIZE);
    b.put(hashMode == HASH_CALLS ? DOMAIN_CALLS : DOMAIN_STRICT);
    b.putLong(chainId);
    b.put(txHash.getBytes().toArrayUnsafe());
    b.put(fingerprint.getBytes().toArrayUnsafe());
    b.put(reserved.getBytes().toArrayUnsafe());
    return b.array();
  }

  static Approval parse(final ByteBuffer b) throws InvalidBatchException {
    if (b.remaining() < ITEM_SIZE) {
      throw new InvalidBatchException("truncated approval item");
    }
    final byte[] domain = new byte[DOMAIN_STRICT.length];
    b.get(domain);
    final int mode;
    if (Arrays.equals(domain, DOMAIN_CALLS)) {
      mode = HASH_CALLS;
    } else if (Arrays.equals(domain, DOMAIN_STRICT)) {
      mode = HASH_STRICT;
    } else {
      throw new InvalidBatchException("unknown approval domain");
    }
    final long chain = b.getLong();
    return new Approval(mode, chain, hash(b), hash(b), hash(b));
  }

  private static Hash hash(final ByteBuffer b) {
    final byte[] out = new byte[32];
    b.get(out);
    return Hash.wrap(org.apache.tuweni.bytes.Bytes32.wrap(out));
  }
}
