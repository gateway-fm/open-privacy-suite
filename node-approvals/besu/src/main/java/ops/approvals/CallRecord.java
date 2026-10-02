package ops.approvals;

import java.util.List;
import java.util.Map;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;

/**
 * One executed message frame, in enter order. Exactly the facts calls-V3 binds (see
 * internal/nodeapproval/call_fingerprint.go); outputs, logs, storage and gas are deliberately
 * absent.
 *
 * @param parent index of the enclosing record, {@link #ROOT_PARENT} for the transaction's root frame
 * @param kind {@link #CALL} … {@link #CREATE2}; only 1–4 are hashable
 * @param from the caller as geth reports it: tx sender for the root, else the parent's storage
 *     address
 * @param to the executed code address
 * @param storage the account whose storage the frame runs in
 * @param codeHash keccak of the executed code (keccak("") for accounts without code)
 * @param value ETH transferred by the call (zero for STATICCALL/DELEGATECALL)
 * @param failed the frame ended in revert or exceptional halt, even if the caller caught it
 * @param input full calldata (the init code for CREATE/CREATE2)
 * @param output return data (the deployed code for CREATE/CREATE2); strict V2 only
 * @param logs events emitted directly by this frame, geth-shaped; strict V2 only
 */
public record CallRecord(
    int parent,
    int kind,
    Address from,
    Address to,
    Address storage,
    Hash codeHash,
    Wei value,
    boolean failed,
    Bytes input,
    Bytes output,
    List<Map<String, Object>> logs) {
  /** A frame with no return data and no logs: everything calls V3 needs. */
  public CallRecord(
      final int parent,
      final int kind,
      final Address from,
      final Address to,
      final Address storage,
      final Hash codeHash,
      final Wei value,
      final boolean failed,
      final Bytes input) {
    this(parent, kind, from, to, storage, codeHash, value, failed, input, Bytes.EMPTY, List.of());
  }

  public static final int ROOT_PARENT = -1;
  public static final int CALL = 1;
  public static final int STATICCALL = 2;
  public static final int DELEGATECALL = 3;
  public static final int CALLCODE = 4;
  public static final int CREATE = 5;
  public static final int CREATE2 = 6;
  public static final int SELFDESTRUCT = 7;

  static String typeName(final int kind) {
    return switch (kind) {
      case CALL -> "CALL";
      case STATICCALL -> "STATICCALL";
      case DELEGATECALL -> "DELEGATECALL";
      case CALLCODE -> "CALLCODE";
      case CREATE -> "CREATE";
      case CREATE2 -> "CREATE2";
      case SELFDESTRUCT -> "SELFDESTRUCT";
      default -> "UNKNOWN";
    };
  }

  CallRecord withParent(final int p) {
    return new CallRecord(p, kind, from, to, storage, codeHash, value, failed, input, output, logs);
  }

  CallRecord withKind(final int k) {
    return new CallRecord(parent, k, from, to, storage, codeHash, value, failed, input, output, logs);
  }

  CallRecord withFrom(final Address a) {
    return new CallRecord(parent, kind, a, to, storage, codeHash, value, failed, input, output, logs);
  }

  CallRecord withStorage(final Address a) {
    return new CallRecord(parent, kind, from, to, a, codeHash, value, failed, input, output, logs);
  }

  CallRecord withCodeHash(final Hash h) {
    return new CallRecord(parent, kind, from, to, storage, h, value, failed, input, output, logs);
  }

  CallRecord withValue(final Wei v) {
    return new CallRecord(parent, kind, from, to, storage, codeHash, v, failed, input, output, logs);
  }

  CallRecord withFailed(final boolean f) {
    return new CallRecord(parent, kind, from, to, storage, codeHash, value, f, input, output, logs);
  }

  CallRecord withInput(final Bytes i) {
    return new CallRecord(parent, kind, from, to, storage, codeHash, value, failed, i, output, logs);
  }
}
