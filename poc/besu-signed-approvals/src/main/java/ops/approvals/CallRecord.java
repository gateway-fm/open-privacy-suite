package ops.approvals;

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
 * @param input full calldata
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
    Bytes input) {
  public static final int ROOT_PARENT = -1;
  public static final int CALL = 1;
  public static final int STATICCALL = 2;
  public static final int DELEGATECALL = 3;
  public static final int CALLCODE = 4;
  public static final int CREATE = 5;
  public static final int CREATE2 = 6;

  static String typeName(final int kind) {
    return switch (kind) {
      case CALL -> "CALL";
      case STATICCALL -> "STATICCALL";
      case DELEGATECALL -> "DELEGATECALL";
      case CALLCODE -> "CALLCODE";
      case CREATE -> "CREATE";
      case CREATE2 -> "CREATE2";
      default -> "UNKNOWN";
    };
  }

  CallRecord withParent(final int p) {
    return new CallRecord(p, kind, from, to, storage, codeHash, value, failed, input);
  }

  CallRecord withKind(final int k) {
    return new CallRecord(parent, k, from, to, storage, codeHash, value, failed, input);
  }

  CallRecord withFrom(final Address a) {
    return new CallRecord(parent, kind, a, to, storage, codeHash, value, failed, input);
  }

  CallRecord withStorage(final Address a) {
    return new CallRecord(parent, kind, from, to, a, codeHash, value, failed, input);
  }

  CallRecord withCodeHash(final Hash h) {
    return new CallRecord(parent, kind, from, to, storage, h, value, failed, input);
  }

  CallRecord withValue(final Wei v) {
    return new CallRecord(parent, kind, from, to, storage, codeHash, v, failed, input);
  }

  CallRecord withFailed(final boolean f) {
    return new CallRecord(parent, kind, from, to, storage, codeHash, value, f, input);
  }

  CallRecord withInput(final Bytes i) {
    return new CallRecord(parent, kind, from, to, storage, codeHash, value, failed, i);
  }
}
