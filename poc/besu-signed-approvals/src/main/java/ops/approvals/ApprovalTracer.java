package ops.approvals;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Log;
import org.hyperledger.besu.datatypes.Transaction;
import org.hyperledger.besu.evm.Code;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.operation.Operation;
import org.hyperledger.besu.evm.worldstate.WorldView;
import org.hyperledger.besu.plugin.services.tracer.BlockAwareOperationTracer;

/**
 * Observes the actual frames of one candidate transaction and turns them into {@link CallRecord}s.
 * Attached to block building through {@code PluginTransactionSelector.getOperationTracer()} and to
 * preflight simulation through {@code TransactionSimulationService}; the same class feeds both
 * sides of the comparison. Not thread-safe: one instance per selector / simulation.
 */
public final class ApprovalTracer implements BlockAwareOperationTracer {
  /** What one transaction's execution looked like, as far as calls V3 cares. */
  public record Observation(
      Optional<Hash> txHash,
      List<CallRecord> records,
      Optional<String> lifecycle,
      Optional<String> error,
      boolean complete) {}

  private final List<CallRecord> records = new ArrayList<>();
  private final Deque<Integer> openRecords = new ArrayDeque<>();
  private final Deque<MessageFrame> openFrames = new ArrayDeque<>();
  private Hash txHash;
  private String lifecycle;
  private String error;
  private boolean ended;

  public Observation observation() {
    return new Observation(
        Optional.ofNullable(txHash),
        List.copyOf(records),
        Optional.ofNullable(lifecycle),
        Optional.ofNullable(error),
        ended && openFrames.isEmpty());
  }

  List<CallRecord> records() {
    return List.copyOf(records);
  }

  void reset() {
    records.clear();
    openRecords.clear();
    openFrames.clear();
    txHash = null;
    lifecycle = null;
    error = null;
    ended = false;
  }

  @Override
  public void traceStartTransaction(final WorldView worldView, final Transaction transaction) {
    reset();
    txHash = transaction.getHash();
  }

  @Override
  public void traceContextEnter(final MessageFrame frame) {
    if (error != null) {
      return;
    }
    if (records.size() >= CallsFingerprint.MAX_CALLS) {
      error = "more than " + CallsFingerprint.MAX_CALLS + " calls";
      return;
    }
    final MessageFrame parent = openFrames.peek();
    final int kind;
    if (frame.getType() == MessageFrame.Type.CONTRACT_CREATION) {
      kind = parent != null && "CREATE2".equals(opName(parent)) ? CallRecord.CREATE2 : CallRecord.CREATE;
      lifecycle = "contract creation";
    } else if (parent == null) {
      kind = CallRecord.CALL;
    } else {
      kind =
          switch (opName(parent)) {
            case "CALL" -> CallRecord.CALL;
            case "STATICCALL" -> CallRecord.STATICCALL;
            case "DELEGATECALL" -> CallRecord.DELEGATECALL;
            case "CALLCODE" -> CallRecord.CALLCODE;
            default -> -1;
          };
      if (kind < 0) {
        error = "frame entered by unsupported operation " + opName(parent);
        return;
      }
    }
    final Address from = parent == null ? frame.getSenderAddress() : parent.getRecipientAddress();
    final Code code = frame.getCode();
    record(
        new CallRecord(
            openRecords.isEmpty() ? CallRecord.ROOT_PARENT : openRecords.peek(),
            kind,
            from,
            frame.getContractAddress(),
            frame.getRecipientAddress(),
            code == null ? Hash.EMPTY : code.getCodeHash(),
            frame.getValue(),
            false,
            Bytes.wrap(frame.getInputData().toArray())));
    openRecords.push(records.size() - 1);
    openFrames.push(frame);
  }

  @Override
  public void tracePreExecution(final MessageFrame frame) {
    // Cheapest possible per-opcode hook: lifecycle opcodes are flagged before they run, so a
    // SELFDESTRUCT that EIP-6780 turns into a bare balance sweep, or a CREATE that fails before a
    // frame exists, is still a lifecycle event. Everything else is a single int compare.
    if (lifecycle != null) {
      return;
    }
    final Operation op = frame.getCurrentOperation();
    if (op == null) {
      return;
    }
    switch (op.getOpcode()) {
      case 0xF0, 0xF5 -> lifecycle = "contract creation";
      case 0xFF -> lifecycle = "selfdestruct";
      default -> {}
    }
  }

  @Override
  public void traceContextExit(final MessageFrame frame) {
    if (error != null || openFrames.isEmpty()) {
      return;
    }
    if (openFrames.peek() != frame) {
      error = "frame nesting mismatch";
      return;
    }
    openFrames.pop();
    final int index = openRecords.pop();
    if (frame.getState() == MessageFrame.State.COMPLETED_FAILED) {
      records.set(index, records.get(index).withFailed(true));
    }
  }

  @Override
  public void traceEndTransaction(
      final WorldView worldView,
      final Transaction tx,
      final boolean status,
      final Bytes output,
      final List<Log> logs,
      final long gasUsed,
      final Set<Address> selfDestructs,
      final long timeNs) {
    if (!selfDestructs.isEmpty()) {
      lifecycle = "selfdestruct";
    }
    if (!openFrames.isEmpty() && error == null) {
      error = "frames left open";
    }
    ended = true;
  }

  /** Test seam: the transaction-level end hook without a live EVM. */
  void markEnded() {
    ended = true;
  }

  /** Appends one observed frame; tests use it to observe without a live EVM. */
  void record(final CallRecord record) {
    records.add(record);
  }

  /** Test seam. */
  void markLifecycle(final String reason) {
    lifecycle = reason;
  }

  private static String opName(final MessageFrame frame) {
    final Operation op = frame.getCurrentOperation();
    return op == null ? "" : op.getName();
  }
}
