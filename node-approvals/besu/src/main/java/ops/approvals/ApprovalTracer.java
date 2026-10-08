package ops.approvals;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Log;
import org.hyperledger.besu.datatypes.Transaction;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.evm.Code;
import org.hyperledger.besu.evm.account.Account;
import org.hyperledger.besu.evm.frame.MessageFrame;
import org.hyperledger.besu.evm.internal.Words;
import org.hyperledger.besu.evm.operation.Operation;
import org.hyperledger.besu.evm.worldstate.WorldUpdater;
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
      boolean complete,
      StateSnapshot state) {}

  // EIP-161 has been active on every fork this plugin supports; EIP-8246 (Amsterdam) has not, so a
  // settled self-destruct still deletes the account. Both are asserted by the lifecycle scenarios.
  private static final boolean CLEAR_EMPTY_ACCOUNTS = true;
  private static final boolean SELFDESTRUCT_BALANCE_PRESERVED = false;

  private final List<CallRecord> records = new ArrayList<>();
  private final Deque<Integer> openRecords = new ArrayDeque<>();
  private final Deque<MessageFrame> openFrames = new ArrayDeque<>();
  private final Deque<List<int[]>> childLogRanges = new ArrayDeque<>();
  private StateSnapshot snapshot = new StateSnapshot();
  private WorldUpdater applicationState;
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
        ended && openFrames.isEmpty(),
        snapshot);
  }

  List<CallRecord> records() {
    return List.copyOf(records);
  }

  void reset() {
    records.clear();
    openRecords.clear();
    openFrames.clear();
    childLogRanges.clear();
    snapshot = new StateSnapshot();
    applicationState = null;
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
    // The value has not moved yet and a created account does not exist yet, so these reads are the
    // pre-transaction state for any account the execution reaches.
    touch(frame, from);
    touch(frame, frame.getRecipientAddress());
    touch(frame, frame.getContractAddress());
    if (frame.getType() == MessageFrame.Type.CONTRACT_CREATION) {
      snapshot.created(frame.getContractAddress());
    }
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
            // geth reports a creation frame's init code as its input; Besu keeps it in the frame's
            // code and leaves the input data empty.
            frame.getType() == MessageFrame.Type.CONTRACT_CREATION && code != null
                ? Bytes.wrap(code.getBytes().toArray())
                : Bytes.wrap(frame.getInputData().toArray())));
    openRecords.push(records.size() - 1);
    openFrames.push(frame);
    childLogRanges.push(new ArrayList<>());
  }

  /** Records an account's pre-transaction state, reading through the frame's own updater. */
  private void touch(final MessageFrame frame, final Address address) {
    if (address == null) {
      return;
    }
    final WorldUpdater updater = frame.getWorldUpdater();
    snapshot.before(
        address,
        () -> {
          final Account account = updater.get(address);
          return account == null
              ? StateSnapshot.AccountState.ABSENT
              : new StateSnapshot.AccountState(
                  account.getBalance(), account.getNonce(), account.getCode());
        });
  }

  @Override
  public void tracePreExecution(final MessageFrame frame) {
    lifecycleOpcode(frame);
    if (error != null || openFrames.isEmpty()) {
      return;
    }
    final Operation op = frame.getCurrentOperation();
    if (op == null) {
      return;
    }
    final WorldUpdater updater = frame.getWorldUpdater();
    switch (op.getOpcode()) {
      case 0x54, 0x55 -> { // SLOAD / SSTORE: the storage context is the frame's recipient
        final Address owner = frame.getRecipientAddress();
        final UInt256 key = UInt256.fromBytes(frame.getStackItem(0));
        touch(frame, owner);
        snapshot.beforeSlot(
            owner,
            key,
            () -> {
              final Account account = updater.get(owner);
              return account == null ? UInt256.ZERO : account.getStorageValue(key);
            });
      }
      case 0x31, 0x3b, 0x3c, 0x3f -> // BALANCE / EXTCODESIZE / EXTCODECOPY / EXTCODEHASH
          touch(frame, Words.toAddress(frame.getStackItem(0)));
      case 0xff -> { // SELFDESTRUCT: the beneficiary is only on the stack, and there is no frame
        final Address beneficiary = Words.toAddress(frame.getStackItem(0));
        final Address destroyed = frame.getRecipientAddress();
        touch(frame, beneficiary);
        touch(frame, destroyed);
        final Account account = updater.get(destroyed);
        // geth's callTracer reports the sweep as a child entry; Besu creates no frame for it.
        record(
            new CallRecord(
                openRecords.isEmpty() ? CallRecord.ROOT_PARENT : openRecords.peek(),
                CallRecord.SELFDESTRUCT,
                destroyed,
                beneficiary,
                destroyed,
                Hash.EMPTY,
                account == null ? Wei.ZERO : account.getBalance(),
                false,
                Bytes.EMPTY));
      }
      case 0xa0, 0xa1, 0xa2, 0xa3, 0xa4 -> touch(frame, frame.getRecipientAddress());
      default -> {
        // no state to record
      }
    }
  }

  /**
   * Lifecycle opcodes are flagged before they run, so a SELFDESTRUCT that EIP-6780 turns into a bare
   * balance sweep, or a CREATE that fails before a frame exists, is still a lifecycle event.
   */
  private void lifecycleOpcode(final MessageFrame frame) {
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
      default -> {
        // not a lifecycle operation
      }
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
    final List<int[]> ranges = childLogRanges.pop();
    final int index = openRecords.pop();
    final CallRecord seen = records.get(index);
    final boolean failed = frame.getState() == MessageFrame.State.COMPLETED_FAILED;
    records.set(
        index,
        new CallRecord(
            seen.parent(),
            seen.kind(),
            seen.from(),
            seen.to(),
            seen.storage(),
            seen.codeHash(),
            seen.value(),
            failed,
            seen.input(),
            Bytes.wrap(frame.getOutputData().toArray()),
            // A reverted frame's logs are discarded with its state changes, as geth reports them.
            failed ? List.of() : ownLogs(frame, ranges)));
    final MessageFrame parent = openFrames.peek();
    if (parent == null) {
      // Everything the application did is visible here and nothing Besu does afterwards — the gas
      // refund, the fee recipient's credit, self-destruct settlement — has happened yet.
      applicationState = frame.getWorldUpdater();
      snapshot.readAfter(
          address -> {
            final Account account = applicationState.get(address);
            return account == null
                ? StateSnapshot.AccountState.ABSENT
                : new StateSnapshot.AccountState(
                    account.getBalance(), account.getNonce(), account.getCode());
          },
          (address, key) -> {
            final Account account = applicationState.get(address);
            return account == null ? UInt256.ZERO : account.getStorageValue(key);
          });
    } else if (!failed) {
      // Besu copies a child's logs into its parent only when the child succeeds, so the parent's
      // list is its own logs with each successful child's subtree spliced in where it completed.
      childLogRanges.peek().add(new int[] {parent.getLogs().size(), frame.getLogs().size()});
    }
  }

  /** The logs this frame emitted itself, with the subtrees of its children removed. */
  private static List<Map<String, Object>> ownLogs(
      final MessageFrame frame, final List<int[]> childRanges) {
    final List<Log> all = frame.getLogs();
    if (all.isEmpty()) {
      return List.of();
    }
    final boolean[] fromChild = new boolean[all.size()];
    for (final int[] range : childRanges) {
      for (int i = range[0]; i < range[0] + range[1] && i < fromChild.length; i++) {
        fromChild[i] = true;
      }
    }
    final List<Map<String, Object>> out = new ArrayList<>();
    for (int i = 0; i < all.size(); i++) {
      if (fromChild[i]) {
        continue;
      }
      final Log log = all.get(i);
      final Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("address", log.getLogger().getBytes().toHexString());
      entry.put(
          "topics", log.getTopics().stream().map(t -> (Object) t.getBytes().toHexString()).toList());
      entry.put("data", log.getData().toHexString());
      out.add(entry);
    }
    return out;
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
    // Besu settles self-destructs and clears emptied accounts after this callback; the snapshot
    // applies the same two rules so it describes the state that will be committed.
    snapshot.settle(selfDestructs, SELFDESTRUCT_BALANCE_PRESERVED, CLEAR_EMPTY_ACCOUNTS);
    snapshot.overflow().ifPresent(reason -> error = error == null ? reason : error);
    if (lifecycle != null && records.stream().noneMatch(r -> r.kind() >= CallRecord.CREATE)) {
      // A lifecycle operation that produced no frame (a CREATE refused for depth or balance) cannot
      // be described by either fingerprint: neither side could agree on what was approved.
      error = error == null ? "lifecycle operation without an observable frame" : error;
    }
    ended = true;
  }

  /** Test seam: the transaction-level end hook without a live EVM. */
  void markEnded() {
    snapshot.settle(Set.of(), SELFDESTRUCT_BALANCE_PRESERVED, CLEAR_EMPTY_ACCOUNTS);
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
