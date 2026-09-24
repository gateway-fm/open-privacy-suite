package ops.approvals;

import java.util.Optional;
import java.util.function.LongSupplier;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.PendingTransaction;
import org.hyperledger.besu.plugin.data.TransactionProcessingResult;
import org.hyperledger.besu.plugin.data.TransactionSelectionResult;
import org.hyperledger.besu.plugin.services.tracer.BlockAwareOperationTracer;
import org.hyperledger.besu.plugin.services.txselection.PluginTransactionSelector;
import org.hyperledger.besu.plugin.services.txselection.TransactionEvaluationContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The producer gate. Pre-processing: no usable approval → wait (keep in pool) until the wait
 * window ends, then drop. An approval is usable while now &lt; expires_at; an expired one counts
 * as absent (wire contract §6). Post-processing: the approval must still be usable, and the actual
 * execution's fingerprint must equal the approved one, otherwise Besu rolls the candidate back.
 * Every exceptional path is a rejection.
 */
public final class ApprovalSelector implements PluginTransactionSelector {
  static final String PENDING = "OPS_APPROVAL_PENDING";
  static final String TIMEOUT = "OPS_APPROVAL_TIMEOUT";
  static final String MISMATCH = "OPS_APPROVAL_MISMATCH";
  static final String UNSUPPORTED = "OPS_APPROVAL_UNSUPPORTED";
  private static final Logger LOG = LoggerFactory.getLogger(ApprovalSelector.class);

  private final ApprovalStore store;
  private final long chainId;
  private final WaitWindow window;
  private final LongSupplier clock;
  private final ApprovalTracer tracer;
  private final Metrics metrics;

  /** Counters the plugin reports; a no-op implementation is used in tests. */
  public interface Metrics {
    Metrics NONE = new Metrics() {};

    /**
     * One producer decision, as the decision log names it — allow, wait, drop or deny — with its
     * reason: matched, pending, timeout, mismatch or unsupported.
     */
    default void decision(String decision, String reason) {}
  }

  public ApprovalSelector(
      final ApprovalStore store,
      final long chainId,
      final WaitWindow window,
      final LongSupplier clock,
      final ApprovalTracer tracer,
      final Metrics metrics) {
    this.store = store;
    this.chainId = chainId;
    this.window = window;
    this.clock = clock;
    this.tracer = tracer;
    this.metrics = metrics;
  }

  /** Calls V3 unless the execution created or destroyed a contract, which only strict V2 binds. */
  static int requiredMode(final ApprovalTracer.Observation seen) {
    final boolean lifecycle =
        seen.records().stream().anyMatch(record -> record.kind() >= CallRecord.CREATE);
    return lifecycle ? Approval.HASH_STRICT : Approval.HASH_CALLS;
  }

  @Override
  public BlockAwareOperationTracer getOperationTracer() {
    return tracer;
  }

  private long gateNanos;
  /** The expiry of the approval pre-processing let through; Besu evaluates one candidate at a time. */
  private long selectedExpiresAt = Long.MIN_VALUE;

  @Override
  public TransactionSelectionResult evaluateTransactionPreProcessing(
      final TransactionEvaluationContext context) {
    final long started = System.nanoTime();
    tracer.reset(); // never compare against frames of an earlier candidate
    selectedExpiresAt = Long.MIN_VALUE;
    final PendingTransaction pending = context.getPendingTransaction();
    final Hash txHash = pending.getTransaction().getHash();
    final Optional<ApprovalStore.Stored> stored = store.get(txHash);
    gateNanos = System.nanoTime() - started;
    final long now = clock.getAsLong();
    if (stored.isEmpty() || !stored.get().usableAt(now)) {
      return absent(pending, txHash, now, stored.isPresent());
    }
    selectedExpiresAt = stored.get().expiresAt();
    final Approval a = stored.get().approval();
    if (a.chainId() != chainId || !Approval.validMode(a.hashMode())) {
      // Unreachable through the ingress, which refuses foreign chains and unknown modes.
      return reject(txHash, UNSUPPORTED, "approval mode " + a.hashMode() + " chain " + a.chainId());
    }
    return TransactionSelectionResult.SELECTED;
  }

  /**
   * No usable approval: wait while the window lasts (Besu keeps the transaction and asks again at
   * the next candidate build), then drop it. An approval that exists but has expired is the same
   * case; OPS may still deliver a fresh one within the window.
   */
  private TransactionSelectionResult absent(
      final PendingTransaction pending, final Hash txHash, final long now, final boolean expired) {
    final long waited = now - pending.getAddedAt();
    final String approval = expired ? " approval=expired" : "";
    if (window.timedOut(pending.getAddedAt(), now)) {
      LOG.info("OPS_APPROVAL_DECISION drop tx={} waited_ms={}{}", txHash, waited, approval);
      metrics.decision("drop", "timeout");
      return TransactionSelectionResult.invalid(TIMEOUT);
    }
    LOG.info("OPS_APPROVAL_DECISION wait tx={} waited_ms={}{}", txHash, waited, approval);
    metrics.decision("wait", "pending");
    return TransactionSelectionResult.invalidTransient(PENDING);
  }

  @Override
  public TransactionSelectionResult evaluateTransactionPostProcessing(
      final TransactionEvaluationContext context, final TransactionProcessingResult result) {
    final long postStarted = System.nanoTime();
    final Hash txHash = context.getPendingTransaction().getTransaction().getHash();
    if (result.isInvalid()) {
      // Besu's ProcessingResultTransactionSelector rejects these before we are consulted; if that
      // order ever changed, nothing executed and nothing was compared, so still say no.
      return reject(txHash, MISMATCH, "transaction invalid: " + result.getInvalidReason().orElse("?"));
    }
    final Optional<ApprovalStore.Stored> stored = store.get(txHash);
    final long now = clock.getAsLong();
    if (stored.isEmpty() || !stored.get().usableAt(now)) {
      // Expired while the candidate executed — still held, or already swept by the store's expiry
      // pass: commit time decides, as at pre-processing, and the transaction waits out its window.
      if (stored.isPresent() || (selectedExpiresAt != Long.MIN_VALUE && now >= selectedExpiresAt)) {
        return absent(context.getPendingTransaction(), txHash, now, true);
      }
      return reject(txHash, MISMATCH, "approval vanished before commit");
    }
    final Approval approval = stored.get().approval();
    if (approval.chainId() != chainId || !Approval.validMode(approval.hashMode())) {
      return reject(txHash, UNSUPPORTED, "approval replaced by an unsupported one");
    }
    final ApprovalTracer.Observation seen = tracer.observation();
    if (seen.txHash().isEmpty() || !seen.txHash().get().getBytes().equals(txHash.getBytes())) {
      return reject(txHash, MISMATCH, "tracer did not observe this transaction");
    }
    if (seen.error().isPresent()) {
      return reject(txHash, MISMATCH, seen.error().get());
    }
    if (!seen.complete()) {
      // Interrupted or partially traced execution: nothing to compare against.
      return reject(txHash, MISMATCH, "execution not fully observed");
    }
    // The execution decides which fingerprint applies; the approval must have been issued for that
    // same mode, so a calls approval can never cover an execution that deploys or self-destructs.
    final int required = requiredMode(seen);
    if (approval.hashMode() != required) {
      return reject(
          txHash,
          UNSUPPORTED,
          "approval mode " + approval.hashMode() + ", execution requires " + required);
    }
    final Hash actual;
    try {
      actual =
          required == Approval.HASH_STRICT
              ? StrictFingerprint.of(
                  CallTreeJson.toTree(seen.records()), seen.state().pre(), seen.state().diff())
              : CallsFingerprint.of(seen.records());
    } catch (final UnsupportedExecutionException | RuntimeException e) {
      return reject(txHash, UNSUPPORTED, String.valueOf(e.getMessage()));
    }
    if (!actual.getBytes().equals(approval.fingerprint().getBytes())) {
      return reject(txHash, MISMATCH, "approved " + approval.fingerprint() + " actual " + actual);
    }
    metrics.decision("allow", "matched");
    LOG.info("OPS_APPROVAL_DECISION allow tx={} calls={}", txHash, seen.records().size());
    LOG.info(
        "OPS_APPROVAL_TIMING {\"tx\":\"{}\",\"mode\":{},\"calls\":{},\"gate_ns\":{}}",
        txHash,
        required,
        seen.records().size(),
        gateNanos + (System.nanoTime() - postStarted));
    return TransactionSelectionResult.SELECTED;
  }

  private TransactionSelectionResult reject(final Hash txHash, final String code, final String detail) {
    LOG.info("OPS_APPROVAL_DECISION deny tx={} reason={} detail={}", txHash, code, detail);
    metrics.decision("deny", code.equals(UNSUPPORTED) ? "unsupported" : "mismatch");
    return TransactionSelectionResult.invalid(code);
  }
}
