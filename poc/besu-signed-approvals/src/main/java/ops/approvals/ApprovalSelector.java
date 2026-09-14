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
 * The producer gate. Pre-processing: no verified approval → wait (keep in pool) until the deadline
 * measured from pool admission, then drop. Post-processing: the actual execution's calls-V3
 * fingerprint must equal the approved one, otherwise Besu rolls the candidate back and the pool
 * discards it. Every exceptional path is a rejection.
 */
public final class ApprovalSelector implements PluginTransactionSelector {
  static final String PENDING = "OPS_APPROVAL_PENDING";
  static final String TIMEOUT = "OPS_APPROVAL_TIMEOUT";
  static final String MISMATCH = "OPS_APPROVAL_MISMATCH";
  static final String UNSUPPORTED = "OPS_APPROVAL_UNSUPPORTED";
  private static final Logger LOG = LoggerFactory.getLogger(ApprovalSelector.class);

  private final ApprovalStore store;
  private final long chainId;
  private final long waitMs;
  private final LongSupplier clock;
  private final ApprovalTracer tracer;
  private final Metrics metrics;

  /** Counters the plugin reports; a no-op implementation is used in tests. */
  public interface Metrics {
    Metrics NONE = new Metrics() {};

    default void pending() {}

    default void timeout() {}

    default void mismatch(String reason) {}

    default void matched() {}
  }

  public ApprovalSelector(
      final ApprovalStore store,
      final long chainId,
      final long waitMs,
      final LongSupplier clock,
      final ApprovalTracer tracer) {
    this(store, chainId, waitMs, clock, tracer, Metrics.NONE);
  }

  public ApprovalSelector(
      final ApprovalStore store,
      final long chainId,
      final long waitMs,
      final LongSupplier clock,
      final ApprovalTracer tracer,
      final Metrics metrics) {
    this.store = store;
    this.chainId = chainId;
    this.waitMs = waitMs;
    this.clock = clock;
    this.tracer = tracer;
    this.metrics = metrics;
  }

  @Override
  public BlockAwareOperationTracer getOperationTracer() {
    return tracer;
  }

  @Override
  public TransactionSelectionResult evaluateTransactionPreProcessing(
      final TransactionEvaluationContext context) {
    tracer.reset(); // never compare against frames of an earlier candidate
    final PendingTransaction pending = context.getPendingTransaction();
    final Hash txHash = pending.getTransaction().getHash();
    final Optional<Approval> approval = store.get(txHash);
    if (approval.isEmpty()) {
      final long waited = clock.getAsLong() - pending.getAddedAt();
      if (waited >= waitMs) {
        LOG.info("OPS_APPROVAL_DECISION drop tx={} waited_ms={}", txHash, waited);
        metrics.timeout();
        return TransactionSelectionResult.invalid(TIMEOUT);
      }
      LOG.info("OPS_APPROVAL_DECISION wait tx={} waited_ms={}", txHash, waited);
      metrics.pending();
      return TransactionSelectionResult.invalidTransient(PENDING);
    }
    final Approval a = approval.get();
    if (a.chainId() != chainId || a.hashMode() != Approval.HASH_CALLS) {
      LOG.warn("OPS_APPROVAL_DECISION unsupported tx={} mode={} chain={}", txHash, a.hashMode(), a.chainId());
      metrics.mismatch(UNSUPPORTED);
      return TransactionSelectionResult.invalid(UNSUPPORTED);
    }
    return TransactionSelectionResult.SELECTED;
  }

  @Override
  public TransactionSelectionResult evaluateTransactionPostProcessing(
      final TransactionEvaluationContext context, final TransactionProcessingResult result) {
    final Hash txHash = context.getPendingTransaction().getTransaction().getHash();
    if (result.isInvalid()) {
      // Besu's ProcessingResultTransactionSelector rejects these before we are consulted; if that
      // order ever changed, nothing executed and nothing was compared, so still say no.
      return reject(txHash, MISMATCH, "transaction invalid: " + result.getInvalidReason().orElse("?"));
    }
    final Optional<Approval> approval = store.get(txHash);
    if (approval.isEmpty()) {
      return reject(txHash, MISMATCH, "approval vanished before commit");
    }
    if (approval.get().chainId() != chainId || approval.get().hashMode() != Approval.HASH_CALLS) {
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
    if (seen.lifecycle().isPresent()) {
      return reject(txHash, UNSUPPORTED, seen.lifecycle().get());
    }
    final Hash actual;
    try {
      actual = CallsFingerprint.of(seen.records());
    } catch (final UnsupportedExecutionException e) {
      return reject(txHash, UNSUPPORTED, e.getMessage());
    }
    if (!actual.getBytes().equals(approval.get().fingerprint().getBytes())) {
      return reject(txHash, MISMATCH, "approved " + approval.get().fingerprint() + " actual " + actual);
    }
    metrics.matched();
    LOG.info("OPS_APPROVAL_DECISION allow tx={} calls={}", txHash, seen.records().size());
    return TransactionSelectionResult.SELECTED;
  }

  private TransactionSelectionResult reject(final Hash txHash, final String code, final String detail) {
    LOG.info("OPS_APPROVAL_DECISION deny tx={} reason={} detail={}", txHash, code, detail);
    metrics.mismatch(code);
    return TransactionSelectionResult.invalid(code);
  }
}
