package ops.approvals;

import io.grpc.Status;
import java.security.SecureRandom;
import java.util.EnumMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.LongSupplier;
import ops.approvals.grpc.StatusResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The receiver's side of the delivery contract (docs/implementation/approvals-wire-contract.md
 * §3–4), independent of the transport: checks a batch in the contract's order and answers with the
 * first failing check's status; a batch is all or nothing. {@link ApprovalServer} carries it over
 * gRPC.
 */
public final class ApprovalIngress {
  private static final Logger LOG = LoggerFactory.getLogger(ApprovalIngress.class);
  /** Check 6: how far ahead of this node's clock a batch's issued_at may be. */
  static final long MAX_ISSUED_AHEAD_MS = 5_000;
  /** The {@code ops-approval-reason} trailer of a refusal by a full store. */
  static final String STORE_FULL = "store-full";
  private static final long REFUSAL_LOG_INTERVAL_MS = 10_000;

  /**
   * What a delivery is answered with: the status code, a description for OPS's log, the approvals
   * stored (the batch size on OK) and, for a full store, the reason trailer.
   */
  public record Outcome(Status.Code code, String detail, int stored, String reason) {
    static Outcome refused(final Status.Code code, final String detail) {
      return new Outcome(code, detail, 0, null);
    }
  }

  /** Delivery counters; a no-op implementation is used in tests. */
  public interface Metrics {
    Metrics NONE = new Metrics() {};

    /** Every delivered batch, by the status it was answered with. */
    default void batch(Status.Code code) {}

    /** Approvals of an accepted batch. */
    default void stored(int approvals) {}
  }

  private final ApprovalVerifier verifier;
  private final long chainId;
  private final long maxTtlMs;
  private final ApprovalStore store;
  private final WaitWindow window;
  private final LongSupplier clock;
  private final Metrics metrics;
  private final String bootId = newBootId();
  private final Map<Status.Code, long[]> refusalLog = new EnumMap<>(Status.Code.class);
  private volatile boolean accepting = true;

  public ApprovalIngress(
      final ApprovalVerifier verifier,
      final long chainId,
      final long maxTtlMs,
      final ApprovalStore store,
      final WaitWindow window,
      final LongSupplier clock,
      final Metrics metrics) {
    this.verifier = verifier;
    this.chainId = chainId;
    this.maxTtlMs = maxTtlMs;
    this.store = store;
    this.window = window;
    this.clock = clock;
    this.metrics = metrics;
  }

  /** 128 random bits, drawn once per process start: OPS resends everything when it changes. */
  static String newBootId() {
    final byte[] id = new byte[16];
    new SecureRandom().nextBytes(id);
    return HexFormat.of().formatHex(id);
  }

  public String bootId() {
    return bootId;
  }

  public boolean accepting() {
    return accepting;
  }

  /** From now on every call is answered UNAVAILABLE: OPS retries, and resends after the restart. */
  public void stop() {
    accepting = false;
  }

  public Outcome deliver(final byte[] envelope) {
    Outcome outcome;
    try {
      outcome = accepting ? check(envelope) : Outcome.refused(Status.Code.UNAVAILABLE, "receiver stopping");
    } catch (final RuntimeException e) {
      LOG.error("OPS approval delivery failed", e);
      outcome = Outcome.refused(Status.Code.INTERNAL, "internal error");
    }
    metrics.batch(outcome.code());
    if (outcome.code() == Status.Code.OK) {
      metrics.stored(outcome.stored());
    }
    return outcome;
  }

  private Outcome check(final byte[] envelope) {
    final ApprovalBatch.Decoded batch;
    try {
      batch = ApprovalBatch.decode(envelope);
    } catch (final InvalidBatchException e) {
      return refuse(Status.Code.INVALID_ARGUMENT, e.getMessage(), null);
    }
    if (!verifier.trusts(batch.keyId())) {
      return refuse(Status.Code.PERMISSION_DENIED, "key id '" + batch.keyId() + "' is not trusted", batch);
    }
    if (!verifier.verify(batch)) {
      return refuse(Status.Code.UNAUTHENTICATED, "signature does not verify under key id '" + batch.keyId() + "'", batch);
    }
    for (final Approval a : batch.approvals()) {
      if (a.chainId() != chainId) {
        return refuse(Status.Code.INVALID_ARGUMENT, "approval for chain " + a.chainId() + ", this node is chain " + chainId, batch);
      }
    }
    // Unsigned: the fields are u64. Decoding guarantees expires_at > issued_at.
    final long ttl = batch.expiresAt() - batch.issuedAt();
    if (Long.compareUnsigned(ttl, maxTtlMs) > 0) {
      return refuse(
          Status.Code.INVALID_ARGUMENT,
          "TTL " + Long.toUnsignedString(ttl) + " ms exceeds this node's maximum of " + maxTtlMs + " ms",
          batch);
    }
    final long now = clock.getAsLong();
    if (Long.compareUnsigned(batch.issuedAt(), now + MAX_ISSUED_AHEAD_MS) > 0) {
      return refuse(
          Status.Code.FAILED_PRECONDITION,
          "issued_at is " + (batch.issuedAt() - now) + " ms ahead of this node's clock",
          batch);
    }
    if (Long.compareUnsigned(batch.expiresAt(), now) <= 0) {
      return refuse(Status.Code.FAILED_PRECONDITION, "expired " + (now - batch.expiresAt()) + " ms ago", batch);
    }
    if (!store.putAll(batch.keyId(), batch.issuedAt(), batch.expiresAt(), batch.approvals())) {
      logRefusal(Status.Code.UNAVAILABLE, "store full (" + store.size() + " of " + store.capacity() + ")", batch);
      return new Outcome(Status.Code.UNAVAILABLE, "store full", 0, STORE_FULL);
    }
    return new Outcome(Status.Code.OK, "", batch.approvals().size(), null);
  }

  private Outcome refuse(final Status.Code code, final String detail, final ApprovalBatch.Decoded batch) {
    logRefusal(code, detail, batch);
    return Outcome.refused(code, detail);
  }

  /**
   * One WARN per status per interval, counting the rest: a full store under load, or a sender with
   * a rotated-out key, would otherwise write a line per batch. The batches metric counts them all.
   */
  private void logRefusal(final Status.Code code, final String detail, final ApprovalBatch.Decoded batch) {
    final long now = clock.getAsLong();
    final long suppressed;
    synchronized (refusalLog) {
      final long[] state = refusalLog.computeIfAbsent(code, c -> new long[] {Long.MIN_VALUE / 2, 0});
      if (now - state[0] < REFUSAL_LOG_INTERVAL_MS) {
        state[1]++;
        return;
      }
      suppressed = state[1];
      state[0] = now;
      state[1] = 0;
    }
    LOG.warn(
        "OPS approval batch refused ({}): {}{}{}",
        code,
        detail,
        batch == null ? "" : "; " + batch.approvals().size() + " approvals under key id " + batch.keyId(),
        suppressed == 0 ? "" : " (and " + suppressed + " more with this status since the last line)");
  }

  /** Who this receiver is. The first call after boot also starts the restart wait window. */
  public StatusResponse status() {
    window.statusCalled(clock.getAsLong());
    return StatusResponse.newBuilder()
        .setBootId(bootId)
        .setChainId(chainId)
        .addAllTrustedKeyIds(verifier.keyIds())
        .setMaxTtlMs(maxTtlMs)
        .setCapacity(store.capacity())
        .setWaitMs(window.waitMs())
        .build();
  }
}
