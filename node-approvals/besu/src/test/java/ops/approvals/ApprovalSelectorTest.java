package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Stopwatch;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.crypto.KeyPair;
import org.hyperledger.besu.crypto.SignatureAlgorithmFactory;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Log;
import org.hyperledger.besu.datatypes.PendingTransaction;
import org.hyperledger.besu.datatypes.Transaction;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.Wei;
import org.hyperledger.besu.plugin.data.ProcessableBlockHeader;
import org.hyperledger.besu.plugin.data.TransactionProcessingResult;
import org.hyperledger.besu.plugin.data.TransactionSelectionResult;
import org.hyperledger.besu.plugin.services.txselection.TransactionEvaluationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ApprovalSelectorTest {
  private static final long CHAIN = 31337;
  private static final long WAIT = 5_000;

  private static final long TTL = 600_000;

  private final AtomicLong clock = new AtomicLong(100_000);
  private final List<String> decisions = new ArrayList<>();
  private long issued;
  private ApprovalStore store;
  private WaitWindow window;
  private ApprovalTracer tracer;
  private ApprovalSelector selector;
  private Transaction tx;
  private List<CallRecord> records;
  private Hash fingerprint;

  @BeforeEach
  void setUp() throws Exception {
    store = new ApprovalStore(100, 0, clock::get);
    // Booted long ago and OPS has called Status: every wait counts from pool admission.
    window = new WaitWindow(WAIT, 0);
    window.statusCalled(0);
    tracer = new ApprovalTracer();
    selector =
        new ApprovalSelector(
            store,
            CHAIN,
            window,
            clock::get,
            tracer,
            new ApprovalSelector.Metrics() {
              @Override
              public void decision(final String decision, final String reason) {
                decisions.add(decision + "/" + reason);
              }
            });
    final KeyPair keys = SignatureAlgorithmFactory.getInstance().generateKeyPair();
    tx =
        org.hyperledger.besu.ethereum.core.Transaction.builder()
            .type(TransactionType.FRONTIER)
            .chainId(BigInteger.valueOf(CHAIN))
            .nonce(0)
            .gasPrice(Wei.ONE)
            .gasLimit(100_000)
            .to(Address.fromHexString("0x1111111111111111111111111111111111111111"))
            .value(Wei.ZERO)
            .payload(Bytes.fromHexString("0x12345678"))
            .signAndBuild(keys);
    final JsonNode v = Fixtures.load("call-v3.json");
    final Map<Address, Hash> codes = Fixtures.codes(v.get("pre"));
    records = Fixtures.records(v.get("calls"), codes::get);
    fingerprint = Hash.fromHexString(v.get("expected_calls").asText());
  }

  private Approval approval(final int mode, final Hash fp) {
    return new Approval(mode, CHAIN, tx.getHash(), fp, Hash.ZERO);
  }

  /** Stores an approval signed now; each later one is issued later, so it replaces the last. */
  private void approve(final int mode, final Hash fp) {
    approve(mode, fp, TTL);
  }

  private void approve(final int mode, final Hash fp, final long ttl) {
    final long issuedAt = clock.get() + issued++;
    assertTrue(store.putAll("default", issuedAt, issuedAt + ttl, List.of(approval(mode, fp))));
  }

  private TransactionEvaluationContext context(final long addedAt) {
    final PendingTransaction pending =
        new PendingTransaction() {
          @Override
          public Transaction getTransaction() {
            return tx;
          }

          @Override
          public boolean isReceivedFromLocalSource() {
            return true;
          }

          @Override
          public boolean hasPriority() {
            return false;
          }

          @Override
          public long getAddedAt() {
            return addedAt;
          }

          @Override
          public int memorySize() {
            return 0;
          }

          @Override
          public String toTraceLog() {
            return "";
          }
        };
    return new TransactionEvaluationContext() {
      @Override
      public ProcessableBlockHeader getPendingBlockHeader() {
        return null;
      }

      @Override
      public PendingTransaction getPendingTransaction() {
        return pending;
      }

      @Override
      public Stopwatch getEvaluationTimer() {
        return Stopwatch.createStarted();
      }

      @Override
      public Wei getTransactionGasPrice() {
        return Wei.ONE;
      }

      @Override
      public Wei getMinGasPrice() {
        return Wei.ZERO;
      }

      @Override
      public boolean isCancelled() {
        return false;
      }
    };
  }

  /** A synthesised SELFDESTRUCT entry, as the tracer emits for the opcode. */
  private static CallRecord selfDestruct() {
    final Address contract = Address.fromHexString("0x" + "11".repeat(20));
    final Address beneficiary = Address.fromHexString("0x" + "22".repeat(20));
    return new CallRecord(
        0, CallRecord.SELFDESTRUCT, contract, beneficiary, contract, Hash.EMPTY, Wei.ZERO, false, Bytes.EMPTY);
  }

  private static TransactionProcessingResult result(final boolean invalid) {
    return new TransactionProcessingResult() {
      @Override
      public List<Log> getLogs() {
        return List.of();
      }

      @Override
      public long getGasRemaining() {
        return 0;
      }

      @Override
      public long getEstimateGasUsedByTransaction() {
        return 21_000;
      }

      @Override
      public Bytes getOutput() {
        return Bytes.EMPTY;
      }

      @Override
      public boolean isInvalid() {
        return invalid;
      }

      @Override
      public boolean isSuccessful() {
        return !invalid;
      }

      @Override
      public boolean isFailed() {
        return false;
      }

      @Override
      public Optional<Bytes> getRevertReason() {
        return Optional.empty();
      }

      @Override
      public Optional<String> getInvalidReason() {
        return invalid ? Optional.of("nonce") : Optional.empty();
      }
    };
  }

  /** Simulates Besu executing the candidate with our tracer attached. */
  private void execute(final List<CallRecord> observed, final boolean lifecycle) {
    execute(observed, lifecycle, true);
  }

  private void execute(final List<CallRecord> observed, final boolean lifecycle, final boolean ended) {
    tracer.traceStartTransaction(null, tx);
    observed.forEach(tracer::record);
    if (lifecycle) {
      tracer.record(selfDestruct());
    }
    if (ended) {
      tracer.markEnded();
    }
  }

  @Test
  void waitsThenDropsWithoutApproval() {
    final TransactionSelectionResult pending = selector.evaluateTransactionPreProcessing(context(clock.get() - 1));
    assertFalse(pending.selected());
    assertFalse(pending.discard());
    assertEquals(Optional.of(ApprovalSelector.PENDING), pending.maybeInvalidReason());

    final TransactionSelectionResult dropped =
        selector.evaluateTransactionPreProcessing(context(clock.get() - WAIT));
    assertTrue(dropped.discard());
    assertEquals(Optional.of(ApprovalSelector.TIMEOUT), dropped.maybeInvalidReason());
  }

  @Test
  void selectsOnlyWhenExecutionMatchesTheApproval() {
    approve(Approval.HASH_CALLS, fingerprint);
    final TransactionEvaluationContext ctx = context(clock.get() - WAIT * 10); // age is irrelevant once approved
    assertTrue(selector.evaluateTransactionPreProcessing(ctx).selected());
    execute(records, false);
    assertTrue(selector.evaluateTransactionPostProcessing(ctx, result(false)).selected());

    execute(records.subList(0, records.size() - 1), false);
    final TransactionSelectionResult mismatch = selector.evaluateTransactionPostProcessing(ctx, result(false));
    assertTrue(mismatch.discard());
    assertEquals(Optional.of(ApprovalSelector.MISMATCH), mismatch.maybeInvalidReason());
  }

  @Test
  void lifecycleUnsupportedModeAndVanishedApprovalFailClosed() {
    approve(Approval.HASH_CALLS, fingerprint);
    final TransactionEvaluationContext ctx = context(clock.get());
    assertTrue(selector.evaluateTransactionPreProcessing(ctx).selected());
    execute(records, true);
    final TransactionSelectionResult lifecycle = selector.evaluateTransactionPostProcessing(ctx, result(false));
    assertTrue(lifecycle.discard());
    assertEquals(Optional.of(ApprovalSelector.UNSUPPORTED), lifecycle.maybeInvalidReason());

    execute(records, false);
    store.removeAll(List.of(tx.getHash()));
    final TransactionSelectionResult vanished = selector.evaluateTransactionPostProcessing(ctx, result(false));
    assertTrue(vanished.discard());
    assertEquals(Optional.of(ApprovalSelector.MISMATCH), vanished.maybeInvalidReason());

    // A strict approval is a valid approval, but not for an execution that needs the calls mode.
    approve(Approval.HASH_STRICT, fingerprint);
    assertTrue(selector.evaluateTransactionPreProcessing(ctx).selected());
    execute(records, false);
    final TransactionSelectionResult wrongMode = selector.evaluateTransactionPostProcessing(ctx, result(false));
    assertTrue(wrongMode.discard());
    assertEquals(Optional.of(ApprovalSelector.UNSUPPORTED), wrongMode.maybeInvalidReason());
  }

  @Test
  void aLifecycleExecutionIsSelectedWhenItsStrictApprovalMatches() throws Exception {
    final ApprovalTracer observed = new ApprovalTracer();
    observed.traceStartTransaction(null, tx);
    records.forEach(observed::record);
    observed.record(selfDestruct());
    observed.markEnded();
    final Hash strictHash =
        StrictFingerprint.of(
            CallTreeJson.toTree(observed.records()),
            observed.observation().state().pre(),
            observed.observation().state().diff());

    final ApprovalSelector strictSelector =
        new ApprovalSelector(store, CHAIN, window, clock::get, observed, ApprovalSelector.Metrics.NONE);
    approve(Approval.HASH_STRICT, strictHash);
    final TransactionEvaluationContext ctx = context(clock.get());
    assertTrue(strictSelector.evaluateTransactionPostProcessing(ctx, result(false)).selected());

    approve(Approval.HASH_STRICT, Hash.ZERO);
    final TransactionSelectionResult mismatch =
        strictSelector.evaluateTransactionPostProcessing(ctx, result(false));
    assertTrue(mismatch.discard());
    assertEquals(Optional.of(ApprovalSelector.MISMATCH), mismatch.maybeInvalidReason());
  }

  @Test
  void interruptedExecutionIsNeverSelected() {
    approve(Approval.HASH_CALLS, fingerprint);
    final TransactionEvaluationContext ctx = context(clock.get());
    execute(records, false, false); // all frames seen, but the transaction never ended
    assertTrue(selector.evaluateTransactionPostProcessing(ctx, result(false)).discard());
  }

  @Test
  void invalidProcessingResultIsNeverSelected() {
    approve(Approval.HASH_CALLS, fingerprint);
    final TransactionEvaluationContext ctx = context(clock.get());
    execute(records, false); // a matching trace must not rescue an invalid result
    // Besu rejects invalid results before consulting plugins; we still never say yes to one.
    final TransactionSelectionResult invalid = selector.evaluateTransactionPostProcessing(ctx, result(true));
    assertTrue(invalid.discard());
    assertEquals(Optional.of(ApprovalSelector.MISMATCH), invalid.maybeInvalidReason());
  }

  @Test
  void tracerNeverTracesSystemCallsAndResetsPerTransaction() {
    assertFalse(tracer.isSystemCallTracingEnabled());
    execute(records, false);
    tracer.traceStartTransaction(null, tx);
    assertEquals(List.of(), tracer.records());
  }

  @Test
  void anExpiredApprovalCountsAsAbsent() {
    approve(Approval.HASH_CALLS, fingerprint, 1_000);
    final TransactionEvaluationContext ctx = context(clock.get());
    assertTrue(selector.evaluateTransactionPreProcessing(ctx).selected());
    clock.addAndGet(1_000); // now = expires_at: usable only while now < expires_at
    final TransactionSelectionResult waiting = selector.evaluateTransactionPreProcessing(ctx);
    assertFalse(waiting.selected());
    assertFalse(waiting.discard(), "within its wait window the transaction waits for a fresh approval");
    assertEquals(Optional.of(ApprovalSelector.PENDING), waiting.maybeInvalidReason());
    clock.addAndGet(WAIT);
    final TransactionSelectionResult dropped = selector.evaluateTransactionPreProcessing(ctx);
    assertTrue(dropped.discard());
    assertEquals(Optional.of(ApprovalSelector.TIMEOUT), dropped.maybeInvalidReason());
  }

  @Test
  void anApprovalThatExpiresDuringExecutionIsNotSelected() {
    approve(Approval.HASH_CALLS, fingerprint, 1);
    final TransactionEvaluationContext ctx = context(clock.get());
    assertTrue(selector.evaluateTransactionPreProcessing(ctx).selected());
    execute(records, false);
    clock.addAndGet(1); // expires between pre- and post-processing
    final TransactionSelectionResult post = selector.evaluateTransactionPostProcessing(ctx, result(false));
    assertFalse(post.selected());
    assertFalse(post.discard());
    assertEquals(Optional.of(ApprovalSelector.PENDING), post.maybeInvalidReason());
  }

  @Test
  void anApprovalSweptForExpiryDuringExecutionCountsAsAbsentNotVanished() {
    approve(Approval.HASH_CALLS, fingerprint, 1);
    final TransactionEvaluationContext ctx = context(clock.get());
    assertTrue(selector.evaluateTransactionPreProcessing(ctx).selected());
    execute(records, false);
    clock.addAndGet(1);
    assertEquals(1, store.evictExpired()); // the sweeper runs while the candidate executes
    final TransactionSelectionResult post = selector.evaluateTransactionPostProcessing(ctx, result(false));
    assertFalse(post.discard(), "expired, not vanished: the transaction waits out its window");
    assertEquals(Optional.of(ApprovalSelector.PENDING), post.maybeInvalidReason());
  }

  @Test
  void afterARestartTheWaitCountsFromTheFirstStatusCall() {
    final WaitWindow booted = new WaitWindow(WAIT, clock.get());
    final ApprovalSelector fresh =
        new ApprovalSelector(store, CHAIN, booted, clock::get, tracer, ApprovalSelector.Metrics.NONE);
    // Re-announced by an RPC node right after the restart, long before OPS has resent anything.
    final TransactionEvaluationContext ctx = context(clock.get());
    clock.addAndGet(2 * WAIT);
    final TransactionSelectionResult early = fresh.evaluateTransactionPreProcessing(ctx);
    assertFalse(early.discard(), "OPS has not called Status yet: keep waiting");
    booted.statusCalled(clock.get());
    clock.addAndGet(WAIT - 1);
    assertFalse(fresh.evaluateTransactionPreProcessing(ctx).discard(), "the window runs from the Status call");
    clock.addAndGet(1);
    final TransactionSelectionResult late = fresh.evaluateTransactionPreProcessing(ctx);
    assertTrue(late.discard());
    assertEquals(Optional.of(ApprovalSelector.TIMEOUT), late.maybeInvalidReason());
  }

  @Test
  void everyDecisionIsCountedAsAllowWaitDropOrDeny() {
    final TransactionEvaluationContext fresh = context(clock.get());
    selector.evaluateTransactionPreProcessing(fresh);
    selector.evaluateTransactionPreProcessing(context(clock.get() - WAIT));
    approve(Approval.HASH_CALLS, fingerprint);
    assertTrue(selector.evaluateTransactionPreProcessing(fresh).selected());
    execute(records, false);
    assertTrue(selector.evaluateTransactionPostProcessing(fresh, result(false)).selected());
    execute(records.subList(0, 1), false);
    selector.evaluateTransactionPostProcessing(fresh, result(false));
    assertEquals(List.of("wait/pending", "drop/timeout", "allow/matched", "deny/mismatch"), decisions);
  }
}
