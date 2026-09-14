package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.base.Stopwatch;
import java.math.BigInteger;
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

  private final AtomicLong clock = new AtomicLong(100_000);
  private ApprovalStore store;
  private ApprovalTracer tracer;
  private ApprovalSelector selector;
  private Transaction tx;
  private List<CallRecord> records;
  private Hash fingerprint;

  @BeforeEach
  void setUp() throws Exception {
    store = new ApprovalStore(100, 60_000, clock::get);
    tracer = new ApprovalTracer();
    selector = new ApprovalSelector(store, CHAIN, WAIT, clock::get, tracer);
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
      tracer.markLifecycle("selfdestruct");
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
    store.put(approval(Approval.HASH_CALLS, fingerprint));
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
    store.put(approval(Approval.HASH_CALLS, fingerprint));
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

    store.put(approval(Approval.HASH_STRICT, fingerprint));
    final TransactionSelectionResult strict = selector.evaluateTransactionPreProcessing(ctx);
    assertTrue(strict.discard());
    assertEquals(Optional.of(ApprovalSelector.UNSUPPORTED), strict.maybeInvalidReason());
  }

  @Test
  void interruptedExecutionIsNeverSelected() {
    store.put(approval(Approval.HASH_CALLS, fingerprint));
    final TransactionEvaluationContext ctx = context(clock.get());
    execute(records, false, false); // all frames seen, but the transaction never ended
    assertTrue(selector.evaluateTransactionPostProcessing(ctx, result(false)).discard());
  }

  @Test
  void invalidProcessingResultIsNeverSelected() {
    store.put(approval(Approval.HASH_CALLS, fingerprint));
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
}
