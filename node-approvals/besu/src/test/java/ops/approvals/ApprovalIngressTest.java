package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.grpc.Status;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import ops.approvals.grpc.StatusResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The receiver's checks, in the order and with the status codes of the wire contract §3
 * (docs/implementation/approvals-wire-contract.md). A batch is all or nothing.
 */
class ApprovalIngressTest {
  private static final long MAX_TTL = 3_600_000;
  private static final long TTL = 600_000;
  private static final long WAIT = 5_000;

  private final AtomicLong clock = new AtomicLong(1_800_000_000_000L);
  private final List<Status.Code> counted = new ArrayList<>();
  private final List<Integer> storedCounts = new ArrayList<>();
  private ApprovalStore store;
  private WaitWindow window;
  private ApprovalIngress ingress;

  @BeforeEach
  void setUp() {
    store = new ApprovalStore(100, WAIT, clock::get);
    window = new WaitWindow(WAIT, clock.get());
    ingress = ingress(store);
  }

  private ApprovalIngress ingress(final ApprovalStore target) {
    return new ApprovalIngress(
        new ApprovalVerifier(Map.of("default", Fixtures.FIXTURE_PUBLIC_KEY, "next", Fixtures.FIXTURE_PUBLIC_KEY.clone())),
        Fixtures.CHAIN,
        MAX_TTL,
        target,
        window,
        clock::get,
        new ApprovalIngress.Metrics() {
          @Override
          public void batch(final Status.Code code) {
            counted.add(code);
          }

          @Override
          public void stored(final int approvals) {
            storedCounts.add(approvals);
          }
        });
  }

  private long now() {
    return clock.get();
  }

  private byte[] batch(final Approval... approvals) {
    return Fixtures.envelope("default", now(), now() + TTL, List.of(approvals));
  }

  private static void assertRefused(final Status.Code code, final ApprovalIngress.Outcome outcome, final String what) {
    assertEquals(code, outcome.code(), what + ": " + outcome.detail());
    assertEquals(0, outcome.stored(), what);
  }

  @Test
  void storesEveryApprovalOfAValidBatchAndAnswersOkWithTheCount() {
    final ApprovalIngress.Outcome outcome = ingress.deliver(batch(Fixtures.approval(1, 1), Fixtures.approval(2, 2)));
    assertEquals(Status.Code.OK, outcome.code(), outcome.detail());
    assertEquals(2, outcome.stored());
    assertTrue(store.get(Fixtures.hash(1)).isPresent());
    assertTrue(store.get(Fixtures.hash(2)).isPresent());
    assertEquals(now() + TTL, store.get(Fixtures.hash(1)).orElseThrow().expiresAt());
    assertEquals(List.of(Status.Code.OK), counted);
    assertEquals(List.of(2), storedCounts);
  }

  @Test
  void acceptsTheGoSignedGoldenBatches() throws Exception {
    clock.set(Fixtures.GOLDEN_ISSUED_AT + 1_000);
    for (final String name : List.of("batch.json", "call-batch.json")) {
      final ApprovalIngress.Outcome outcome = ingress.deliver(Fixtures.goldenEnvelope(name));
      assertEquals(Status.Code.OK, outcome.code(), name + ": " + outcome.detail());
      assertEquals(Fixtures.goldenApprovals(name).size(), outcome.stored(), name);
    }
  }

  @Test
  void eachCheckAnswersWithItsContractStatusAndStoresNothing() {
    final Approval a = Fixtures.approval(1, 1);
    final byte[] valid = batch(a);

    // 1. Decodes.
    assertRefused(Status.Code.INVALID_ARGUMENT, ingress.deliver(new byte[] {1, 2, 3}), "garbage");
    final byte[] wrongDomain = valid.clone();
    wrongDomain[0] = 'X';
    assertRefused(Status.Code.INVALID_ARGUMENT, ingress.deliver(wrongDomain), "unknown domain");
    assertRefused(
        Status.Code.INVALID_ARGUMENT, ingress.deliver(Fixtures.envelope("default", now(), now(), List.of(a))), "expires_at = issued_at");
    // 2. The key id is trusted.
    assertRefused(
        Status.Code.PERMISSION_DENIED,
        ingress.deliver(Fixtures.envelope("rotated-out", now(), now() + TTL, List.of(a))),
        "untrusted key id");
    // 3. The signature verifies under that key.
    final byte[] flipped = valid.clone();
    flipped[flipped.length - 1] ^= 1;
    assertRefused(Status.Code.UNAUTHENTICATED, ingress.deliver(flipped), "flipped signature byte");
    assertRefused(
        Status.Code.UNAUTHENTICATED,
        ingress.deliver(Fixtures.envelope(Fixtures.seed(9), "default", now(), now() + TTL, List.of(a))),
        "signed by another key under a trusted id");
    // 4. Every approval is for this chain.
    assertRefused(
        Status.Code.INVALID_ARGUMENT,
        ingress.deliver(Fixtures.envelope("default", now(), now() + TTL, List.of(a, Fixtures.approval(1, 2, 2)))),
        "an approval for chain 1");
    // 5. expires_at - issued_at within the maximum TTL; no clock involved.
    assertRefused(
        Status.Code.INVALID_ARGUMENT,
        ingress.deliver(Fixtures.envelope("default", now() - 10 * MAX_TTL, now() - 9 * MAX_TTL + 1, List.of(a))),
        "TTL above the maximum, even though long expired");
    // 6. issued_at at most 5 s ahead of this node's clock.
    assertRefused(
        Status.Code.FAILED_PRECONDITION,
        ingress.deliver(Fixtures.envelope("default", now() + 5_001, now() + TTL, List.of(a))),
        "issued 5.001 s ahead");
    // 7. expires_at still in the future.
    assertRefused(
        Status.Code.FAILED_PRECONDITION,
        ingress.deliver(Fixtures.envelope("default", now() - TTL, now(), List.of(a))),
        "expires now");
    assertEquals(0, store.size(), "no refused batch may store anything");

    // The boundaries themselves are accepted.
    assertEquals(Status.Code.OK, ingress.deliver(Fixtures.envelope("default", now(), now() + MAX_TTL, List.of(a))).code(), "TTL = max");
    assertEquals(
        Status.Code.OK,
        ingress.deliver(Fixtures.envelope("default", now() + 5_000, now() + TTL, List.of(Fixtures.approval(2, 2)))).code(),
        "issued exactly 5 s ahead");
    assertEquals(
        Status.Code.OK,
        ingress.deliver(Fixtures.envelope("default", now() - TTL, now() + 1, List.of(Fixtures.approval(3, 3)))).code(),
        "expires 1 ms from now");
  }

  @Test
  void aFullStoreAnswersUnavailableWithTheStoreFullReason() {
    final ApprovalStore tiny = new ApprovalStore(1, WAIT, clock::get);
    final ApprovalIngress small = ingress(tiny);
    assertEquals(Status.Code.OK, small.deliver(batch(Fixtures.approval(1, 1))).code());
    final ApprovalIngress.Outcome full = small.deliver(batch(Fixtures.approval(2, 2)));
    assertRefused(Status.Code.UNAVAILABLE, full, "store full");
    assertEquals(ApprovalIngress.STORE_FULL, full.reason());
    assertTrue(tiny.get(Fixtures.hash(2)).isEmpty());
  }

  @Test
  void checksRunInContractOrderAndTheFirstFailureAnswers() {
    final Approval foreign = Fixtures.approval(1, 1, 1);
    // Untrusted key, bad signature, wrong chain and expired: the key id is checked first.
    final byte[] everything = Fixtures.envelope(Fixtures.seed(9), "rotated-out", now() - TTL, now() - 1, List.of(foreign));
    assertEquals(Status.Code.PERMISSION_DENIED, ingress.deliver(everything).code());
    // Bad signature and wrong chain: the signature comes first.
    final byte[] forged = Fixtures.envelope(Fixtures.seed(9), "default", now(), now() + TTL, List.of(foreign));
    assertEquals(Status.Code.UNAUTHENTICATED, ingress.deliver(forged).code());
    // Wrong chain and a TTL above the maximum: both INVALID_ARGUMENT, the chain is reported.
    final ApprovalIngress.Outcome chain =
        ingress.deliver(Fixtures.envelope("default", now(), now() + MAX_TTL + 1, List.of(foreign)));
    assertEquals(Status.Code.INVALID_ARGUMENT, chain.code());
    assertTrue(chain.detail().contains("chain"), chain.detail());
    // TTL above the maximum and issued ahead of the clock: the TTL needs no clock and comes first.
    final ApprovalIngress.Outcome ttl =
        ingress.deliver(Fixtures.envelope("default", now() + 60_000, now() + 60_000 + MAX_TTL + 1, List.of(Fixtures.approval(1, 1))));
    assertEquals(Status.Code.INVALID_ARGUMENT, ttl.code());
    assertTrue(ttl.detail().contains("TTL"), ttl.detail());
    // Expired and a full store: the expiry is checked before the store.
    final ApprovalStore tiny = new ApprovalStore(1, WAIT, clock::get);
    final ApprovalIngress small = ingress(tiny);
    assertEquals(Status.Code.OK, small.deliver(batch(Fixtures.approval(1, 1))).code());
    assertEquals(
        Status.Code.FAILED_PRECONDITION,
        small.deliver(Fixtures.envelope("default", now() - TTL, now() - 1, List.of(Fixtures.approval(2, 2)))).code());
  }

  @Test
  void aBatchIsAllOrNothing() {
    // Room for one of two new approvals: neither is stored.
    final ApprovalStore two = new ApprovalStore(2, WAIT, clock::get);
    final ApprovalIngress small = ingress(two);
    assertEquals(Status.Code.OK, small.deliver(batch(Fixtures.approval(1, 1))).code());
    assertEquals(Status.Code.UNAVAILABLE, small.deliver(batch(Fixtures.approval(2, 2), Fixtures.approval(3, 3))).code());
    assertTrue(two.get(Fixtures.hash(2)).isEmpty());
    assertTrue(two.get(Fixtures.hash(3)).isEmpty());
    // One approval for another chain refuses its valid neighbours too.
    assertEquals(
        Status.Code.INVALID_ARGUMENT,
        ingress.deliver(batch(Fixtures.approval(4, 4), Fixtures.approval(1, 5, 5))).code());
    assertTrue(store.get(Fixtures.hash(4)).isEmpty());
  }

  @Test
  void redeliveryIsIdempotentAndLateApprovalsAreStored() {
    final byte[] envelope = batch(Fixtures.approval(1, 1), Fixtures.approval(2, 2));
    assertEquals(Status.Code.OK, ingress.deliver(envelope).code());
    final ApprovalStore.Stored first = store.get(Fixtures.hash(1)).orElseThrow();
    final ApprovalIngress.Outcome again = ingress.deliver(envelope);
    assertEquals(Status.Code.OK, again.code());
    assertEquals(2, again.stored(), "stored = n, also when nothing changed");
    assertEquals(2, store.size());
    assertEquals(first, store.get(Fixtures.hash(1)).orElseThrow());

    // The pool already dropped this transaction: its approval is stored anyway, it may return.
    store.pooled(Fixtures.hash(7));
    store.unpooled(Fixtures.hash(7));
    assertEquals(Status.Code.OK, ingress.deliver(batch(Fixtures.approval(7, 7))).code());
    assertTrue(store.get(Fixtures.hash(7)).isPresent());
  }

  @Test
  void statusDescribesTheReceiverAndStartsTheRestartWaitWindow() {
    final StatusResponse status = ingress.status();
    assertEquals(ingress.bootId(), status.getBootId());
    assertEquals(Fixtures.CHAIN, status.getChainId());
    assertEquals(List.of("default", "next"), status.getTrustedKeyIdsList());
    assertEquals(MAX_TTL, status.getMaxTtlMs());
    assertEquals(100, status.getCapacity());
    assertEquals(WAIT, status.getWaitMs());
    // A transaction pooled before this first Status call waits from the call, not from admission.
    assertEquals(now(), window.startOf(now() - 30_000));
  }

  @Test
  void theBootIdIsRandom128BitHexAndStableForTheProcess() {
    final String boot = ingress.bootId();
    assertTrue(boot.matches("[0-9a-f]{32}"), boot);
    assertEquals(boot, ingress.bootId());
    assertEquals(boot, ingress.status().getBootId());
    assertNotEquals(boot, ingress(store).bootId(), "a new process start draws a new boot id");
  }

  @Test
  void aStoppingReceiverAnswersUnavailable() {
    assertTrue(ingress.accepting());
    ingress.stop();
    assertFalse(ingress.accepting());
    final ApprovalIngress.Outcome outcome = ingress.deliver(batch(Fixtures.approval(1, 1)));
    assertRefused(Status.Code.UNAVAILABLE, outcome, "stopping");
    assertNull(outcome.reason(), "not a full store: nothing to back off from but the restart");
    assertEquals(0, store.size());
  }

  @Test
  void theEnvelopeIsCappedAtTheLongestValidBatch() {
    final List<Approval> most = new ArrayList<>();
    for (int i = 0; i < ApprovalBatch.MAX_APPROVALS; i++) {
      most.add(Fixtures.approval(100 + i, i));
    }
    final byte[] longest = Fixtures.envelope("k".repeat(ApprovalBatch.MAX_KEY_ID), now(), now() + TTL, most);
    assertEquals(ApprovalBatch.MAX_ENVELOPE, longest.length);
    final byte[] tooLong = Arrays.copyOf(longest, longest.length + 1);
    assertRefused(Status.Code.INVALID_ARGUMENT, ingress.deliver(tooLong), "one byte beyond the longest batch");
  }
}
