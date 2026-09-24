package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.datatypes.Hash;
import org.junit.jupiter.api.Test;

/**
 * Approvals are released when their block is <em>final</em>, not when it is merely added: a block
 * that is reorganised away returns its transactions to the pool, and they must still find their
 * approvals there. Expiry bounds it: a block drops its approvals when they expire, and its link
 * once no approval can still be alive.
 */
class InclusionTrackerTest {
  private static final long NOW = 1_800_000_000_000L;
  /** How long a block's link is kept: the maximum TTL plus the 5 s issue skew. */
  private static final long LINK = 3_605_000;
  private static final long LATER = NOW + 60_000;

  private static Hash h(final int v) {
    return Hash.wrap(Bytes32.leftPad(Bytes.of(v)));
  }

  @Test
  void releasesOnlyTheFinalizedChainAndKeepsReorgedBlocks() {
    final InclusionTracker tracker = new InclusionTracker(LINK);
    // Canonical: genesis(0) <- A1(11) <- A2(12). Fork: genesis <- B1(21).
    tracker.recordIncluded(h(11), h(0), 1, List.of(h(101), h(102)), LATER, NOW);
    tracker.recordIncluded(h(21), h(0), 1, List.of(h(201)), LATER, NOW);
    tracker.recordIncluded(h(12), h(11), 2, List.of(h(103)), LATER, NOW);

    // Nothing is final yet: nothing is released.
    assertTrue(tracker.finalizedUpTo(Optional.empty()).isEmpty());

    // A1 becomes final: its transactions are released; A2 and the fork are not.
    Set<Hash> released = tracker.finalizedUpTo(Optional.of(h(11)));
    assertEquals(Set.of(h(101), h(102)), released);
    assertEquals(2, tracker.trackedBlocks());

    // A2 becomes final: released; the fork block B1 stays tracked until it is dropped explicitly,
    // and its approvals are never released by finality of another chain.
    released = tracker.finalizedUpTo(Optional.of(h(12)));
    assertEquals(Set.of(h(103)), released);
    assertEquals(1, tracker.trackedBlocks());
    assertEquals(Set.of(h(201)), tracker.forget(h(21)));
    assertEquals(0, tracker.trackedBlocks());
  }

  @Test
  void finalityJumpingSeveralBlocksReleasesTheWholeSegmentOnce() {
    final InclusionTracker tracker = new InclusionTracker(LINK);
    tracker.recordIncluded(h(11), h(0), 1, List.of(h(101)), LATER, NOW);
    tracker.recordIncluded(h(12), h(11), 2, List.of(h(102)), LATER, NOW);
    tracker.recordIncluded(h(13), h(12), 3, List.of(h(103)), LATER, NOW);
    assertEquals(Set.of(h(101), h(102), h(103)), tracker.finalizedUpTo(Optional.of(h(13))));
    assertTrue(tracker.finalizedUpTo(Optional.of(h(13))).isEmpty());
  }

  @Test
  void aBlockReplacedAtTheSameHeightIsNotConfusedWithItsRival() {
    final InclusionTracker tracker = new InclusionTracker(LINK);
    tracker.recordIncluded(h(11), h(0), 1, List.of(h(101)), LATER, NOW);
    tracker.recordIncluded(h(21), h(0), 1, List.of(h(201)), LATER, NOW); // reorg: rival at height 1
    assertEquals(Set.of(h(201)), tracker.finalizedUpTo(Optional.of(h(21))));
    // The losing block's transactions are back in the pool and keep their approvals.
    assertEquals(1, tracker.trackedBlocks());
  }

  @Test
  void emptyBlocksDoNotCutTheWalkFromTheFinalizedHead() {
    // Finality jumps whole epochs and often lands on an empty block: the walk must pass through it.
    final InclusionTracker tracker = new InclusionTracker(LINK);
    tracker.recordIncluded(h(11), h(0), 1, List.of(h(101)), NOW + 1_000, NOW);
    tracker.recordIncluded(h(12), h(11), 2, List.of(), NOW, NOW);
    tracker.recordIncluded(h(13), h(12), 3, List.of(), NOW, NOW);
    assertEquals(Set.of(h(101)), tracker.finalizedUpTo(Optional.of(h(13))));
    assertEquals(0, tracker.trackedBlocks());
  }

  @Test
  void aBlockDropsItsApprovalsAtTheirExpiryButKeepsItsLinkForTheMaximumTtl() {
    // With finality lagging for hours, expiry is what bounds the tracking — without cutting the
    // chain: a block whose approvals expired still links an older block with longer-lived ones.
    final InclusionTracker tracker = new InclusionTracker(LINK);
    tracker.recordIncluded(h(11), h(0), 1, List.of(h(101)), NOW + 50_000, NOW);
    tracker.recordIncluded(h(12), h(11), 2, List.of(h(102)), NOW + 1_000, NOW);
    tracker.recordIncluded(h(13), h(12), 3, List.of(h(103)), NOW + 50_000, NOW);
    assertEquals(0, tracker.forgetExpired(NOW + 1_000), "block 12 keeps its link");
    assertEquals(3, tracker.trackedBlocks());
    assertEquals(Set.of(h(101), h(103)), tracker.finalizedUpTo(Optional.of(h(13))), "102 expired and is gone already");

    final InclusionTracker old = new InclusionTracker(LINK);
    old.recordIncluded(h(11), h(0), 1, List.of(h(101)), NOW + 1_000, NOW);
    assertEquals(0, old.forgetExpired(NOW + LINK - 1));
    assertEquals(1, old.forgetExpired(NOW + LINK), "no approval can outlive the maximum TTL: the link goes");
    assertTrue(old.finalizedUpTo(Optional.of(h(11))).isEmpty());
  }
}
