package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.Map;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;
import org.junit.jupiter.api.Test;

/** The geth-shaped `pre` / `diff` objects the strict fingerprint consumes. */
class StateSnapshotTest {
  private static final Address A = Address.fromHexString("0x" + "11".repeat(20));
  private static final Address B = Address.fromHexString("0x" + "22".repeat(20));
  private static final UInt256 SLOT = UInt256.ZERO;
  private static final UInt256 OTHER_SLOT = UInt256.ONE;

  /** A tiny mutable world the snapshot reads "after" values from. */
  private static final class World {
    final Map<Address, StateSnapshot.AccountState> accounts = new HashMap<>();
    final Map<Address, Map<UInt256, UInt256>> storage = new HashMap<>();

    World set(final Address a, final long balance, final long nonce, final String code) {
      accounts.put(a, new StateSnapshot.AccountState(Wei.of(balance), nonce, Bytes.fromHexString(code)));
      return this;
    }

    World slot(final Address a, final UInt256 key, final long value) {
      storage.computeIfAbsent(a, k -> new HashMap<>()).put(key, UInt256.valueOf(value));
      return this;
    }

    void into(final StateSnapshot snapshot, final boolean balancePreserved, final boolean clearEmpty) {
      into(snapshot, balancePreserved, clearEmpty, java.util.Set.of());
    }

    void into(
        final StateSnapshot snapshot,
        final boolean balancePreserved,
        final boolean clearEmpty,
        final java.util.Set<Address> selfDestructs) {
      snapshot.readAfter(
          a -> accounts.get(a),
          (a, key) -> storage.getOrDefault(a, Map.of()).getOrDefault(key, UInt256.ZERO));
      snapshot.settle(selfDestructs, balancePreserved, clearEmpty);
    }
  }

  private static StateSnapshot.AccountState account(final long balance, final long nonce, final String code) {
    return new StateSnapshot.AccountState(Wei.of(balance), nonce, Bytes.fromHexString(code));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> at(final Map<String, Object> m, final String... path) {
    Map<String, Object> current = m;
    for (final String key : path) {
      current = (Map<String, Object>) current.get(key);
    }
    return current;
  }

  @Test
  void aSlotThatWasOnlyReadIsBoundButNotReportedAsChanged() {
    final StateSnapshot s = new StateSnapshot();
    s.before(A, () -> account(5, 1, "0x6000"));
    s.beforeSlot(A, SLOT, () -> UInt256.valueOf(7));
    new World().set(A, 5, 1, "0x6000").slot(A, SLOT, 7).into(s, false, false);

    assertEquals(UInt256.valueOf(7).toHexString(), at(s.pre(), A.getBytes().toHexString(), "storage").get(word(SLOT)));
    assertTrue(s.diff().isEmpty() || at(s.diff(), "pre").isEmpty(), "unchanged account is not in the diff");
  }

  @Test
  void writtenSlotsAndBalancesAppearOnBothSidesOfTheDiff() {
    final StateSnapshot s = new StateSnapshot();
    s.before(A, () -> account(5, 1, "0x6000"));
    s.beforeSlot(A, SLOT, () -> UInt256.ZERO);
    s.before(B, () -> account(0, 0, "0x"));
    new World().set(A, 3, 1, "0x6000").slot(A, SLOT, 9).set(B, 2, 0, "0x").into(s, false, false);

    assertEquals(UInt256.ZERO.toHexString(), at(s.pre(), A.getBytes().toHexString(), "storage").get(word(SLOT)));
    assertEquals(UInt256.valueOf(9).toHexString(), at(s.diff(), "post", A.getBytes().toHexString(), "storage").get(word(SLOT)));
    assertEquals(UInt256.ZERO.toHexString(), at(s.diff(), "pre", A.getBytes().toHexString(), "storage").get(word(SLOT)));
    assertEquals("0x3", at(s.diff(), "post", A.getBytes().toHexString()).get("balance"));
    assertEquals("0x2", at(s.diff(), "post", B.getBytes().toHexString()).get("balance"));
  }

  @Test
  void createdAccountsHaveNoCodeBeforeAndCarryTheirDeployedCode() {
    final StateSnapshot s = new StateSnapshot();
    s.before(A, () -> account(0, 0, "0x"));
    s.created(A);
    new World().set(A, 0, 1, "0x6001").into(s, false, true);

    assertEquals("0x", at(s.pre(), A.getBytes().toHexString()).get("code"));
    assertEquals("0x6001", at(s.diff(), "post", A.getBytes().toHexString()).get("code"));
    assertEquals("0x1", at(s.diff(), "post", A.getBytes().toHexString()).get("nonce"));
  }

  @Test
  void selfDestructIsSettledByTheForkRule() {
    final StateSnapshot deleting = new StateSnapshot();
    deleting.before(A, () -> account(9, 3, "0x6000"));
    deleting.beforeSlot(A, SLOT, () -> UInt256.valueOf(4));
    // Besu applies the sweep during execution but settles after the tracer's window.
    new World().set(A, 0, 3, "0x6000").slot(A, SLOT, 4).into(deleting, false, false, java.util.Set.of(A));
    assertTrue(at(deleting.diff(), "pre").containsKey(A.getBytes().toHexString()));
    assertFalse(at(deleting.diff(), "post").containsKey(A.getBytes().toHexString()), "deleted account has no post entry");

    final StateSnapshot preserving = new StateSnapshot();
    preserving.before(A, () -> account(9, 3, "0x6000"));
    preserving.beforeSlot(A, SLOT, () -> UInt256.valueOf(4));
    new World().set(A, 9, 3, "0x6000").slot(A, SLOT, 4).into(preserving, true, false, java.util.Set.of(A));
    final Map<String, Object> post = at(preserving.diff(), "post", A.getBytes().toHexString());
    assertEquals("0x", post.get("code"));
    assertEquals("0x0", post.get("nonce"));
    assertEquals(UInt256.ZERO.toHexString(), at(preserving.diff(), "post", A.getBytes().toHexString(), "storage").get(word(SLOT)));
  }

  @Test
  void anAccountLeftEmptyIsDeletedWhenTheForkClearsEmptyAccounts() {
    final StateSnapshot s = new StateSnapshot();
    s.before(B, () -> account(0, 0, "0x"));
    new World().set(B, 0, 0, "0x").into(s, false, true);
    assertFalse(at(s.diff(), "post").containsKey(B.getBytes().toHexString()));
    assertFalse(at(s.diff(), "pre").containsKey(B.getBytes().toHexString()), "an account that never existed is not a change");
  }

  @Test
  void firstTouchWinsForBothAccountsAndSlots() {
    final StateSnapshot s = new StateSnapshot();
    s.before(A, () -> account(5, 1, "0x6000"));
    s.before(A, () -> account(99, 9, "0xdead")); // a later touch must not overwrite the original
    s.beforeSlot(A, SLOT, () -> UInt256.valueOf(1));
    s.beforeSlot(A, SLOT, () -> UInt256.valueOf(2));
    s.beforeSlot(A, OTHER_SLOT, () -> UInt256.valueOf(3));
    new World().set(A, 5, 1, "0x6000").slot(A, SLOT, 1).slot(A, OTHER_SLOT, 3).into(s, false, false);

    assertEquals("0x5", at(s.pre(), A.getBytes().toHexString()).get("balance"));
    assertEquals("0x1", at(s.pre(), A.getBytes().toHexString()).get("nonce"));
    assertEquals(UInt256.ONE.toHexString(), at(s.pre(), A.getBytes().toHexString(), "storage").get(word(SLOT)));
    assertEquals(UInt256.valueOf(3).toHexString(), at(s.pre(), A.getBytes().toHexString(), "storage").get(word(OTHER_SLOT)));
  }

  private static String word(final UInt256 key) {
    return key.toHexString();
  }
}
