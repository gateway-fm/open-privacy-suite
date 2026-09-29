package ops.approvals;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.Supplier;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Wei;

/**
 * The application state one transaction read and wrote, in the shape geth's {@code prestateTracer}
 * reports it, so that {@code internal/nodeapproval.Fingerprint} can consume it unchanged.
 *
 * <p>"Before" values are captured at first touch, "after" values when the transaction's root frame
 * exits — deliberately before Besu refunds gas, pays the fee recipient, settles self-destructs or
 * clears emptied accounts, so the snapshot holds application effects only. The fee therefore never
 * enters the fingerprint: the upfront gas charge is already deducted when the first touch happens,
 * and cancels out of the balance delta, which is the only balance figure the fingerprint binds.
 * Self-destruct settlement and empty-account clearing are applied here instead, from the same rules
 * Besu uses, so the snapshot still describes the committed state.
 */
final class StateSnapshot {
  /** Everything the fingerprint needs from one account. */
  record AccountState(Wei balance, long nonce, Bytes code) {
    static final AccountState ABSENT = new AccountState(Wei.ZERO, 0, Bytes.EMPTY);

    boolean isEmpty() {
      return balance.isZero() && nonce == 0 && code.isEmpty();
    }
  }

  private final Map<Address, AccountState> before = new HashMap<>();
  private final Map<Address, Map<UInt256, UInt256>> slotsBefore = new HashMap<>();
  private final Map<Address, AccountState> after = new HashMap<>();
  private final Map<Address, Map<UInt256, UInt256>> slotsAfter = new HashMap<>();
  private final Set<Address> created = new HashSet<>();
  private final Set<Address> selfDestructed = new HashSet<>();
  private boolean finished;

  static final int MAX_ACCOUNTS = 4096;
  static final int MAX_SLOTS = 16384;
  private int slotCount;
  private String overflow;

  /** Records an account's pre-transaction state the first time the execution touches it. */
  void before(final Address address, final Supplier<AccountState> read) {
    if (before.containsKey(address)) {
      return;
    }
    if (before.size() >= MAX_ACCOUNTS) {
      overflow = "more than " + MAX_ACCOUNTS + " touched accounts";
      return;
    }
    before.put(address, value(read.get()));
  }

  /** Records a slot's pre-transaction value the first time the execution reads or writes it. */
  void beforeSlot(final Address address, final UInt256 key, final Supplier<UInt256> read) {
    final Map<UInt256, UInt256> slots = slotsBefore.computeIfAbsent(address, a -> new HashMap<>());
    if (slots.containsKey(key)) {
      return;
    }
    if (slotCount >= MAX_SLOTS) {
      overflow = "more than " + MAX_SLOTS + " touched storage slots";
      return;
    }
    slotCount++;
    slots.put(key, read.get());
  }

  /** Set when the snapshot stopped recording, which must fail the transaction rather than bind less. */
  Optional<String> overflow() {
    return Optional.ofNullable(overflow);
  }

  void created(final Address address) {
    created.add(address);
  }

  Set<Address> touched() {
    return before.keySet();
  }

  /** Reads the post-execution value of every touched account and slot. */
  void readAfter(
      final Function<Address, AccountState> readAccount,
      final BiFunction<Address, UInt256, UInt256> readSlot) {
    for (final Address address : before.keySet()) {
      after.put(address, value(readAccount.apply(address)));
      final Map<UInt256, UInt256> slots = new HashMap<>();
      for (final UInt256 key : slotsBefore.getOrDefault(address, Map.of()).keySet()) {
        final UInt256 now = readSlot.apply(address, key);
        slots.put(key, now == null ? UInt256.ZERO : now);
      }
      slotsAfter.put(address, slots);
    }
  }

  /**
   * Applies what Besu does after the last tracer callback of the transaction.
   *
   * @param selfDestructs the accounts Besu will actually settle (already EIP-6780-filtered)
   * @param balancePreserved the fork keeps a settled account (EIP-8246) instead of deleting it
   * @param clearEmpty the fork deletes accounts left empty (EIP-161)
   */
  void settle(
      final Set<Address> selfDestructs, final boolean balancePreserved, final boolean clearEmpty) {
    if (after.isEmpty() && !before.isEmpty()) {
      // The root frame's exit never ran (an aborted or unsupported execution): there is no state to
      // describe, and the selector rejects such an observation anyway.
      finished = true;
      return;
    }
    selfDestructed.addAll(selfDestructs);
    for (final Address address : selfDestructs) {
      if (!before.containsKey(address)) {
        continue; // never touched by the application: nothing to describe
      }
      final Map<UInt256, UInt256> slots = slotsAfter.computeIfAbsent(address, a -> new HashMap<>());
      slots.replaceAll((k, v) -> UInt256.ZERO);
      if (balancePreserved) {
        after.put(address, new AccountState(after.get(address).balance(), 0, Bytes.EMPTY));
      } else {
        after.put(address, AccountState.ABSENT);
        deleted.add(address);
      }
    }
    if (clearEmpty) {
      for (final Address address : before.keySet()) {
        if (after.get(address).isEmpty()
            && slotsAfter.getOrDefault(address, Map.of()).values().stream().allMatch(UInt256::isZero)) {
          after.put(address, AccountState.ABSENT);
          deleted.add(address);
        }
      }
    }
    finished = true;
  }

  private final Set<Address> deleted = new HashSet<>();

  /** geth's {@code prestateTracer}: every touched account as it was before the transaction. */
  Map<String, Object> pre() {
    final Map<String, Object> out = new TreeMap<>();
    before.forEach((address, state) -> out.put(key(address), account(state, slotsBefore.get(address))));
    return out;
  }

  /** geth's {@code prestateTracer{diffMode}}: only the accounts and fields that changed. */
  Map<String, Object> diff() {
    require();
    final Map<String, Object> pre = new TreeMap<>();
    final Map<String, Object> post = new TreeMap<>();
    for (final Address address : before.keySet()) {
      final AccountState was = before.get(address);
      final AccountState is = after.get(address);
      final Map<UInt256, UInt256> slotsWere = slotsBefore.getOrDefault(address, Map.of());
      final Map<UInt256, UInt256> slotsAre = slotsAfter.getOrDefault(address, Map.of());
      final boolean gone = deleted.contains(address);
      final Map<String, Object> changedBefore = new LinkedHashMap<>();
      final Map<String, Object> changedAfter = new LinkedHashMap<>();
      final Map<String, Object> storageBefore = new TreeMap<>();
      final Map<String, Object> storageAfter = new TreeMap<>();
      for (final Map.Entry<UInt256, UInt256> slot : slotsWere.entrySet()) {
        final UInt256 now = slotsAre.getOrDefault(slot.getKey(), UInt256.ZERO);
        if (!now.equals(slot.getValue())) {
          storageBefore.put(slot.getKey().toHexString(), slot.getValue().toHexString());
          storageAfter.put(slot.getKey().toHexString(), now.toHexString());
        }
      }
      if (!was.balance().equals(is.balance())) {
        changedBefore.put("balance", was.balance().toShortHexString());
        changedAfter.put("balance", is.balance().toShortHexString());
      }
      if (was.nonce() != is.nonce()) {
        changedBefore.put("nonce", "0x" + Long.toHexString(was.nonce()));
        changedAfter.put("nonce", "0x" + Long.toHexString(is.nonce()));
      }
      if (!was.code().equals(is.code())) {
        changedBefore.put("code", was.code().toHexString());
        changedAfter.put("code", is.code().toHexString());
      }
      if (!storageBefore.isEmpty()) {
        changedBefore.put("storage", storageBefore);
        changedAfter.put("storage", storageAfter);
      }
      if (gone) {
        // An account present in diff.pre and absent from diff.post is a deletion, which is how the
        // fingerprint learns that code, nonce and storage are gone.
        if (!AccountState.ABSENT.equals(was) || !slotsWere.isEmpty()) {
          pre.put(key(address), account(was, slotsWere));
        }
        continue;
      }
      if (!changedBefore.isEmpty()) {
        pre.put(key(address), changedBefore);
        post.put(key(address), changedAfter);
      }
    }
    final Map<String, Object> out = new LinkedHashMap<>();
    out.put("pre", pre);
    out.put("post", post);
    return out;
  }

  boolean isEmpty() {
    return before.isEmpty();
  }

  private void require() {
    if (!finished) {
      throw new IllegalStateException("after() must run before the diff is built");
    }
  }

  /** Besu deprecates Address.toHexString(); the canonical key is the lowercase 20-byte hex. */
  private static String key(final Address address) {
    return address.getBytes().toHexString();
  }

  private static AccountState value(final AccountState state) {
    return state == null ? AccountState.ABSENT : state;
  }

  private static Map<String, Object> account(final AccountState state, final Map<UInt256, UInt256> slots) {
    final Map<String, Object> out = new LinkedHashMap<>();
    out.put("balance", state.balance().toShortHexString());
    out.put("nonce", "0x" + Long.toHexString(state.nonce()));
    out.put("code", state.code().toHexString());
    if (slots != null && !slots.isEmpty()) {
      final Map<String, Object> storage = new TreeMap<>();
      slots.forEach((key, value) -> storage.put(key.toHexString(), value.toHexString()));
      out.put("storage", storage);
    }
    return out;
  }
}
