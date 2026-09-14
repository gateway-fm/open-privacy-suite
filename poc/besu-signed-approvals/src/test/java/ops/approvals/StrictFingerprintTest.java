package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.hyperledger.besu.datatypes.Hash;
import org.junit.jupiter.api.Test;

/** Strict V2 must equal internal/nodeapproval.Fingerprint on the shared golden vector. */
class StrictFingerprintTest {
  private static final String CONTRACT = "0x" + "11".repeat(20);
  private static final String SLOT0 = "0x" + "0".repeat(64);

  @SuppressWarnings("unchecked")
  private static Map<String, Object> cast(final Object o) {
    return (Map<String, Object>) o;
  }

  private static Map<String, Object> vector() throws Exception {
    return cast(Fixtures.toJava(Fixtures.load("fingerprint.json")));
  }

  private static Hash hash(final Map<String, Object> v) throws UnsupportedExecutionException {
    return StrictFingerprint.of(cast(v.get("calls")), cast(v.get("pre")), cast(v.get("diff")));
  }

  private static Map<String, Object> mutated(final Consumer<Map<String, Object>> change)
      throws Exception {
    final Map<String, Object> v = vector();
    change.accept(v);
    return v;
  }

  private static Map<String, Object> account(final Map<String, Object> v, final String where) {
    return cast(cast(v.get(where)).get(CONTRACT));
  }

  private static Map<String, Object> slots(
      final Map<String, Object> v, final String where, final String side) {
    return cast(cast(cast(cast(v.get(where)).get(side)).get(CONTRACT)).get("storage"));
  }

  @Test
  void matchesTheGoGoldenVector() throws Exception {
    final Map<String, Object> v = vector();
    assertEquals(Hash.fromHexString((String) v.get("expected")), hash(v));
  }

  @Test
  void bindsStateAndResults() throws Exception {
    final Hash want = Hash.fromHexString((String) vector().get("expected"));
    final List<Consumer<Map<String, Object>>> changes =
        List.of(
            v -> slots(v, "diff", "post").put(SLOT0, "0x9"), // written value
            v -> cast(account(v, "pre").get("storage")).put(SLOT0, "0x1"), // value read before
            // diff.pre carries only membership: a slot listed there with no post entry reads as
            // written-to-zero, which must change the hash.
            v -> slots(v, "diff", "pre").put("0x" + "0".repeat(63) + "1", "0x0"),
            v -> account(v, "pre").put("code", "0x6001"), // code before
            v -> account(v, "pre").put("nonce", "0x7"), // contract nonce
            v ->
                cast(v.get("pre"))
                    .put(
                        "0x" + "cc".repeat(20),
                        new LinkedHashMap<>(Map.of("balance", "0x1", "code", "0x60ff"))),
            v -> cast(v.get("calls")).put("output", "0x01"), // return data
            v ->
                cast(v.get("calls"))
                    .put(
                        "logs",
                        List.of(Map.of("address", CONTRACT, "topics", List.of(), "data", "0x"))),
            v -> cast(v.get("calls")).put("input", "0xdeadbeef"));
    for (int i = 0; i < changes.size(); i++) {
      assertNotEquals(want, hash(mutated(changes.get(i))), "change " + i);
    }
  }

  @Test
  void gasMetadataIsNotBound() throws Exception {
    final Hash want = Hash.fromHexString((String) vector().get("expected"));
    assertEquals(want, hash(mutated(v -> cast(v.get("calls")).put("gas", "0x999999"))));
    assertEquals(want, hash(mutated(v -> cast(v.get("calls")).put("gasUsed", "0x999999"))));
  }

  @Test
  void failsClosedOnUnsupportedInput() throws Exception {
    assertThrows(
        UnsupportedExecutionException.class,
        () -> hash(mutated(v -> cast(v.get("calls")).put("type", "AUTHCALL"))));
    assertThrows(
        UnsupportedExecutionException.class,
        () -> hash(mutated(v -> cast(v.get("pre")).put("not-an-address", new LinkedHashMap<>()))));
    assertThrows(
        UnsupportedExecutionException.class,
        () ->
            hash(
                mutated(
                    v -> cast(v.get("calls")).put("input", "0x" + "ab".repeat(600_000)))));
  }

  @Test
  void lifecycleFramesAreAllowed() throws Exception {
    // Strict is exactly the mode that must accept CREATE/CREATE2/SELFDESTRUCT.
    final Map<String, Object> created = new LinkedHashMap<>();
    created.put("type", "CREATE");
    created.put("from", CONTRACT);
    created.put("to", "0x" + "dd".repeat(20));
    created.put("input", "0x6000");
    created.put("output", "0x00");
    created.put("value", "0x0");
    final Map<String, Object> v =
        mutated(
            x -> {
              cast(x.get("calls")).put("calls", List.of(created));
              cast(x.get("pre"))
                  .put("0x" + "dd".repeat(20), new LinkedHashMap<>(Map.of("balance", "0x0")));
            });
    assertNotEquals(Hash.fromHexString((String) vector().get("expected")), hash(v));
  }
}
