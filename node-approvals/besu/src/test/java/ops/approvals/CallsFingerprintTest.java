package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;
import org.junit.jupiter.api.Test;

class CallsFingerprintTest {
  private static List<CallRecord> golden() throws Exception {
    final JsonNode v = Fixtures.load("call-v3.json");
    final Map<Address, Hash> codes = Fixtures.codes(v.get("pre"));
    return Fixtures.records(v.get("calls"), codes::get);
  }

  private static Hash expected() throws Exception {
    return Hash.fromHexString(Fixtures.load("call-v3.json").get("expected_calls").asText());
  }

  @Test
  void matchesGoGoldenVector() throws Exception {
    assertEquals(expected(), CallsFingerprint.of(golden()));
  }

  @Test
  void bindsStructureInputsCodeContextAndCaughtFailures() throws Exception {
    final Hash want = expected();
    final List<CallRecord> base = golden();
    // Same mutations as the Rust unit test, expressed on records: each must change the hash.
    final List<List<CallRecord>> variants = new ArrayList<>();
    variants.add(swap(base, 1, 2));
    variants.add(with(base, 2, r -> r.withKind(CallRecord.CALLCODE)));
    variants.add(with(base, 2, r -> r.withInput(Bytes.of(99))));
    variants.add(with(base, 2, r -> r.withValue(Wei.of(8))));
    variants.add(with(base, 2, r -> r.withFailed(!r.failed())));
    variants.add(with(base, 0, r -> r.withCodeHash(Hash.wrap(Bytes32.repeat((byte) 7)))));
    variants.add(with(base, 2, r -> r.withFrom(Address.fromHexString("0x" + "88".repeat(20)))));
    variants.add(with(base, 2, r -> r.withStorage(Address.fromHexString("0x" + "89".repeat(20)))));
    variants.add(with(base, 2, r -> r.withParent(0)));
    final List<CallRecord> duplicated = new ArrayList<>(base);
    duplicated.add(base.get(1).withParent(0));
    variants.add(duplicated);
    for (int i = 0; i < variants.size(); i++) {
      assertNotEquals(want, CallsFingerprint.of(variants.get(i)), "variant " + i);
    }
  }

  @Test
  void lifecycleAndLimitsFailClosed() throws Exception {
    final List<CallRecord> base = golden();
    for (final int kind : new int[] {CallRecord.CREATE, CallRecord.CREATE2, 9}) {
      assertThrows(
          UnsupportedExecutionException.class,
          () -> CallsFingerprint.of(with(base, 2, r -> r.withKind(kind))),
          "kind " + kind);
    }
    assertThrows(
        UnsupportedExecutionException.class,
        () -> CallsFingerprint.of(with(base, 0, r -> r.withInput(Bytes.wrap(new byte[1 << 20])))));
    final List<CallRecord> many = new ArrayList<>();
    many.add(base.get(0));
    for (int i = 0; i < 128; i++) {
      many.add(base.get(1).withParent(0));
    }
    assertThrows(UnsupportedExecutionException.class, () -> CallsFingerprint.of(many));
    assertThrows(UnsupportedExecutionException.class, () -> CallsFingerprint.of(List.of()));
  }

  @Test
  void treeRoundTripsThroughGethShape() throws Exception {
    final JsonNode v = Fixtures.load("call-v3.json");
    final Map<Address, Hash> codes = Fixtures.codes(v.get("pre"));
    final List<CallRecord> base = Fixtures.records(v.get("calls"), codes::get);
    final Map<String, Object> tree = CallTreeJson.toTree(base);
    final JsonNode again = Fixtures.JSON.valueToTree(tree);
    assertEquals(base, Fixtures.records(again, codes::get));
    assertEquals(expected(), CallsFingerprint.of(Fixtures.records(again, codes::get)));
  }

  private static List<CallRecord> swap(final List<CallRecord> in, final int a, final int b) {
    final List<CallRecord> out = new ArrayList<>(in);
    out.set(a, in.get(b));
    out.set(b, in.get(a));
    return out;
  }

  private static List<CallRecord> with(
      final List<CallRecord> in, final int index, final UnaryOperator<CallRecord> f) {
    final List<CallRecord> out = new ArrayList<>(in);
    out.set(index, f.apply(in.get(index)));
    return out;
  }
}
