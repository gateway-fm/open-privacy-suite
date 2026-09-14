package ops.approvals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;

/** Shared Go golden vectors (single source of truth in internal/nodeapproval/testdata). */
final class Fixtures {
  static final ObjectMapper JSON = new ObjectMapper();
  static final Path GO_TESTDATA = Path.of("..", "..", "internal", "nodeapproval", "testdata");
  /** ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public() */
  static final byte[] FIXTURE_PUBLIC_KEY =
      Bytes.fromHexString("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
          .toArrayUnsafe();

  private Fixtures() {}

  /** JsonNode to the plain Map/List/String/Boolean shapes the encoders work on. */
  static Object toJava(final JsonNode node) {
    if (node.isObject()) {
      final Map<String, Object> out = new java.util.LinkedHashMap<>();
      node.fields().forEachRemaining(e -> out.put(e.getKey(), toJava(e.getValue())));
      return out;
    }
    if (node.isArray()) {
      final List<Object> out = new ArrayList<>();
      node.forEach(child -> out.add(toJava(child)));
      return out;
    }
    if (node.isBoolean()) {
      return node.booleanValue();
    }
    return node.asText();
  }

  static JsonNode load(final String name) throws IOException {
    return JSON.readTree(Files.readString(GO_TESTDATA.resolve(name)));
  }

  /** Mirrors Go normalizeCall + CallFingerprint's per-call inputs for a geth-shaped tree. */
  static List<CallRecord> records(final JsonNode tree, final Function<Address, Hash> codeOf) {
    final List<CallRecord> out = new ArrayList<>();
    walk(tree, CallRecord.ROOT_PARENT, null, out, codeOf);
    return out;
  }

  private static void walk(
      final JsonNode call,
      final int parent,
      final Address parentStorage,
      final List<CallRecord> out,
      final Function<Address, Hash> codeOf) {
    final int kind =
        switch (call.get("type").asText()) {
          case "CALL" -> CallRecord.CALL;
          case "STATICCALL" -> CallRecord.STATICCALL;
          case "DELEGATECALL" -> CallRecord.DELEGATECALL;
          case "CALLCODE" -> CallRecord.CALLCODE;
          case "CREATE" -> CallRecord.CREATE;
          case "CREATE2" -> CallRecord.CREATE2;
          default -> throw new IllegalArgumentException("unsupported " + call.get("type"));
        };
    final Address to = Address.fromHexString(call.get("to").asText());
    final Address from = Address.fromHexString(call.get("from").asText());
    final Address storage =
        (kind == CallRecord.DELEGATECALL || kind == CallRecord.CALLCODE) ? parentStorage : to;
    final Wei value =
        call.hasNonNull("value") ? Wei.fromHexString(call.get("value").asText()) : Wei.ZERO;
    final Bytes input =
        call.hasNonNull("input") ? Bytes.fromHexString(call.get("input").asText()) : Bytes.EMPTY;
    final int index = out.size();
    out.add(
        new CallRecord(
            parent,
            kind,
            from,
            to,
            storage,
            codeOf.apply(to),
            value,
            call.hasNonNull("error"),
            input));
    if (call.hasNonNull("calls")) {
      for (final JsonNode child : call.get("calls")) {
        walk(child, index, storage, out, codeOf);
      }
    }
  }

  static Map<Address, Hash> codes(final JsonNode pre) {
    final Map<Address, Hash> codes = new HashMap<>();
    pre.fields()
        .forEachRemaining(
            e ->
                codes.put(
                    Address.fromHexString(e.getKey()),
                    Hash.hash(
                        e.getValue().hasNonNull("code")
                            ? Bytes.fromHexString(e.getValue().get("code").asText())
                            : Bytes.EMPTY)));
    return codes;
  }
}
