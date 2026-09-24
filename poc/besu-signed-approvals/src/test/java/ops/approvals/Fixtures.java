package ops.approvals;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.NamedParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.datatypes.Address;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.Wei;

/** Shared Go golden vectors (single source of truth in internal/nodeapproval/testdata). */
final class Fixtures {
  static final ObjectMapper JSON = new ObjectMapper();
  static final Path GO_TESTDATA = Path.of("..", "..", "internal", "nodeapproval", "testdata");
  /** The Go fixture signer's seed: bytes.Repeat([]byte{7}, 32). */
  static final byte[] FIXTURE_SEED = seed(7);
  /** ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public() */
  static final byte[] FIXTURE_PUBLIC_KEY =
      Bytes.fromHexString("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c")
          .toArrayUnsafe();

  /** The golden vectors are signed at this instant (Go expiry_test.go goldenIssued) with the default 10-minute TTL. */
  static final long GOLDEN_ISSUED_AT = 1790000000000L;
  static final long GOLDEN_EXPIRES_AT = 1790000600000L;
  static final long CHAIN = 31337;

  private Fixtures() {}

  static byte[] seed(final int value) {
    final byte[] seed = new byte[32];
    Arrays.fill(seed, (byte) value);
    return seed;
  }

  /** The approvals of a golden batch, in batch order. */
  static List<Approval> goldenApprovals(final String name) throws IOException {
    final List<Approval> approvals = new ArrayList<>();
    for (final JsonNode a : load(name).get("approvals")) {
      approvals.add(
          new Approval(
              a.has("hash_mode") ? a.get("hash_mode").asInt() : Approval.HASH_STRICT,
              a.get("chain_id").asLong(),
              Hash.fromHexString(a.get("tx_hash").asText()),
              Hash.fromHexString(a.get("fingerprint").asText()),
              Hash.fromHexString(a.get("principal").asText())));
    }
    return approvals;
  }

  /** A golden batch's envelope exactly as Go signed it: the signed message, then its signature. */
  static byte[] goldenEnvelope(final String name) throws IOException {
    final JsonNode v = load(name);
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(
        ApprovalBatch.message(
            v.get("key_id").asText(), v.get("issued_at").asLong(), v.get("expires_at").asLong(), goldenApprovals(name)));
    out.writeBytes(Bytes.fromHexString(v.get("signature").asText()).toArrayUnsafe());
    return out.toByteArray();
  }

  /** A calls-mode approval for chain 31337 with a synthetic transaction hash and fingerprint. */
  static Approval approval(final int tx, final int fingerprint) {
    return approval(CHAIN, tx, fingerprint);
  }

  static Approval approval(final long chain, final int tx, final int fingerprint) {
    return new Approval(Approval.HASH_CALLS, chain, hash(tx), hash(fingerprint), Hash.ZERO);
  }

  static Hash hash(final int value) {
    return Hash.wrap(Bytes32.leftPad(Bytes.ofUnsignedInt(value)));
  }

  /** A batch envelope signed with the fixture seed, as OPS would sign it. */
  static byte[] envelope(final String keyId, final long issuedAt, final long expiresAt, final List<Approval> approvals) {
    return envelope(FIXTURE_SEED, keyId, issuedAt, expiresAt, approvals);
  }

  static byte[] envelope(
      final byte[] seed, final String keyId, final long issuedAt, final long expiresAt, final List<Approval> approvals) {
    final byte[] message = ApprovalBatch.message(keyId, issuedAt, expiresAt, approvals);
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.writeBytes(message);
    out.writeBytes(sign(seed, message));
    return out.toByteArray();
  }

  /** RFC 8032 Ed25519 with the JDK provider; deterministic, so it reproduces Go's signatures. */
  static byte[] sign(final byte[] seed, final byte[] message) {
    try {
      final PrivateKey key =
          KeyFactory.getInstance("Ed25519").generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
      final Signature signer = Signature.getInstance("Ed25519");
      signer.initSign(key);
      signer.update(message);
      return signer.sign();
    } catch (final GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

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
