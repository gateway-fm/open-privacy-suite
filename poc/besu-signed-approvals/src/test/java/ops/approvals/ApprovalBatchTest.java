package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Hash;
import org.junit.jupiter.api.Test;

/** Wire compatibility with internal/nodeapproval (batch.go, service.go Message()). */
class ApprovalBatchTest {
  record Golden(List<Approval> approvals, byte[] signature) {}

  private static Golden golden(final String name) throws Exception {
    final JsonNode v = Fixtures.load(name);
    final List<Approval> approvals = new ArrayList<>();
    for (final JsonNode a : v.get("approvals")) {
      approvals.add(
          new Approval(
              a.has("hash_mode") ? a.get("hash_mode").asInt() : Approval.HASH_STRICT,
              a.get("chain_id").asLong(),
              Hash.fromHexString(a.get("tx_hash").asText()),
              Hash.fromHexString(a.get("fingerprint").asText()),
              Hash.fromHexString(a.get("principal").asText())));
    }
    return new Golden(approvals, Bytes.fromHexString(v.get("signature").asText()).toArrayUnsafe());
  }

  private static byte[] frame(final List<Approval> approvals, final byte[] signature) throws Exception {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(ApprovalBatch.message(approvals));
    out.write(signature);
    return out.toByteArray();
  }

  @Test
  void itemLayoutIs120BytesWithModeDomain() {
    final Approval strict = new Approval(0, 31337, Hash.ZERO, Hash.ZERO, Hash.ZERO);
    final Approval calls = new Approval(3, 31337, Hash.ZERO, Hash.ZERO, Hash.ZERO);
    assertEquals(120, strict.message().length);
    assertEquals("OPS_APPROVAL_V1\0", new String(strict.message(), 0, 16, java.nio.charset.StandardCharsets.US_ASCII));
    assertEquals("OPS_APPROVAL_V3\0", new String(calls.message(), 0, 16, java.nio.charset.StandardCharsets.US_ASCII));
  }

  @Test
  void decodesAndVerifiesGoSignedBatches() throws Exception {
    for (final String name : List.of("batch.json", "call-batch.json")) {
      final Golden g = golden(name);
      final ApprovalBatch.Decoded decoded = ApprovalBatch.decode(frame(g.approvals(), g.signature()));
      assertEquals(g.approvals(), decoded.approvals(), name);
      final ApprovalVerifier verifier = new ApprovalVerifier(Fixtures.FIXTURE_PUBLIC_KEY);
      assertTrue(verifier.verify(decoded), name);
    }
  }

  @Test
  void rejectsTamperingUnknownModesAndBadSizes() throws Exception {
    final Golden g = golden("call-batch.json");
    final ApprovalVerifier verifier = new ApprovalVerifier(Fixtures.FIXTURE_PUBLIC_KEY);
    final byte[] ok = frame(g.approvals(), g.signature());

    final byte[] flipped = ok.clone();
    flipped[ApprovalBatch.DOMAIN.length + 4 + 16 + 8] ^= 1; // first tx hash byte
    assertFalse(verifier.verify(ApprovalBatch.decode(flipped)));

    final byte[] badSig = ok.clone();
    badSig[badSig.length - 1] ^= 1;
    assertFalse(verifier.verify(ApprovalBatch.decode(badSig)));

    final byte[] otherKey = new byte[32];
    otherKey[0] = 1;
    assertFalse(new ApprovalVerifier(otherKey).verify(ApprovalBatch.decode(ok)));

    final byte[] unknownMode = ok.clone();
    unknownMode[ApprovalBatch.DOMAIN.length + 4 + 14] = '9'; // "OPS_APPROVAL_V9"
    assertThrows(InvalidBatchException.class, () -> ApprovalBatch.decode(unknownMode));

    final byte[] wrongDomain = ok.clone();
    wrongDomain[0] = 'X';
    assertThrows(InvalidBatchException.class, () -> ApprovalBatch.decode(wrongDomain));

    final byte[] truncated = java.util.Arrays.copyOf(ok, ok.length - 1);
    assertThrows(InvalidBatchException.class, () -> ApprovalBatch.decode(truncated));

    final byte[] countMismatch = ok.clone();
    countMismatch[ApprovalBatch.DOMAIN.length + 3] = 1; // says 1 approval, carries 2
    assertThrows(InvalidBatchException.class, () -> ApprovalBatch.decode(countMismatch));

    assertThrows(InvalidBatchException.class, () -> ApprovalBatch.decode(frame(List.of(), g.signature())));
    final List<Approval> tooMany = new ArrayList<>();
    for (int i = 0; i < 33; i++) {
      tooMany.add(g.approvals().get(0));
    }
    assertThrows(InvalidBatchException.class, () -> ApprovalBatch.decode(frame(tooMany, g.signature())));
    assertThrows(InvalidBatchException.class, () -> ApprovalBatch.decode(new byte[ApprovalBatch.MAX_FRAME + 1]));
  }
}
