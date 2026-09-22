package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Hash;
import org.junit.jupiter.api.Test;

/**
 * A batch names the key that signed it, and the producer holds a set of trusted keys: rotation is
 * "add the new key, switch OPS, remove the old key", with no simultaneous restart.
 */
class ApprovalKeySetTest {
  private static byte[] frame(final String golden) throws Exception {
    final JsonNode v = Fixtures.load(golden);
    final List<Approval> approvals = new ArrayList<>();
    for (final JsonNode a : v.get("approvals")) {
      approvals.add(new Approval(a.has("hash_mode") ? a.get("hash_mode").asInt() : Approval.HASH_STRICT, a.get("chain_id").asLong(),
          Hash.fromHexString(a.get("tx_hash").asText()), Hash.fromHexString(a.get("fingerprint").asText()),
          Hash.fromHexString(a.get("principal").asText())));
    }
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(ApprovalBatch.message(v.get("key_id").asText(), approvals));
    out.write(Bytes.fromHexString(v.get("signature").asText()).toArrayUnsafe());
    return out.toByteArray();
  }

  @Test
  void decodesTheKeyIdAndVerifiesAgainstThatKey() throws Exception {
    final ApprovalBatch.Decoded decoded = ApprovalBatch.decode(frame("batch.json"));
    assertEquals("default", decoded.keyId());
    final byte[] other = new byte[32];
    other[0] = 1;
    final ApprovalVerifier verifier = new ApprovalVerifier(Map.of("default", Fixtures.FIXTURE_PUBLIC_KEY, "next", other));
    assertTrue(verifier.verify(decoded));
    // The same signature under a key id the producer does not know, or knows with another key, fails.
    assertFalse(new ApprovalVerifier(Map.of("next", Fixtures.FIXTURE_PUBLIC_KEY)).verify(decoded), "unknown key id");
    assertFalse(new ApprovalVerifier(Map.of("default", other)).verify(decoded), "wrong key under that id");
  }

  @Test
  void theKeyIdIsSignedSoItCannotBeSwapped() throws Exception {
    final byte[] ok = frame("batch.json");
    final byte[] swapped = ok.clone();
    swapped[ApprovalBatch.DOMAIN.length + 1] ^= 1; // first byte of the key id
    final ApprovalBatch.Decoded decoded = ApprovalBatch.decode(swapped);
    assertFalse(new ApprovalVerifier(Map.of(decoded.keyId(), Fixtures.FIXTURE_PUBLIC_KEY, "default", Fixtures.FIXTURE_PUBLIC_KEY)).verify(decoded));
  }

  @Test
  void parsesTheKeySetOption() {
    final Map<String, byte[]> keys = PluginOptions.parseKeys("a=" + "11".repeat(32) + ",b-2026=" + "22".repeat(32));
    assertEquals(2, keys.size());
    assertEquals((byte) 0x22, keys.get("b-2026")[0]);
    assertThrows(IllegalArgumentException.class, () -> PluginOptions.parseKeys("nohex"));
    assertThrows(IllegalArgumentException.class, () -> PluginOptions.parseKeys("bad id=" + "11".repeat(32)));
    assertThrows(IllegalArgumentException.class, () -> PluginOptions.parseKeys("a=" + "11".repeat(31)));
  }
}
