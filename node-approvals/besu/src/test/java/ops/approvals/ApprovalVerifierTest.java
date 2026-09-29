package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class ApprovalVerifierTest {
  @Test
  void verifiesWycheproofVectors() throws Exception {
    try (var input = getClass().getResourceAsStream("/wycheproof/ed25519_test.json")) {
      final var vectors = Fixtures.JSON.readTree(input);
      int checked = 0;
      for (final var group : vectors.get("testGroups")) {
        final byte[] key = HexFormat.of().parseHex(group.get("publicKey").get("pk").asText());
        final var verifier = new ApprovalVerifier(Map.of("default", key));
        for (final var test : group.get("tests")) {
          final String expected = test.get("result").asText();
          assertTrue(expected.equals("valid") || expected.equals("invalid"), "unexpected vector classification");
          // Exercise the verifier directly: malformed signature lengths must fail even before
          // an ingress decoder is involved. The corpus includes signatures with extra bytes.
          final var batch = new ApprovalBatch.Decoded("default", 1, 2, List.of(),
              HexFormat.of().parseHex(test.get("msg").asText()),
              HexFormat.of().parseHex(test.get("sig").asText()));
          assertEquals(expected.equals("valid"), verifier.verify(batch),
              "Wycheproof case " + test.get("tcId") + ": " + test.get("comment").asText());
          checked++;
        }
      }
      assertEquals(vectors.get("numberOfTests").asInt(), checked);
    }
  }

  @Test
  void ownsItsTrustedKeyBytes() throws Exception {
    final byte[] key = Fixtures.FIXTURE_PUBLIC_KEY.clone();
    final var verifier = new ApprovalVerifier(Map.of("default", key));
    Arrays.fill(key, (byte) 0);
    assertTrue(verifier.verify(ApprovalBatch.decode(Fixtures.goldenEnvelope("call-batch.json"))));
  }

  @Test
  void rejectsInvalidKeyLengthsAndEmptyTrust() {
    assertThrows(IllegalArgumentException.class, () -> new ApprovalVerifier(Map.of()));
    for (final int size : new int[] {0, 31, 33}) {
      assertThrows(IllegalArgumentException.class, () -> new ApprovalVerifier(Map.of("default", new byte[size])));
    }
  }

  @Test
  void oneVerifierCanServeConcurrentWorkers() throws Exception {
    final var verifier = new ApprovalVerifier(Map.of("default", Fixtures.FIXTURE_PUBLIC_KEY));
    final var good = ApprovalBatch.decode(Fixtures.goldenEnvelope("call-batch.json"));
    final byte[] changedMessage = good.message().clone();
    changedMessage[changedMessage.length - 1] ^= 1;
    final var bad = new ApprovalBatch.Decoded(good.keyId(), good.issuedAt(), good.expiresAt(),
        good.approvals(), changedMessage, good.signature());
    final Callable<Void> check = () -> {
      for (int i = 0; i < 100; i++) {
        assertTrue(verifier.verify(good));
        assertFalse(verifier.verify(bad));
      }
      return null;
    };
    try (var workers = Executors.newFixedThreadPool(4)) {
      for (final var result : workers.invokeAll(List.of(check, check, check, check))) {
        result.get();
      }
    }
  }
}
