package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Hash;
import org.junit.jupiter.api.Test;

class ApprovalListenerTest {
  @Test
  void storesGoSignedBatchesFromTheWireAndIgnoresGarbage() throws Exception {
    final JsonNode v = Fixtures.load("call-batch.json");
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
    final byte[] signature = Bytes.fromHexString(v.get("signature").asText()).toArrayUnsafe();
    final ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write(ApprovalBatch.message("default", approvals));
    body.write(signature);

    final ApprovalStore store = new ApprovalStore(10, 60_000, 0, new AtomicLong(1)::get);
    try (ApprovalListener listener =
        new ApprovalListener(
            new InetSocketAddress("127.0.0.1", 0),
            1,
            300,
            new ApprovalVerifier(java.util.Map.of("default", Fixtures.FIXTURE_PUBLIC_KEY)),
            31337,
            store,
            ApprovalListener.Metrics.NONE)) {
      listener.start();
      // A peer that announces a frame and never finishes it must not hold the only slot.
      try (Socket slow = new Socket("127.0.0.1", listener.port());
          DataOutputStream out = new DataOutputStream(slow.getOutputStream())) {
        out.writeInt(body.size());
        boolean closedByListener = false;
        try {
          for (int i = 0; i < 6; i++) { // one byte every 150 ms: never idle, never complete
            out.write(body.toByteArray(), i, 1);
            out.flush();
            Thread.sleep(150);
          }
          slow.setSoTimeout(3_000);
          closedByListener = slow.getInputStream().read() == -1;
        } catch (final java.net.SocketTimeoutException e) {
          closedByListener = false; // still open after 3 s: the deadline did not fire
        } catch (final java.io.IOException e) {
          closedByListener = true; // broken pipe / reset: the listener dropped us
        }
        assertTrue(closedByListener, "listener must close a stalled frame");
      }
      try (Socket socket = new Socket("127.0.0.1", listener.port());
          DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {
        out.writeInt(5);
        out.write(new byte[5]); // garbage frame: rejected, connection stays up
        out.writeInt(body.size());
        out.write(body.toByteArray());
        out.writeInt(body.size());
        out.write(body.toByteArray()); // duplicate delivery is idempotent
        out.flush();
        final long deadline = System.currentTimeMillis() + 5_000;
        while (store.size() == 0 && System.currentTimeMillis() < deadline) {
          Thread.sleep(20);
        }
      }
      // Both golden approvals share one tx hash: the last one delivered wins, one slot used.
      assertEquals(1, store.size());
      assertTrue(store.get(approvals.get(0).txHash()).isPresent());
    }
  }
}
