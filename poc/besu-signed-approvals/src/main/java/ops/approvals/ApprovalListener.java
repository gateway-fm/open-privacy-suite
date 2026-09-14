package ops.approvals;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Private ingress for OPS approval batches: 4-byte big-endian length prefix, then the batch. One
 * reader thread per connection, at most {@code maxConnections}; a frame that does not decode or
 * verify closes nothing and grants nothing — it is logged and skipped. There are no replies.
 */
public final class ApprovalListener implements AutoCloseable {
  private static final Logger LOG = LoggerFactory.getLogger(ApprovalListener.class);

  /** Ingress counters; a no-op implementation is used in tests. */
  public interface Metrics {
    Metrics NONE = new Metrics() {};

    default void accepted(int approvals) {}

    default void rejected(String reason) {}
  }

  static final int DEFAULT_FRAME_TIMEOUT_MS = 5_000;

  private final InetSocketAddress bind;
  private final int maxConnections;
  private final int frameTimeoutMs;
  private final ApprovalVerifier verifier;
  private final long chainId;
  private final ApprovalStore store;
  private final Metrics metrics;
  private final AtomicBoolean closed = new AtomicBoolean();
  private final AtomicInteger readers = new AtomicInteger();
  private final List<Socket> connections = new ArrayList<>();
  private ServerSocket server;
  private Thread acceptor;

  public ApprovalListener(
      final InetSocketAddress bind,
      final int maxConnections,
      final ApprovalVerifier verifier,
      final long chainId,
      final ApprovalStore store,
      final Metrics metrics) {
    this(bind, maxConnections, DEFAULT_FRAME_TIMEOUT_MS, verifier, chainId, store, metrics);
  }

  public ApprovalListener(
      final InetSocketAddress bind,
      final int maxConnections,
      final int frameTimeoutMs,
      final ApprovalVerifier verifier,
      final long chainId,
      final ApprovalStore store,
      final Metrics metrics) {
    this.bind = bind;
    this.maxConnections = maxConnections;
    this.frameTimeoutMs = frameTimeoutMs;
    this.verifier = verifier;
    this.chainId = chainId;
    this.store = store;
    this.metrics = metrics;
  }

  public void start() throws IOException {
    server = new ServerSocket();
    server.setReuseAddress(true);
    server.bind(bind);
    final Semaphore slots = new Semaphore(maxConnections);
    acceptor =
        Thread.ofPlatform()
            .name("ops-approval-acceptor")
            .daemon(true)
            .start(
                () -> {
                  while (!closed.get()) {
                    try {
                      final Socket socket = server.accept();
                      if (!slots.tryAcquire()) {
                        LOG.warn("OPS approval ingress: connection limit {} reached, refusing {}", maxConnections, socket.getRemoteSocketAddress());
                        socket.close();
                        continue;
                      }
                      socket.setTcpNoDelay(true);
                      synchronized (connections) {
                        connections.add(socket);
                      }
                      Thread.ofPlatform()
                          .name("ops-approval-reader-" + readers.incrementAndGet())
                          .daemon(true)
                          .start(
                              () -> {
                                try {
                                  serve(socket);
                                } finally {
                                  slots.release();
                                  synchronized (connections) {
                                    connections.remove(socket);
                                  }
                                }
                              });
                    } catch (final IOException e) {
                      if (!closed.get()) {
                        LOG.warn("OPS approval ingress accept failed", e);
                        try {
                          Thread.sleep(100); // e.g. EMFILE: do not spin
                        } catch (final InterruptedException ie) {
                          Thread.currentThread().interrupt();
                          return;
                        }
                      }
                    }
                  }
                });
  }

  public int port() {
    return server.getLocalPort();
  }

  private void serve(final Socket socket) {
    try (socket;
        InputStream in = socket.getInputStream()) {
      final byte[] prefix = new byte[4];
      while (!closed.get()) {
        socket.setSoTimeout(0); // idle between frames is normal: OPS keeps the connection open
        final int first = in.read();
        if (first < 0) {
          throw new EOFException();
        }
        // From the first byte of a frame, the whole frame must land within frameTimeoutMs:
        // a hard deadline, not a per-read idle timeout, so trickling bytes cannot hold a slot.
        final long deadline = System.nanoTime() + frameTimeoutMs * 1_000_000L;
        prefix[0] = (byte) first;
        readWithin(in, socket, prefix, 1, deadline);
        final int length = ByteBuffer.wrap(prefix).getInt();
        if (length < 1 || length > ApprovalBatch.MAX_FRAME) {
          LOG.warn("OPS approval ingress: bad frame length {} from {}", length, socket.getRemoteSocketAddress());
          metrics.rejected("frame_length");
          return; // protocol desync: drop the connection, OPS reconnects
        }
        final byte[] body = new byte[length];
        readWithin(in, socket, body, 0, deadline);
        accept(body);
      }
    } catch (final SocketTimeoutException e) {
      LOG.warn("OPS approval ingress: partial frame from {} timed out", socket.getRemoteSocketAddress());
      metrics.rejected("frame_timeout");
    } catch (final EOFException e) {
      LOG.debug("OPS approval connection closed by peer");
    } catch (final IOException e) {
      if (!closed.get()) {
        LOG.warn("OPS approval connection error", e);
      }
    }
  }

  private static void readWithin(
      final InputStream in, final Socket socket, final byte[] buf, final int from, final long deadline)
      throws IOException {
    int offset = from;
    while (offset < buf.length) {
      final long remainingMs = (deadline - System.nanoTime()) / 1_000_000L;
      if (remainingMs <= 0) {
        throw new SocketTimeoutException("frame deadline exceeded");
      }
      socket.setSoTimeout((int) Math.min(remainingMs, Integer.MAX_VALUE));
      final int n = in.read(buf, offset, buf.length - offset);
      if (n < 0) {
        throw new EOFException();
      }
      offset += n;
    }
  }

  /** Decode, verify and store one frame body. Package-private for tests. */
  void accept(final byte[] body) {
    final ApprovalBatch.Decoded batch;
    try {
      batch = ApprovalBatch.decode(body);
    } catch (final InvalidBatchException e) {
      LOG.warn("OPS approval batch rejected: {}", e.getMessage());
      metrics.rejected("malformed");
      return;
    }
    if (!verifier.verify(batch)) {
      LOG.warn("OPS approval batch rejected: bad signature ({} approvals)", batch.approvals().size());
      metrics.rejected("signature");
      return;
    }
    int stored = 0;
    for (final Approval a : batch.approvals()) {
      if (a.chainId() != chainId) {
        LOG.warn("OPS approval for chain {} ignored (this node: {})", a.chainId(), chainId);
        metrics.rejected("chain");
        continue;
      }
      if (store.put(a)) {
        stored++;
      } else {
        LOG.error("OPS approval store full ({}); approval for {} dropped", store.size(), a.txHash());
        metrics.rejected("capacity");
      }
    }
    metrics.accepted(stored);
  }

  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    try {
      if (server != null) {
        server.close();
      }
    } catch (final IOException ignored) {
      // shutting down
    }
    synchronized (connections) {
      for (final Socket s : connections) {
        try {
          s.close();
        } catch (final IOException ignored) {
          // shutting down
        }
      }
    }
    if (acceptor != null) {
      acceptor.interrupt();
    }
  }
}
