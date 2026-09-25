package ops.approvals;

import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.channel.Channel;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.util.concurrent.DefaultThreadFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Predicate;
import ops.approvals.grpc.ApprovalDeliveryGrpc;
import ops.approvals.grpc.DeliverRequest;
import ops.approvals.grpc.DeliverResponse;
import ops.approvals.grpc.StatusRequest;
import ops.approvals.grpc.StatusResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The {@code ops.approvals.v1.ApprovalDelivery} service OPS dials: one unary {@code Deliver} per
 * batch, whose status is the confirmation, and {@code Status} for the boot id (wire contract §1,
 * §3, §4). Plaintext HTTP/2 on grpc-java and Netty exactly as Besu ships them; only OPS may reach
 * the port (a network rule), and the allowed-sources list and the connection cap refuse anyone else
 * at accept time, before HTTP/2 sees a byte. A connection that does not complete the HTTP/2 preface
 * within 5 s, or carries no call for 30 s, is closed, so nobody who gets through can hold the slots
 * OPS reconnects into.
 */
public final class ApprovalServer implements AutoCloseable {
  private static final Logger LOG = LoggerFactory.getLogger(ApprovalServer.class);
  /** Requests above this are refused by gRPC itself (RESOURCE_EXHAUSTED); a full batch is ~4 KiB. */
  static final int MAX_REQUEST_BYTES = 64 * 1024;
  /** OPS pings an idle connection every 20 s; pings every 10 s are permitted, with no call in flight. */
  static final long PERMIT_KEEPALIVE_MS = 10_000;
  /** A connection must complete its HTTP/2 preface within this, or it is closed. */
  static final long HANDSHAKE_TIMEOUT_MS = 5_000;
  /** A connection that has carried no call for this long is closed; OPS calls Status every second. */
  static final long MAX_CONNECTION_IDLE_MS = 30_000;
  /** Verification runs off Netty's I/O threads; size the pool for the measured batch rate. */
  static final int DEFAULT_VERIFY_WORKERS = 2;
  static final int MAX_VERIFY_WORKERS = 32;
  private static final int IO_THREADS = 2;
  private static final long REFUSAL_LOG_INTERVAL_MS = 60_000;
  static final Metadata.Key<String> REASON = Metadata.Key.of("ops-approval-reason", Metadata.ASCII_STRING_MARSHALLER);

  /**
   * @param sources who may connect
   * @param maxConnections open connections at most; one per OPS instance is the norm
   * @param maxConcurrentCalls calls in flight per connection (HTTP/2 streams); OPS bounds its own
   * @param permitKeepAliveMs the shortest ping interval tolerated, calls in flight or not
   * @param maxConnectionIdleMs how long a connection may carry no call before it is closed
   */
  public record Limits(
      AllowedSources sources, int maxConnections, int maxConcurrentCalls, long permitKeepAliveMs, long maxConnectionIdleMs) {}

  /** Connection refusals; a no-op implementation is used in tests. */
  public interface Metrics {
    Metrics NONE = new Metrics() {};

    /** A connection closed at accept: "source" (not allowed) or "limit" (the cap was reached). */
    default void refused(String reason) {}
  }

  private final InetSocketAddress bind;
  private final ApprovalIngress ingress;
  private final Limits limits;
  private final Metrics metrics;
  private final int verifyWorkers;
  private final AtomicInteger connections = new AtomicInteger();
  private final AtomicLong lastRefusalLogged = new AtomicLong();
  private EventLoopGroup acceptor;
  private EventLoopGroup io;
  private ExecutorService calls;
  private Server server;

  public ApprovalServer(final InetSocketAddress bind, final ApprovalIngress ingress, final Limits limits, final Metrics metrics) {
    this(bind, ingress, limits, metrics, DEFAULT_VERIFY_WORKERS);
  }

  public ApprovalServer(final InetSocketAddress bind, final ApprovalIngress ingress, final Limits limits, final Metrics metrics, final int verifyWorkers) {
    if (verifyWorkers < 1 || verifyWorkers > MAX_VERIFY_WORKERS) {
      throw new IllegalArgumentException("approval verify workers must be between 1 and " + MAX_VERIFY_WORKERS);
    }
    this.bind = bind;
    this.ingress = ingress;
    this.limits = limits;
    this.metrics = metrics;
    this.verifyWorkers = verifyWorkers;
  }

  public void start() throws IOException {
    acceptor = new MultiThreadIoEventLoopGroup(1, new DefaultThreadFactory("ops-approval-accept", true), NioIoHandler.newFactory());
    io = new MultiThreadIoEventLoopGroup(IO_THREADS, new DefaultThreadFactory("ops-approval-io", true), NioIoHandler.newFactory());
    calls = Executors.newFixedThreadPool(verifyWorkers, Thread.ofPlatform().name("ops-approval-call-", 1).daemon(true).factory());
    try {
      server =
          NettyServerBuilder.forAddress(bind)
              // Our own NIO channel and event loops: the accept-time guard needs the channel class,
              // and Netty requires loops of the same transport.
              .channelFactory(() -> new GuardedServerChannel(this::admit))
              // A restarted producer rebinds the address OPS dials while old connections linger.
              .withOption(ChannelOption.SO_REUSEADDR, true)
              .bossEventLoopGroup(acceptor)
              .workerEventLoopGroup(io)
              .executor(calls)
              .addService(new Delivery())
              .maxInboundMessageSize(MAX_REQUEST_BYTES)
              .maxConcurrentCallsPerConnection(limits.maxConcurrentCalls())
              .permitKeepAliveTime(limits.permitKeepAliveMs(), TimeUnit.MILLISECONDS)
              .permitKeepAliveWithoutCalls(true)
              // A peer that reaches the port must not hold a connection slot for nothing: no
              // HTTP/2 preface within 5 s, or no call for the idle limit, closes the connection.
              // Keepalive pings are not calls; OPS's Status every second is.
              .handshakeTimeout(HANDSHAKE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
              .maxConnectionIdle(limits.maxConnectionIdleMs(), TimeUnit.MILLISECONDS)
              .build()
              .start();
    } catch (final IOException | RuntimeException e) {
      close();
      throw e;
    }
  }

  public int port() {
    return server.getPort();
  }

  /** Open delivery connections, for the connected gauge. */
  public int connections() {
    return connections.get();
  }

  /** Runs on the single accept thread, so the cap check and the increment cannot race. */
  private boolean admit(final Channel child) {
    final SocketAddress remote = child.remoteAddress();
    if (!(remote instanceof InetSocketAddress peer) || peer.getAddress() == null || !limits.sources().allows(peer.getAddress())) {
      refuse("source", remote);
      return false;
    }
    if (connections.get() >= limits.maxConnections()) {
      refuse("limit", remote);
      return false;
    }
    connections.incrementAndGet();
    child.closeFuture().addListener(closed -> connections.decrementAndGet());
    return true;
  }

  private void refuse(final String reason, final SocketAddress remote) {
    metrics.refused(reason);
    // A scanner must not flood the log: one line a minute, the counter has the rest.
    final long now = System.currentTimeMillis();
    final long last = lastRefusalLogged.get();
    if (now - last >= REFUSAL_LOG_INTERVAL_MS && lastRefusalLogged.compareAndSet(last, now)) {
      LOG.warn(
          "OPS approval ingress: refused a connection from {} ({}; allowed sources {}, {} of {} connections open)",
          remote,
          reason,
          limits.sources(),
          connections.get(),
          limits.maxConnections());
    }
  }

  /**
   * Stops accepting (calls are answered UNAVAILABLE from here on), lets calls in flight finish for
   * up to 2 s, then releases the port, the call threads and the event loops, in that order, each
   * waited for: a restarted producer must be able to rebind at once.
   */
  @Override
  public void close() {
    ingress.stop();
    try {
      if (server != null) {
        server.shutdown();
        if (!server.awaitTermination(2, TimeUnit.SECONDS)) {
          server.shutdownNow();
          server.awaitTermination(1, TimeUnit.SECONDS);
        }
      }
      if (calls != null) {
        calls.shutdown();
        if (!calls.awaitTermination(1, TimeUnit.SECONDS)) {
          calls.shutdownNow();
        }
      }
    } catch (final InterruptedException e) {
      if (server != null) {
        server.shutdownNow();
      }
      if (calls != null) {
        calls.shutdownNow();
      }
      Thread.currentThread().interrupt();
    }
    for (final EventLoopGroup group : new EventLoopGroup[] {io, acceptor}) {
      if (group != null) {
        group.shutdownGracefully(0, 1, TimeUnit.SECONDS).awaitUninterruptibly(2, TimeUnit.SECONDS);
      }
    }
  }

  private final class Delivery extends ApprovalDeliveryGrpc.ApprovalDeliveryImplBase {
    @Override
    public void deliver(final DeliverRequest request, final StreamObserver<DeliverResponse> response) {
      final ApprovalIngress.Outcome outcome = ingress.deliver(request.getBatch().toByteArray());
      if (outcome.code() == Status.Code.OK) {
        response.onNext(DeliverResponse.newBuilder().setBootId(ingress.bootId()).setStored(outcome.stored()).build());
        response.onCompleted();
        return;
      }
      final Metadata trailers = new Metadata();
      if (outcome.reason() != null) {
        trailers.put(REASON, outcome.reason());
      }
      response.onError(Status.fromCode(outcome.code()).withDescription(outcome.detail()).asRuntimeException(trailers));
    }

    @Override
    public void status(final StatusRequest request, final StreamObserver<StatusResponse> response) {
      if (!ingress.accepting()) {
        response.onError(Status.UNAVAILABLE.withDescription("receiver stopping").asRuntimeException());
        return;
      }
      response.onNext(ingress.status());
      response.onCompleted();
    }
  }

  /**
   * Accepts as Netty does, then closes a connection the guard refuses before it reaches a pipeline:
   * no HTTP/2 state, no buffers, no call for it. A refusal still counts against the read budget, so
   * a flood of refused connections cannot monopolise the accept loop.
   */
  private static final class GuardedServerChannel extends NioServerSocketChannel {
    private final Predicate<Channel> admit;

    GuardedServerChannel(final Predicate<Channel> admit) {
      this.admit = admit;
    }

    @Override
    protected int doReadMessages(final List<Object> buf) throws Exception {
      final int read = super.doReadMessages(buf);
      if (read > 0 && buf.get(buf.size() - 1) instanceof Channel child) {
        boolean admitted;
        try {
          admitted = admit.test(child);
        } catch (final Throwable t) {
          // Netty would still hand the accepted child on after an exception here: fail closed.
          admitted = false;
        }
        if (!admitted) {
          buf.remove(buf.size() - 1);
          child.unsafe().closeForcibly();
        }
      }
      return read;
    }
  }
}
