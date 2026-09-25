package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.protobuf.ByteString;
import io.grpc.ConnectivityState;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.NettyChannelBuilder;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.MultiThreadIoEventLoopGroup;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.channel.nio.NioIoHandler;
import io.netty.channel.socket.SocketChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.http2.DefaultHttp2PingFrame;
import io.netty.handler.codec.http2.Http2Error;
import io.netty.handler.codec.http2.Http2Frame;
import io.netty.handler.codec.http2.Http2FrameCodecBuilder;
import io.netty.handler.codec.http2.Http2GoAwayFrame;
import io.netty.handler.codec.http2.Http2PingFrame;
import io.netty.handler.codec.http2.Http2SettingsFrame;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import ops.approvals.grpc.ApprovalDeliveryGrpc;
import ops.approvals.grpc.DeliverRequest;
import ops.approvals.grpc.DeliverResponse;
import ops.approvals.grpc.StatusRequest;
import ops.approvals.grpc.StatusResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** The gRPC service on a real loopback socket, called by a grpc-java client as OPS would. */
class ApprovalServerTest {
  private static final long TTL = 600_000;
  private static final long MAX_TTL = 3_600_000;

  private final Deque<AutoCloseable> closing = new ArrayDeque<>();
  private final List<String> refused = new CopyOnWriteArrayList<>();
  private ApprovalStore store;
  private ApprovalIngress ingress;

  @AfterEach
  void closeAll() throws Exception {
    while (!closing.isEmpty()) {
      closing.pop().close();
    }
  }

  private static ApprovalServer.Limits limits() {
    return limits(AllowedSources.ANY, 32);
  }

  /** The production timings: keepalive pings every 10 s permitted, idle connections closed at 30 s. */
  private static ApprovalServer.Limits limits(final AllowedSources sources, final int maxConnections) {
    return new ApprovalServer.Limits(
        sources, maxConnections, 32, ApprovalServer.PERMIT_KEEPALIVE_MS, ApprovalServer.MAX_CONNECTION_IDLE_MS);
  }

  private ApprovalServer start(final ApprovalServer.Limits limits, final int capacity) throws Exception {
    return start(
        limits,
        capacity,
        new ApprovalServer.Metrics() {
          @Override
          public void refused(final String reason) {
            refused.add(reason);
          }
        });
  }

  private ApprovalServer start(final ApprovalServer.Limits limits, final int capacity, final ApprovalServer.Metrics metrics)
      throws Exception {
    store = new ApprovalStore(capacity, 5_000, System::currentTimeMillis);
    ingress =
        new ApprovalIngress(
            new ApprovalVerifier(Map.of("default", Fixtures.FIXTURE_PUBLIC_KEY)),
            Fixtures.CHAIN,
            MAX_TTL,
            store,
            new WaitWindow(5_000, System.currentTimeMillis()),
            System::currentTimeMillis,
            ApprovalIngress.Metrics.NONE);
    final ApprovalServer server = new ApprovalServer(new InetSocketAddress("127.0.0.1", 0), ingress, limits, metrics);
    server.start();
    closing.push(server);
    return server;
  }

  private ApprovalDeliveryGrpc.ApprovalDeliveryBlockingStub client(final ApprovalServer server) {
    final ManagedChannel channel = NettyChannelBuilder.forAddress("127.0.0.1", server.port()).usePlaintext().build();
    closing.push(
        () -> {
          channel.shutdownNow();
          channel.awaitTermination(5, TimeUnit.SECONDS);
        });
    return ApprovalDeliveryGrpc.newBlockingStub(channel);
  }

  private static DeliverRequest request(final byte[] envelope) {
    return DeliverRequest.newBuilder().setBatch(ByteString.copyFrom(envelope)).build();
  }

  private static byte[] batch(final Approval... approvals) {
    final long now = System.currentTimeMillis();
    return Fixtures.envelope("default", now, now + TTL, List.of(approvals));
  }

  private static StatusRuntimeException refusal(final Executable call) {
    return assertThrows(StatusRuntimeException.class, call);
  }

  @Test
  void deliversOverGrpcAndAnswersWithTheBootId() throws Exception {
    final ApprovalServer server = start(limits(), 100);
    final ApprovalDeliveryGrpc.ApprovalDeliveryBlockingStub stub = client(server).withDeadlineAfter(5, TimeUnit.SECONDS);
    final StatusResponse status = stub.status(StatusRequest.getDefaultInstance());
    assertEquals(ingress.bootId(), status.getBootId());
    assertTrue(status.getBootId().matches("[0-9a-f]{32}"), status.getBootId());
    assertEquals(Fixtures.CHAIN, status.getChainId());
    assertEquals(List.of("default"), status.getTrustedKeyIdsList());
    assertEquals(MAX_TTL, status.getMaxTtlMs());
    assertEquals(100, status.getCapacity());
    assertEquals(5_000, status.getWaitMs());

    final byte[] envelope = batch(Fixtures.approval(1, 1), Fixtures.approval(2, 2));
    final DeliverResponse ok = stub.deliver(request(envelope));
    assertEquals(status.getBootId(), ok.getBootId());
    assertEquals(2, ok.getStored());
    assertTrue(store.get(Fixtures.hash(1)).isPresent());
    assertTrue(store.get(Fixtures.hash(2)).isPresent());
    assertEquals(2, stub.deliver(request(envelope)).getStored(), "a redelivery is OK with stored = n");
    assertEquals(2, store.size());
  }

  @Test
  void refusalsTravelAsTheirContractStatusCodes() throws Exception {
    final ApprovalServer server = start(limits(), 1);
    final ApprovalDeliveryGrpc.ApprovalDeliveryBlockingStub stub = client(server).withDeadlineAfter(5, TimeUnit.SECONDS);
    final long now = System.currentTimeMillis();
    final byte[] flipped = batch(Fixtures.approval(1, 1));
    flipped[flipped.length - 1] ^= 1;
    assertEquals(Status.Code.UNAUTHENTICATED, refusal(() -> stub.deliver(request(flipped))).getStatus().getCode());
    assertEquals(
        Status.Code.PERMISSION_DENIED,
        refusal(() -> stub.deliver(request(Fixtures.envelope("next", now, now + TTL, List.of(Fixtures.approval(1, 1))))))
            .getStatus()
            .getCode());
    assertEquals(
        Status.Code.INVALID_ARGUMENT,
        refusal(() -> stub.deliver(request(batch(Fixtures.approval(1, 1, 1))))).getStatus().getCode());
    assertEquals(
        Status.Code.FAILED_PRECONDITION,
        refusal(() -> stub.deliver(request(Fixtures.envelope("default", now - TTL, now - 1, List.of(Fixtures.approval(1, 1))))))
            .getStatus()
            .getCode());

    stub.deliver(request(batch(Fixtures.approval(1, 1))));
    final StatusRuntimeException full = refusal(() -> stub.deliver(request(batch(Fixtures.approval(2, 2)))));
    assertEquals(Status.Code.UNAVAILABLE, full.getStatus().getCode());
    assertEquals("store-full", full.getTrailers().get(ApprovalServer.REASON));
  }

  @Test
  void requestsAboveSixtyFourKibAreRefusedByGrpcBeforeTheReceiverSeesThem() throws Exception {
    final ApprovalServer server = start(limits(), 10);
    final ApprovalDeliveryGrpc.ApprovalDeliveryBlockingStub stub = client(server).withDeadlineAfter(5, TimeUnit.SECONDS);
    assertEquals(
        Status.Code.INVALID_ARGUMENT,
        refusal(() -> stub.deliver(request(new byte[60_000]))).getStatus().getCode(),
        "under the cap it reaches the receiver, which finds no batch in it");
    assertEquals(
        Status.Code.RESOURCE_EXHAUSTED,
        refusal(() -> stub.deliver(request(new byte[ApprovalServer.MAX_REQUEST_BYTES + 1]))).getStatus().getCode());
  }

  @Test
  void aStoppedReceiverAnswersUnavailable() throws Exception {
    final ApprovalServer server = start(limits(), 10);
    final ApprovalDeliveryGrpc.ApprovalDeliveryBlockingStub stub = client(server);
    stub.withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance());
    server.close();
    assertEquals(
        Status.Code.UNAVAILABLE,
        refusal(() -> stub.withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance()))
            .getStatus()
            .getCode());
  }

  @Test
  void aSourceOutsideTheAllowedListIsDisconnectedBeforeAnyCall() throws Exception {
    final ApprovalServer server =
        start(limits(AllowedSources.parse("10.0.0.0/8"), 32), 10);
    final ApprovalDeliveryGrpc.ApprovalDeliveryBlockingStub stub = client(server).withDeadlineAfter(5, TimeUnit.SECONDS);
    assertEquals(
        Status.Code.UNAVAILABLE, refusal(() -> stub.status(StatusRequest.getDefaultInstance())).getStatus().getCode());
    assertEquals(0, store.size());
    assertTrue(refused.contains("source"), refused.toString());
    assertEquals(0, server.connections());
  }

  @Test
  void aGuardThatThrowsStillRefusesTheConnection() throws Exception {
    // A failing metrics backend must not turn the source check into an open door.
    final ApprovalServer server =
        start(
            limits(AllowedSources.parse("10.0.0.0/8"), 32),
            10,
            new ApprovalServer.Metrics() {
              @Override
              public void refused(final String reason) {
                throw new IllegalStateException("metrics backend down");
              }
            });
    final ApprovalDeliveryGrpc.ApprovalDeliveryBlockingStub stub = client(server).withDeadlineAfter(5, TimeUnit.SECONDS);
    assertEquals(
        Status.Code.UNAVAILABLE, refusal(() -> stub.status(StatusRequest.getDefaultInstance())).getStatus().getCode());
    assertEquals(0, server.connections());
  }

  @Test
  void closingReleasesTheListeningPortAtOnce() throws Exception {
    final ApprovalServer server = start(limits(), 10);
    client(server).withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance());
    final int port = server.port();
    server.close();
    try (ServerSocket again = new ServerSocket()) {
      again.setReuseAddress(true); // the accepted connection may linger in TIME_WAIT; the listener may not
      again.bind(new InetSocketAddress("127.0.0.1", port));
    }
  }

  @Test
  void connectionsBeyondTheCapAreRefusedUntilOneCloses() throws Exception {
    final ApprovalServer server =
        start(limits(AllowedSources.parse("127.0.0.0/8"), 1), 10);
    final ManagedChannel first = NettyChannelBuilder.forAddress("127.0.0.1", server.port()).usePlaintext().build();
    try {
      ApprovalDeliveryGrpc.newBlockingStub(first).withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance());
      assertEquals(1, server.connections());
      final ApprovalDeliveryGrpc.ApprovalDeliveryBlockingStub second = client(server).withDeadlineAfter(5, TimeUnit.SECONDS);
      assertEquals(
          Status.Code.UNAVAILABLE, refusal(() -> second.status(StatusRequest.getDefaultInstance())).getStatus().getCode());
      assertTrue(refused.contains("limit"), refused.toString());
    } finally {
      first.shutdownNow();
      first.awaitTermination(5, TimeUnit.SECONDS);
    }
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (server.connections() > 0 && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    assertEquals(0, server.connections());
    client(server).withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance());
  }

  @Test
  void anIdleConnectionMayPingAtThePermittedRateButNoFaster() throws Exception {
    final long permit = 300;
    final ApprovalServer server = start(new ApprovalServer.Limits(AllowedSources.ANY, 4, 7, permit, ApprovalServer.MAX_CONNECTION_IDLE_MS), 10);
    try (Http2Probe probe = new Http2Probe(server.port())) {
      assertEquals(7L, probe.settings.get(5, TimeUnit.SECONDS), "SETTINGS advertise the concurrent call cap");
      for (int i = 0; i < 5; i++) {
        Thread.sleep(permit * 3 / 2);
        probe.ping(i);
      }
      Thread.sleep(permit);
      assertNull(probe.goAway.getNow(null), "pings at 1.5 x the permitted interval, no call in flight, are accepted");
      assertEquals(5, probe.acks.get());
    }
    try (Http2Probe probe = new Http2Probe(server.port())) {
      probe.settings.get(5, TimeUnit.SECONDS);
      for (int i = 0; i < 6 && !probe.goAway.isDone(); i++) {
        Thread.sleep(permit / 15);
        probe.ping(i);
      }
      assertEquals(Http2Error.ENHANCE_YOUR_CALM.code(), probe.goAway.get(5, TimeUnit.SECONDS), "faster pings are refused");
    }
    assertEquals(ApprovalServer.PERMIT_KEEPALIVE_MS, 10_000, "the contract: pings every 10 s are permitted");
  }

  /** grpc-java raises a shorter idle limit to one second; the tests use that floor. */
  private static final long IDLE_MS = 1_000;

  @Test
  void aConnectionThatKeepsCallingOutlivesTheIdleLimitAndLosesItOnceItStops() throws Exception {
    final ApprovalServer server = start(new ApprovalServer.Limits(AllowedSources.ANY, 4, 32, ApprovalServer.PERMIT_KEEPALIVE_MS, IDLE_MS), 10);
    final ManagedChannel channel = NettyChannelBuilder.forAddress("127.0.0.1", server.port()).usePlaintext().build();
    closing.push(
        () -> {
          channel.shutdownNow();
          channel.awaitTermination(5, TimeUnit.SECONDS);
        });
    final ApprovalDeliveryGrpc.ApprovalDeliveryBlockingStub stub = ApprovalDeliveryGrpc.newBlockingStub(channel);
    stub.withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance());
    assertEquals(ConnectivityState.READY, channel.getState(false));
    final List<ConnectivityState> left = new CopyOnWriteArrayList<>();
    follow(channel, ConnectivityState.READY, left);

    // OPS calls Status every second against a 30 s limit; here a call every 200 ms for three limits.
    final long busyUntil = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(3 * IDLE_MS);
    long lastCallStarted = System.nanoTime();
    while (System.nanoTime() < busyUntil) {
      lastCallStarted = System.nanoTime();
      stub.withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance());
      Thread.sleep(IDLE_MS / 5);
    }
    assertEquals(List.of(), left, "a connection that keeps calling is never closed for idleness");
    assertEquals(1, server.connections());

    // Idle time starts after the last call, including the final sleep above. Measuring from
    // here would subtract that sleep and incorrectly report a correctly timed close as early.
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (left.isEmpty() && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    assertEquals(ConnectivityState.IDLE, left.isEmpty() ? null : left.get(0), "the server closed the idle connection");
    assertTrue(System.nanoTime() - lastCallStarted >= TimeUnit.MILLISECONDS.toNanos(IDLE_MS * 9 / 10), "not before the limit");
    awaitConnections(server, 0);
  }

  @Test
  void aConnectionThatNeverCallsLosesItsSlotAtTheIdleLimit() throws Exception {
    // One slot, held by a peer that completed the HTTP/2 preface and then says nothing: OPS's
    // reconnect is refused until the idle limit frees the slot.
    final ApprovalServer server = start(new ApprovalServer.Limits(AllowedSources.ANY, 1, 32, ApprovalServer.PERMIT_KEEPALIVE_MS, IDLE_MS), 10);
    try (Http2Probe squatter = new Http2Probe(server.port())) {
      final long opened = System.nanoTime();
      squatter.settings.get(5, TimeUnit.SECONDS);
      assertEquals(1, server.connections());
      final ManagedChannel refusedChannel = NettyChannelBuilder.forAddress("127.0.0.1", server.port()).usePlaintext().build();
      try {
        assertEquals(
            Status.Code.UNAVAILABLE,
            refusal(() -> ApprovalDeliveryGrpc.newBlockingStub(refusedChannel).withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance()))
                .getStatus()
                .getCode());
        assertTrue(refused.contains("limit"), refused.toString());
      } finally {
        refusedChannel.shutdownNow(); // its reconnect attempts would race for the slot below
        refusedChannel.awaitTermination(5, TimeUnit.SECONDS);
      }
      assertEquals(Http2Error.NO_ERROR.code(), squatter.goAway.get(10, TimeUnit.SECONDS), "a graceful GOAWAY for idleness");
      squatter.closed.get(10, TimeUnit.SECONDS);
      assertTrue(System.nanoTime() - opened >= TimeUnit.MILLISECONDS.toNanos(IDLE_MS * 9 / 10), "not before the limit");
    }
    awaitConnections(server, 0);
    client(server).withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance());
    assertEquals(30_000, ApprovalServer.MAX_CONNECTION_IDLE_MS, "the contract: no call for 30 s closes a connection");
  }

  @Test
  void aConnectionThatNeverSendsThePrefaceLosesItsSlotAfterFiveSeconds() throws Exception {
    final ApprovalServer server = start(limits(AllowedSources.ANY, 1), 10);
    try (Socket silent = new Socket("127.0.0.1", server.port())) {
      final long opened = System.nanoTime();
      silent.setSoTimeout(15_000);
      awaitConnections(server, 1);
      final InputStream in = silent.getInputStream();
      while (in.read() >= 0) {
        // the server's own SETTINGS, then nothing until it closes
      }
      final long heldMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - opened);
      assertTrue(heldMs >= ApprovalServer.HANDSHAKE_TIMEOUT_MS - 500 && heldMs < ApprovalServer.HANDSHAKE_TIMEOUT_MS + 3_000, heldMs + " ms");
    }
    awaitConnections(server, 0);
    client(server).withDeadlineAfter(5, TimeUnit.SECONDS).status(StatusRequest.getDefaultInstance());
    assertEquals(5_000, ApprovalServer.HANDSHAKE_TIMEOUT_MS, "the contract: the HTTP/2 preface within 5 s");
  }

  private static void awaitConnections(final ApprovalServer server, final int expected) throws InterruptedException {
    final long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (server.connections() != expected && System.nanoTime() < deadline) {
      Thread.sleep(10);
    }
    assertEquals(expected, server.connections());
  }

  /** Records every state the channel moves to after {@code from}, until it shuts down. */
  private static void follow(final ManagedChannel channel, final ConnectivityState from, final List<ConnectivityState> seen) {
    channel.notifyWhenStateChanged(
        from,
        () -> {
          final ConnectivityState now = channel.getState(false);
          seen.add(now);
          if (now != ConnectivityState.SHUTDOWN) {
            follow(channel, now, seen);
          }
        });
  }

  /** An HTTP/2 connection that makes no call at all: only SETTINGS and PING frames. */
  private static final class Http2Probe implements AutoCloseable {
    final CompletableFuture<Long> settings = new CompletableFuture<>();
    final CompletableFuture<Long> goAway = new CompletableFuture<>();
    final CompletableFuture<Void> closed = new CompletableFuture<>();
    final AtomicInteger acks = new AtomicInteger();
    private final EventLoopGroup group = new MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory());
    private final Channel channel;

    Http2Probe(final int port) throws InterruptedException {
      channel =
          new Bootstrap()
              .group(group)
              .channel(NioSocketChannel.class)
              .handler(
                  new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(final SocketChannel ch) {
                      ch.pipeline()
                          .addLast(
                              Http2FrameCodecBuilder.forClient().build(),
                              new SimpleChannelInboundHandler<Http2Frame>() {
                                @Override
                                protected void channelRead0(final ChannelHandlerContext ctx, final Http2Frame frame) {
                                  if (frame instanceof Http2SettingsFrame s) {
                                    settings.complete(s.settings().maxConcurrentStreams());
                                  } else if (frame instanceof Http2PingFrame p && p.ack()) {
                                    acks.incrementAndGet();
                                  } else if (frame instanceof Http2GoAwayFrame g) {
                                    goAway.complete(g.errorCode());
                                  }
                                }
                              });
                    }
                  })
              .connect("127.0.0.1", port)
              .sync()
              .channel();
      channel.closeFuture().addListener(done -> closed.complete(null));
    }

    void ping(final long content) {
      channel.writeAndFlush(new DefaultHttp2PingFrame(content));
    }

    @Override
    public void close() {
      try {
        assertTrue(channel.close().awaitUninterruptibly(5, TimeUnit.SECONDS), "probe channel closed");
      } finally {
        assertTrue(
            group.shutdownGracefully(0, 1, TimeUnit.SECONDS).awaitUninterruptibly(5, TimeUnit.SECONDS),
            "probe event loop stopped");
      }
    }
  }
}
