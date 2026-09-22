package ops.approvals.bench;

import io.grpc.Server;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;

/**
 * Records when each batch arrives. Same host as the sender, so wall clocks are comparable:
 * {@code recv_ns - sent_ns} is the one-way delivery time of the frame through the transport.
 *
 * <p>Usage: {@code BenchReceiver <tcp|grpc|grpc-mtls> <port> <out.jsonl> [certsDir]}
 */
public final class BenchReceiver {
  private static BufferedWriter out;

  private static long now() {
    final Instant i = Instant.now();
    return i.getEpochSecond() * 1_000_000_000L + i.getNano();
  }

  private static String digest(final byte[] frame) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(frame));
  }

  private static synchronized void record(final String id, final long recv, final int bytes) throws IOException {
    out.write("{\"id\":\"" + id + "\",\"recv_ns\":" + recv + ",\"bytes\":" + bytes + "}\n");
  }

  public static void main(final String[] args) throws Exception {
    final String transport = args[0];
    final int port = Integer.parseInt(args[1]);
    out = new BufferedWriter(new FileWriter(args[2]));
    Runtime.getRuntime().addShutdownHook(new Thread(() -> { try { out.flush(); out.close(); } catch (IOException ignored) {} }));
    if (transport.equals("tcp")) {
      serveTcp(port);
      return;
    }
    final NettyServerBuilder builder =
        NettyServerBuilder.forAddress(new InetSocketAddress("127.0.0.1", port))
            .addService(new Delivery())
            .permitKeepAliveWithoutCalls(true);
    if (transport.equals("grpc-mtls")) {
      final File certs = new File(args[3]);
      final SslContext ssl =
          GrpcSslContexts.forServer(new File(certs, "server.crt"), new File(certs, "server.key"))
              .trustManager(new File(certs, "ca.crt"))
              .clientAuth(ClientAuth.REQUIRE)
              .build();
      builder.sslContext(ssl);
    }
    final Server server = builder.build().start();
    System.out.println("READY " + transport + " " + server.getPort());
    server.awaitTermination();
  }

  /** The raw-TCP shape the plugin listens on: 4-byte big-endian length, then the signed frame. */
  private static void serveTcp(final int port) throws Exception {
    try (ServerSocket server = new ServerSocket()) {
      server.setReuseAddress(true);
      server.bind(new InetSocketAddress("127.0.0.1", port));
      System.out.println("READY tcp " + server.getLocalPort());
      while (true) {
        final Socket socket = server.accept();
        socket.setTcpNoDelay(true);
        new Thread(() -> {
          try (socket; DataInputStream in = new DataInputStream(socket.getInputStream())) {
            while (true) {
              final int length = in.readInt();
              final byte[] frame = in.readNBytes(length);
              final long recv = now();
              record(digest(frame), recv, frame.length);
            }
          } catch (Exception e) {
            // connection closed by the sender at the end of the run
          }
        }).start();
      }
    }
  }

  static final class Delivery extends ApprovalDeliveryGrpc.ApprovalDeliveryImplBase {
    @Override
    public StreamObserver<Batch> deliver(final StreamObserver<Ack> acks) {
      return new StreamObserver<>() {
        @Override
        public void onNext(final Batch batch) {
          final long recv = now();
          try {
            record(batch.getId(), recv, batch.getFrame().size());
          } catch (IOException e) {
            throw new RuntimeException(e);
          }
          acks.onNext(Ack.newBuilder().setId(batch.getId()).setStored(true).build());
        }

        @Override
        public void onError(final Throwable t) {}

        @Override
        public void onCompleted() {
          acks.onCompleted();
        }
      };
    }
  }
}
