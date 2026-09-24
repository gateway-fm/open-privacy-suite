package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

/** The {@code --plugin-ops-approval-*} options: the wire contract §7 and the delivery limits. */
class PluginOptionsTest {
  private static PluginOptions parse(final String... args) {
    final PluginOptions options = new PluginOptions();
    new CommandLine(options).parseArgs(args);
    return options;
  }

  private static InetAddress ip(final String literal) {
    return InetAddress.ofLiteral(literal);
  }

  @Test
  void defaultsFollowTheContract() {
    final PluginOptions options = parse();
    assertEquals(3_600_000, options.maxTtlMs);
    assertEquals(100_000, options.capacity);
    assertEquals(5_000, options.waitMs);
    assertEquals(32, options.maxConnections);
    assertEquals(32, options.maxConcurrentCalls);
    assertTrue(options.allowedSources().allowsAny());
    assertEquals(
        600_000,
        parse("--plugin-ops-approval-max-ttl-ms=600000").maxTtlMs);
  }

  private static PluginOptions valid(final String... more) {
    final String[] required = {
      "--plugin-ops-approval-listen=127.0.0.1:0", "--plugin-ops-approval-chain-id=31337", "--plugin-ops-approval-public-key=" + "11".repeat(32)
    };
    final String[] args = java.util.Arrays.copyOf(required, required.length + more.length);
    System.arraycopy(more, 0, args, required.length, more.length);
    return parse(args);
  }

  @Test
  void startUpRefusesMissingOrUnboundedSettings() {
    valid().validate();
    valid("--plugin-ops-approval-max-ttl-ms=86400000").validate();
    for (final String bad :
        new String[] {
          "--plugin-ops-approval-max-ttl-ms=86400001",
          "--plugin-ops-approval-max-ttl-ms=0",
          "--plugin-ops-approval-capacity=0",
          "--plugin-ops-approval-wait-ms=-1",
          "--plugin-ops-approval-max-connections=0",
          "--plugin-ops-approval-max-concurrent-calls=0",
          "--plugin-ops-approval-allowed-sources=10.0.0.1/8"
        }) {
      assertThrows(IllegalArgumentException.class, () -> valid(bad).validate(), bad);
    }
    assertThrows(IllegalArgumentException.class, () -> parse("--plugin-ops-approval-chain-id=31337").validate(), "no listen address, no key");
  }

  @Test
  void aKeyIdTrustedTwiceIsAConfigurationError() {
    // --public-key is the id 'default'; naming 'default' again in --public-keys is ambiguous.
    assertThrows(
        IllegalArgumentException.class,
        () -> valid("--plugin-ops-approval-public-keys=default=" + "22".repeat(32)).trustedKeys());
    assertThrows(IllegalArgumentException.class, () -> PluginOptions.parseKeys("a=" + "11".repeat(32) + ",a=" + "22".repeat(32)));
    assertEquals(2, valid("--plugin-ops-approval-public-keys=next=" + "22".repeat(32)).trustedKeys().size());
  }

  @Test
  void theOrphanLifetimeIsGoneExpiryReplacesIt() {
    assertThrows(CommandLine.UnmatchedArgumentException.class, () -> parse("--plugin-ops-approval-orphan-ttl-ms=300000"));
  }

  @Test
  void parsesTheListenAddress() {
    assertEquals(new InetSocketAddress("127.0.0.1", 9000), parse("--plugin-ops-approval-listen=127.0.0.1:9000").listenAddress());
    final InetSocketAddress v6 = parse("--plugin-ops-approval-listen=[::1]:9001").listenAddress();
    assertTrue(v6.getAddress() instanceof Inet6Address, v6.toString());
    assertEquals(9001, v6.getPort());
    for (final String bad : new String[] {"9000", "127.0.0.1:", "127.0.0.1:x", "127.0.0.1:70000", "[::1]9000"}) {
      assertThrows(IllegalArgumentException.class, () -> parse("--plugin-ops-approval-listen=" + bad).listenAddress(), bad);
    }
  }

  @Test
  void allowedSourcesAreCidrBlocksMatchedOnTheRemoteAddress() {
    final AllowedSources sources =
        parse("--plugin-ops-approval-allowed-sources=10.0.0.0/8, 192.168.1.7 ,2001:db8::/32").allowedSources();
    assertFalse(sources.allowsAny());
    assertTrue(sources.allows(ip("10.1.2.3")));
    assertFalse(sources.allows(ip("11.0.0.1")));
    assertTrue(sources.allows(ip("192.168.1.7")));
    assertFalse(sources.allows(ip("192.168.1.8")));
    assertTrue(sources.allows(ip("2001:db8::1")));
    assertFalse(sources.allows(ip("2001:db9::1")));
    assertFalse(sources.allows(ip("::1")));
  }

  @Test
  void anIpv4PeerOnADualStackSocketMatchesItsIpv4Block() throws Exception {
    final byte[] mapped = new byte[16];
    mapped[10] = (byte) 0xff;
    mapped[11] = (byte) 0xff;
    mapped[12] = 10;
    mapped[15] = 9;
    final InetAddress peer = Inet6Address.getByAddress(null, mapped, -1);
    assertTrue(AllowedSources.parse("10.0.0.0/8").allows(peer), peer.toString());
    assertFalse(AllowedSources.parse("::/0").allows(ip("10.0.0.9")), "an IPv6 block never matches an IPv4 peer");
  }

  @Test
  void refusesMalformedSourceLists() {
    for (final String bad : new String[] {"", "10.0.0.0/33", "10.0.0.1/8", "example.com", "10.0.0.0/8,,", "10.0.0.0/-1", "::1/129"}) {
      assertThrows(IllegalArgumentException.class, () -> AllowedSources.parse(bad), "'" + bad + "'");
    }
  }
}
