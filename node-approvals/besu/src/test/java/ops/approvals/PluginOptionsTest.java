package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
    assertEquals(2, options.verifyWorkers);
    assertEquals(
        600_000,
        parse("--plugin-ops-approval-max-ttl-ms=600000").maxTtlMs);
  }

  private static final String[] REQUIRED = {
    "--plugin-ops-approval-listen=127.0.0.1:0",
    "--plugin-ops-approval-chain-id=31337",
    "--plugin-ops-approval-public-key=" + "11".repeat(32),
    "--plugin-ops-approval-allowed-sources=127.0.0.1/32"
  };

  /** The required options plus {@code more}; an option named in {@code more} replaces its required value. */
  private static PluginOptions valid(final String... more) {
    final List<String> args = new ArrayList<>();
    for (final String required : REQUIRED) {
      final String name = required.substring(0, required.indexOf('=') + 1);
      if (Arrays.stream(more).noneMatch(option -> option.startsWith(name))) {
        args.add(required);
      }
    }
    args.addAll(List.of(more));
    return parse(args.toArray(String[]::new));
  }

  @Test
  void startUpRefusesMissingOrUnboundedSettings() {
    valid().validate();
    for (final String bad :
        new String[] {
          "--plugin-ops-approval-capacity=0",
          "--plugin-ops-approval-wait-ms=-1",
          "--plugin-ops-approval-max-connections=0",
          "--plugin-ops-approval-max-concurrent-calls=0",
          "--plugin-ops-approval-verify-workers=0",
          "--plugin-ops-approval-verify-workers=33",
          "--plugin-ops-approval-allowed-sources=10.0.0.1/8"
        }) {
      assertThrows(IllegalArgumentException.class, () -> valid(bad).validate(), bad);
    }
    assertThrows(IllegalArgumentException.class, () -> parse("--plugin-ops-approval-chain-id=31337").validate(), "no listen address, no key");
  }

  @Test
  void verificationWorkersHaveABoundedOperatorSetting() {
    for (final int workers : new int[] {1, 4, 32}) {
      final PluginOptions options = valid("--plugin-ops-approval-verify-workers=" + workers);
      options.validate();
      assertEquals(workers, options.verifyWorkers);
    }
  }

  @Test
  void theMaximumTtlIsBetweenTenSecondsAndADay() {
    // OPS signs for 10 s at the shortest: room for the wait window plus a block (wire contract §5).
    valid("--plugin-ops-approval-max-ttl-ms=10000").validate();
    valid("--plugin-ops-approval-max-ttl-ms=86400000").validate();
    for (final String ms : new String[] {"9999", "1", "0", "-1", "86400001"}) {
      final IllegalArgumentException refused =
          assertThrows(IllegalArgumentException.class, () -> valid("--plugin-ops-approval-max-ttl-ms=" + ms).validate(), ms);
      assertEquals("--plugin-ops-approval-max-ttl-ms must be between 10000 and 86400000", refused.getMessage());
    }
  }

  @Test
  void startUpRefusesAMissingSourceListAnyMustBeSaid() {
    final String[] withoutSources = Arrays.copyOf(REQUIRED, REQUIRED.length - 1);
    final IllegalArgumentException missing = assertThrows(IllegalArgumentException.class, () -> parse(withoutSources).validate());
    assertTrue(missing.getMessage().startsWith("--plugin-ops-approval-allowed-sources is required"), missing.getMessage());
    assertThrows(IllegalArgumentException.class, () -> parse().allowedSources(), "no default: not even any");

    final AllowedSources any = valid("--plugin-ops-approval-allowed-sources= any ").allowedSources();
    assertTrue(any.allowsAny());
    assertTrue(any.allows(ip("203.0.113.9")));
    assertTrue(any.allows(ip("2001:db8::1")));
    assertEquals("any", any.toString());
    valid("--plugin-ops-approval-allowed-sources=any").validate();
    assertFalse(valid().allowedSources().allowsAny());
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
    for (final String bad :
        new String[] {
          "", "10.0.0.0/33", "10.0.0.1/8", "example.com", "10.0.0.0/8,,", "10.0.0.0/-1", "::1/129",
          // any means every source: beside a block it would say two things at once
          "any,10.0.0.0/8", "10.0.0.0/8, any", "ANY"
        }) {
      assertThrows(IllegalArgumentException.class, () -> AllowedSources.parse(bad), "'" + bad + "'");
    }
  }
}
