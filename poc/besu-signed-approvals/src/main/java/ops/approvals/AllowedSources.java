package ops.approvals;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * The source addresses allowed to open a delivery connection ({@code
 * --plugin-ops-approval-allowed-sources}, required): CIDR blocks, or {@code any}, which leaves it to
 * the network rule that must let only OPS reach the port. A defence in depth behind that rule.
 */
final class AllowedSources {
  /** The spelling of "every source": explicit, so no configuration gets it by omission. */
  static final String ANY_SPEC = "any";

  static final AllowedSources ANY = new AllowedSources(List.of(), ANY_SPEC);

  private record Block(byte[] network, int prefix) {
    boolean contains(final byte[] address) {
      if (address.length != network.length) {
        return false;
      }
      final int whole = prefix / 8;
      if (!Arrays.equals(address, 0, whole, network, 0, whole)) {
        return false;
      }
      final int rest = prefix % 8;
      if (rest == 0) {
        return true;
      }
      final int mask = 0xff << (8 - rest) & 0xff;
      return (address[whole] & mask) == (network[whole] & mask);
    }
  }

  private final List<Block> blocks;
  private final String spec;

  private AllowedSources(final List<Block> blocks, final String spec) {
    this.blocks = blocks;
    this.spec = spec;
  }

  /**
   * Parses {@code any}, or a comma-separated list of {@code address[/prefix]} with literal IPv4 or
   * IPv6 addresses; a bare address is a single host. Host bits set below the prefix are refused, not
   * masked: they usually mean a typo in a security setting. So is {@code any} beside a block.
   */
  static AllowedSources parse(final String spec) {
    if (spec.trim().equals(ANY_SPEC)) {
      return ANY;
    }
    final List<Block> blocks = new ArrayList<>();
    for (final String raw : spec.split(",", -1)) {
      final String entry = raw.trim();
      if (entry.isEmpty()) {
        throw new IllegalArgumentException("empty entry in allowed sources '" + spec + "'");
      }
      if (entry.equals(ANY_SPEC)) {
        throw new IllegalArgumentException("'any' allows every source and cannot be combined with blocks: '" + spec + "'");
      }
      final int slash = entry.indexOf('/');
      final byte[] network = literal(slash < 0 ? entry : entry.substring(0, slash)).getAddress();
      final int prefix;
      try {
        prefix = slash < 0 ? network.length * 8 : Integer.parseInt(entry.substring(slash + 1));
      } catch (final NumberFormatException e) {
        throw new IllegalArgumentException("invalid prefix in '" + entry + "'", e);
      }
      if (prefix < 0 || prefix > network.length * 8) {
        throw new IllegalArgumentException("invalid prefix in '" + entry + "'");
      }
      final Block block = new Block(network, prefix);
      final byte[] masked = new byte[network.length];
      for (int bit = 0; bit < prefix; bit++) {
        masked[bit / 8] |= (byte) (network[bit / 8] & (0x80 >>> (bit % 8)));
      }
      if (!Arrays.equals(masked, network)) {
        throw new IllegalArgumentException("host bits set below the prefix in '" + entry + "'");
      }
      blocks.add(block);
    }
    return new AllowedSources(List.copyOf(blocks), spec.trim());
  }

  private static InetAddress literal(final String address) {
    try {
      return InetAddress.ofLiteral(address); // never a DNS lookup
    } catch (final IllegalArgumentException e) {
      throw new IllegalArgumentException("not an IP address literal: '" + address + "'", e);
    }
  }

  boolean allowsAny() {
    return blocks.isEmpty();
  }

  boolean allows(final InetAddress address) {
    if (blocks.isEmpty()) {
      return true;
    }
    final byte[] bytes = unmapped(address);
    for (final Block block : blocks) {
      if (block.contains(bytes)) {
        return true;
      }
    }
    return false;
  }

  /** An IPv4 peer on a dual-stack socket shows up as ::ffff:a.b.c.d; match it as a.b.c.d. */
  private static byte[] unmapped(final InetAddress address) {
    final byte[] bytes = address.getAddress();
    if (address instanceof Inet6Address && bytes.length == 16) {
      boolean mapped = bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff;
      for (int i = 0; mapped && i < 10; i++) {
        mapped = bytes[i] == 0;
      }
      if (mapped) {
        return Arrays.copyOfRange(bytes, 12, 16);
      }
    }
    return bytes;
  }

  @Override
  public String toString() {
    return spec;
  }
}
