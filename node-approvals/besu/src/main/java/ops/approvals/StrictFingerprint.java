package ops.approvals;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Hash;

/**
 * Strict V2: the call tree plus the application state the execution read and wrote. A direct port of
 * {@code internal/nodeapproval.Fingerprint} — same projection, same canonical JSON, same domain — so
 * the two implementations can be compared on every preflight. Unlike calls V3 this mode binds
 * storage, balances, contract nonces, code, logs and return data, and it accepts CREATE/CREATE2/
 * SELFDESTRUCT, which is why lifecycle transactions use it.
 */
public final class StrictFingerprint {
  private static final byte[] DOMAIN = "OPS_EXECUTION_V2\0".getBytes(StandardCharsets.US_ASCII);
  private static final int MAX_BYTES = 1 << 20;
  private static final String EMPTY_CODE = "0x";
  private static final Set<String> CALL_TYPES =
      Set.of("CALL", "STATICCALL", "DELEGATECALL", "CALLCODE", "CREATE", "CREATE2", "SELFDESTRUCT");

  private StrictFingerprint() {}

  /**
   * @param calls geth-shaped call tree (as {@code CallTreeJson} emits it)
   * @param pre account state before the transaction, keyed by address
   * @param diff changed accounts: {@code {"pre": {...}, "post": {...}}}
   */
  public static Hash of(
      final Map<String, Object> calls, final Map<String, Object> pre, final Map<String, Object> diff)
      throws UnsupportedExecutionException {
    final Set<String> created = new HashSet<>();
    final Map<String, Object> tree = normalizeCall(calls, null, created, new int[1]);

    final Map<String, Object> diffPre = object(diff.get("pre"));
    final Map<String, Object> diffPost = object(diff.get("post"));
    final Set<String> addresses = new TreeSet<>();
    addresses.addAll(pre.keySet());
    addresses.addAll(diffPre.keySet());
    addresses.addAll(diffPost.keySet());

    final List<Object> accounts = new ArrayList<>();
    for (final String address : addresses) {
      if (!isAddress(address)) {
        throw new UnsupportedExecutionException("invalid account address " + address);
      }
      final Map<String, Object> before = object(pre.get(address));
      final boolean hasPre = diffPre.containsKey(address);
      final boolean hasPost = diffPost.containsKey(address);
      final boolean deleted = hasPre && !hasPost;
      final Map<String, Object> post = object(diffPost.get(address));

      final String codeBefore = string(before.get("code"), EMPTY_CODE).toLowerCase(Locale.ROOT);
      final String codeAfter =
          deleted ? EMPTY_CODE : string(post.get("code"), codeBefore).toLowerCase(Locale.ROOT);
      final BigInteger balanceBefore = number(before.get("balance"));
      BigInteger balanceAfter = balanceBefore;
      if (post.containsKey("balance")) {
        balanceAfter = number(post.get("balance"));
      }
      if (deleted) {
        balanceAfter = BigInteger.ZERO;
      }
      final String delta = balanceAfter.subtract(balanceBefore).toString();

      final Map<String, Object> slotsBefore = object(before.get("storage"));
      final Map<String, Object> slotsPre = object(object(diffPre.get(address)).get("storage"));
      final Map<String, Object> slotsPost = object(post.get("storage"));
      final Set<String> slots = new TreeSet<>();
      slots.addAll(slotsBefore.keySet());
      slots.addAll(slotsPre.keySet());
      slots.addAll(slotsPost.keySet());

      final boolean contract =
          !EMPTY_CODE.equals(codeBefore)
              || !EMPTY_CODE.equals(codeAfter)
              || !slots.isEmpty()
              || created.contains(address.toLowerCase(Locale.ROOT));
      if (!contract && "0".equals(delta)) {
        continue; // an account that neither holds code/storage nor changed balance is not bound
      }

      String nonceBefore = "0";
      String nonceAfter = "0";
      if (contract) {
        nonceBefore = number(before.get("nonce")).toString();
        nonceAfter = nonceBefore;
        if (post.containsKey("nonce")) {
          nonceAfter = number(post.get("nonce")).toString();
        }
        if (deleted) {
          nonceAfter = "0";
        }
      }

      final List<Object> storage = new ArrayList<>(slots.size());
      for (final String key : slots) {
        final String slot = word(key);
        final String valueBefore = word(slotsBefore.get(key));
        String valueAfter = valueBefore;
        if (deleted || slotsPre.containsKey(key) || slotsPost.containsKey(key)) {
          valueAfter = word(slotsPost.get(key));
        }
        final Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("slot", slot);
        entry.put("before", valueBefore);
        entry.put("after", valueAfter);
        storage.add(entry);
      }

      final Map<String, Object> account = new LinkedHashMap<>();
      account.put("address", address.toLowerCase(Locale.ROOT));
      account.put("codeBefore", keccak(codeBefore));
      account.put("codeAfter", keccak(codeAfter));
      account.put("nonceBefore", nonceBefore);
      account.put("nonceAfter", nonceAfter);
      account.put("balanceDelta", delta);
      account.put("storage", storage);
      accounts.add(account);
    }

    final Map<String, Object> document = new LinkedHashMap<>();
    document.put("calls", tree);
    document.put("accounts", accounts);
    final byte[] json = CanonicalJson.encode(document).getBytes(StandardCharsets.UTF_8);
    if (json.length > MAX_BYTES) {
      throw new UnsupportedExecutionException("fingerprint exceeds 1 MiB");
    }
    return Hash.hash(Bytes.concatenate(Bytes.wrap(DOMAIN), Bytes.wrap(json)));
  }

  /** Mirror of Go's normalizeCall: fixed field set, resolved storage context, recorded creations. */
  private static Map<String, Object> normalizeCall(
      final Map<String, Object> call,
      final String parentStorage,
      final Set<String> created,
      final int[] count)
      throws UnsupportedExecutionException {
    if (++count[0] > CallsFingerprint.MAX_CALLS) {
      throw new UnsupportedExecutionException("more than " + CallsFingerprint.MAX_CALLS + " calls");
    }
    final String type = string(call.get("type"), "");
    if (!CALL_TYPES.contains(type)) {
      throw new UnsupportedExecutionException("unsupported call " + type);
    }
    final String value = word(call.get("value"));
    String to = string(call.get("to"), "").toLowerCase(Locale.ROOT);
    String from = string(call.get("from"), "").toLowerCase(Locale.ROOT);
    final boolean failed = call.get("error") != null;
    // Cancun self-to-self SELFDESTRUCT on an existing account has no journal entry: zero caller,
    // no destination or value, no error. It denotes a no-op on the parent.
    if ("SELFDESTRUCT".equals(type)
        && to.isEmpty()
        && from.equals("0x" + "0".repeat(40))
        && value.equals(word(null))
        && !failed
        && parentStorage != null) {
      from = parentStorage;
      to = parentStorage;
    }
    final boolean failedCreate =
        ("CREATE".equals(type) || "CREATE2".equals(type)) && failed && to.isEmpty();
    if ((!isAddress(to) && !failedCreate) || !isAddress(from)) {
      throw new UnsupportedExecutionException("invalid call address");
    }
    String storage = to;
    if ("SELFDESTRUCT".equals(type)) {
      storage = from;
    }
    if ("DELEGATECALL".equals(type) || "CALLCODE".equals(type)) {
      if (parentStorage == null) {
        throw new UnsupportedExecutionException("root delegate");
      }
      storage = parentStorage;
    }
    if ("CREATE".equals(type) || "CREATE2".equals(type)) {
      created.add(to);
    }

    final List<Object> children = new ArrayList<>();
    for (final Object child : list(call.get("calls"))) {
      children.add(normalizeCall(object(child), storage, created, count));
    }
    final Map<String, Object> out = new LinkedHashMap<>();
    out.put("type", type);
    out.put("from", from);
    out.put("to", to);
    out.put("storageAddress", storage);
    out.put("input", string(call.get("input"), "0x").toLowerCase(Locale.ROOT));
    out.put("output", string(call.get("output"), "0x").toLowerCase(Locale.ROOT));
    out.put("failed", failed);
    out.put("value", value);
    out.put("calls", children);
    out.put("logs", list(call.get("logs")));
    return out;
  }

  private static String keccak(final String code) throws UnsupportedExecutionException {
    return Hash.hash(bytes(code)).getBytes().toHexString();
  }

  private static Bytes bytes(final String hex) throws UnsupportedExecutionException {
    try {
      return Bytes.fromHexStringLenient(hex);
    } catch (final RuntimeException e) {
      throw new UnsupportedExecutionException("invalid hex value");
    }
  }

  /** Go's word(): a 32-byte lowercase hex word, left-padded. */
  private static String word(final Object value) throws UnsupportedExecutionException {
    if (value != null && !(value instanceof String)) {
      throw new UnsupportedExecutionException("word must be a string");
    }
    String s = value == null ? "" : (String) value;
    if (s.startsWith("0x") || s.startsWith("0X")) {
      s = s.substring(2);
    }
    if (s.length() > 64) {
      throw new UnsupportedExecutionException("oversize word");
    }
    for (int i = 0; i < s.length(); i++) {
      if (Character.digit(s.charAt(i), 16) < 0) {
        throw new UnsupportedExecutionException("invalid word");
      }
    }
    return "0x" + "0".repeat(64 - s.length()) + s.toLowerCase(Locale.ROOT);
  }

  /** Go's number(): decimal or 0x-prefixed unsigned integer, at most 256 bits. */
  private static BigInteger number(final Object value) throws UnsupportedExecutionException {
    if (value == null) {
      return BigInteger.ZERO;
    }
    if (!(value instanceof String)) {
      throw new UnsupportedExecutionException("integer must be a string");
    }
    String s = (String) value;
    int base = 10;
    if (s.startsWith("0x") || s.startsWith("0X")) {
      s = s.substring(2);
      base = 16;
    }
    final BigInteger n;
    try {
      n = new BigInteger(s, base);
    } catch (final NumberFormatException e) {
      throw new UnsupportedExecutionException("invalid uint256");
    }
    if (n.signum() < 0 || n.bitLength() > 256) {
      throw new UnsupportedExecutionException("invalid uint256");
    }
    return n;
  }

  private static boolean isAddress(final String s) {
    if (s == null) {
      return false;
    }
    final String hex = s.startsWith("0x") || s.startsWith("0X") ? s.substring(2) : s;
    if (hex.length() != 40) {
      return false;
    }
    for (int i = 0; i < hex.length(); i++) {
      if (Character.digit(hex.charAt(i), 16) < 0) {
        return false;
      }
    }
    return true;
  }

  private static String string(final Object value, final String fallback) {
    return value instanceof String s ? s : fallback;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> object(final Object value) {
    return value instanceof Map ? (Map<String, Object>) value : Map.of();
  }

  @SuppressWarnings("unchecked")
  private static List<Object> list(final Object value) {
    return value instanceof List ? (List<Object>) value : List.of();
  }
}
