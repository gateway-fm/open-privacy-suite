package ops.approvals;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * The exact bytes Go's {@code encoding/json} writes for the strict fingerprint's document, with
 * {@code SetEscapeHTML(false)}: object keys sorted, no whitespace, no trailing newline. Only the
 * shapes the fingerprint uses are accepted — string, boolean, list, map — so a value that Go would
 * render differently (a number, a null) is a programming error rather than a silent mismatch.
 */
final class CanonicalJson {
  private CanonicalJson() {}

  static String encode(final Object value) {
    final StringBuilder out = new StringBuilder(256);
    write(value, out);
    return out.toString();
  }

  private static void write(final Object value, final StringBuilder out) {
    switch (value) {
      case String s -> writeString(s, out);
      case Boolean b -> out.append(b.booleanValue() ? "true" : "false");
      case Map<?, ?> map -> writeObject(map, out);
      case List<?> list -> writeArray(list, out);
      case null -> throw new IllegalArgumentException("null is not part of the canonical document");
      default ->
          throw new IllegalArgumentException(
              "unsupported canonical JSON value: " + value.getClass().getName());
    }
  }

  private static void writeObject(final Map<?, ?> map, final StringBuilder out) {
    final List<String> keys = new ArrayList<>(map.size());
    for (final Object key : map.keySet()) {
      if (!(key instanceof String s)) {
        throw new IllegalArgumentException("object keys must be strings");
      }
      keys.add(s);
    }
    Collections.sort(keys); // Go sorts map keys; for our ASCII keys this is the same order
    out.append('{');
    for (int i = 0; i < keys.size(); i++) {
      if (i > 0) {
        out.append(',');
      }
      writeString(keys.get(i), out);
      out.append(':');
      write(map.get(keys.get(i)), out);
    }
    out.append('}');
  }

  private static void writeArray(final List<?> list, final StringBuilder out) {
    out.append('[');
    for (int i = 0; i < list.size(); i++) {
      if (i > 0) {
        out.append(',');
      }
      write(list.get(i), out);
    }
    out.append(']');
  }

  private static void writeString(final String s, final StringBuilder out) {
    out.append('"');
    for (int i = 0; i < s.length(); i++) {
      final char c = s.charAt(i);
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
        }
      }
    }
    out.append('"');
  }
}
