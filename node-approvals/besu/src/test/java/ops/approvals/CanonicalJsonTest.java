package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Must match Go's encoding/json with SetEscapeHTML(false): sorted keys, compact, no newline. */
class CanonicalJsonTest {
  @Test
  void sortsObjectKeysAndKeepsArrayOrder() {
    final Map<String, Object> m = new LinkedHashMap<>();
    m.put("calls", List.of("second", "first"));
    m.put("accounts", Map.of("b", "2", "a", "1"));
    assertEquals(
        "{\"accounts\":{\"a\":\"1\",\"b\":\"2\"},\"calls\":[\"second\",\"first\"]}",
        CanonicalJson.encode(m));
  }

  @Test
  void doesNotEscapeHtmlAndEscapesJsonSpecials() {
    assertEquals("{\"k\":\"<&>\"}", CanonicalJson.encode(Map.of("k", "<&>")));
    assertEquals("{\"k\":\"a\\\"b\\\\c\"}", CanonicalJson.encode(Map.of("k", "a\"b\\c")));
    assertEquals("{\"k\":\"line\\nfeed\"}", CanonicalJson.encode(Map.of("k", "line\nfeed")));
  }

  @Test
  void encodesBooleansAndNestedStructures() {
    assertEquals(
        "{\"failed\":true,\"logs\":[],\"sub\":{\"x\":false}}",
        CanonicalJson.encode(Map.of("failed", true, "logs", List.of(), "sub", Map.of("x", false))));
  }

  @Test
  void refusesValuesGoWouldEncodeDifferently() {
    assertThrows(IllegalArgumentException.class, () -> CanonicalJson.encode(Map.of("n", 1)));
    assertThrows(IllegalArgumentException.class, () -> CanonicalJson.encode(Map.of("d", 1.5)));
  }
}
