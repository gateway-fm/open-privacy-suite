package ops.approvals;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Records → the geth callTracer shape OPS already consumes (type/from/to/input/value/error/calls). */
final class CallTreeJson {
  private CallTreeJson() {}

  static Map<String, Object> toTree(final List<CallRecord> records) {
    final List<Map<String, Object>> nodes = new ArrayList<>(records.size());
    Map<String, Object> root = null;
    for (final CallRecord r : records) {
      final Map<String, Object> node = new LinkedHashMap<>();
      node.put("type", CallRecord.typeName(r.kind()));
      node.put("from", r.from().getBytes().toHexString());
      node.put("to", r.to().getBytes().toHexString());
      node.put("input", r.input().toHexString());
      node.put("value", r.value().toShortHexString());
      if (r.failed()) {
        node.put("error", "execution failed");
      }
      node.put("calls", new ArrayList<Map<String, Object>>());
      nodes.add(node);
      if (r.parent() == CallRecord.ROOT_PARENT) {
        if (root != null) {
          throw new IllegalArgumentException("more than one root frame");
        }
        root = node;
      } else {
        @SuppressWarnings("unchecked")
        final List<Map<String, Object>> siblings =
            (List<Map<String, Object>>) nodes.get(r.parent()).get("calls");
        siblings.add(node);
      }
    }
    if (root == null) {
      throw new IllegalArgumentException("no root frame");
    }
    return root;
  }

  static Map<String, String> codeHashes(final List<CallRecord> records) {
    final Map<String, String> out = new LinkedHashMap<>();
    records.forEach(r -> out.put(r.to().getBytes().toHexString(), r.codeHash().getBytes().toHexString()));
    return out;
  }
}
