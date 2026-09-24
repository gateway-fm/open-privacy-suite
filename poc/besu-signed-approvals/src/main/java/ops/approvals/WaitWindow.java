package ops.approvals;

import java.util.concurrent.atomic.AtomicLong;

/**
 * How long a pooled transaction waits for its approval before the producer drops it (wire
 * contract §4). Normally {@code wait-ms} from pool admission. After a restart the store is empty
 * and the RPC nodes re-announce their pooled transactions, possibly before OPS has reconnected and
 * resent: until OPS's first {@code Status} call after boot, and for at most 60 s after boot, the
 * window counts from that call instead, so a re-announced transaction is not dropped for an
 * approval that is still on its way.
 */
final class WaitWindow {
  /** How long after boot the window may still start later than pool admission. */
  static final long RESTART_EXTENSION_MS = 60_000;
  private static final long NO_STATUS_YET = Long.MAX_VALUE;

  private final long waitMs;
  private final long bootAt;
  private final AtomicLong firstStatusAt = new AtomicLong(NO_STATUS_YET);

  WaitWindow(final long waitMs, final long bootAt) {
    this.waitMs = waitMs;
    this.bootAt = bootAt;
  }

  long waitMs() {
    return waitMs;
  }

  /** OPS asked who this receiver is: only the first call after boot moves the window. */
  void statusCalled(final long now) {
    firstStatusAt.compareAndSet(NO_STATUS_YET, now);
  }

  /** When the wait of a transaction admitted at {@code addedAt} starts counting. */
  long startOf(final long addedAt) {
    final long resumed = Math.min(firstStatusAt.get(), bootAt + RESTART_EXTENSION_MS);
    return Math.max(addedAt, resumed);
  }

  boolean timedOut(final long addedAt, final long now) {
    return now - startOf(addedAt) >= waitMs;
  }
}
