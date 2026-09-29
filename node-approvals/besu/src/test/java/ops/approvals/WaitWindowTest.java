package ops.approvals;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Wire contract §4: after a restart the RPC nodes re-announce their pooled transactions, possibly
 * before OPS has reconnected and resent. The wait counts from the later of pool admission and the
 * first Status call after boot, and that extension lasts at most 60 s after boot.
 */
class WaitWindowTest {
  private static final long BOOT = 1_800_000_000_000L;
  private static final long WAIT = 5_000;

  @Test
  void beforeTheFirstStatusCallNothingTimesOutWithinAMinuteOfBoot() {
    final WaitWindow window = new WaitWindow(WAIT, BOOT);
    final long admitted = BOOT + 2_000;
    assertFalse(window.timedOut(admitted, admitted + WAIT), "OPS has not called Status yet");
    assertFalse(window.timedOut(admitted, BOOT + 60_000 + WAIT - 1));
    assertTrue(window.timedOut(admitted, BOOT + 60_000 + WAIT), "the extension ends 60 s after boot");
  }

  @Test
  void theFirstStatusCallRestartsTheWaitOfEverythingAdmittedBeforeIt() {
    final WaitWindow window = new WaitWindow(WAIT, BOOT);
    window.statusCalled(BOOT + 10_000);
    window.statusCalled(BOOT + 30_000); // only the first call after boot counts
    assertEquals(BOOT + 10_000, window.startOf(BOOT + 2_000));
    assertFalse(window.timedOut(BOOT + 2_000, BOOT + 10_000 + WAIT - 1));
    assertTrue(window.timedOut(BOOT + 2_000, BOOT + 10_000 + WAIT));
    // Admitted after the call: the ordinary window from admission.
    assertEquals(BOOT + 20_000, window.startOf(BOOT + 20_000));
    assertTrue(window.timedOut(BOOT + 20_000, BOOT + 20_000 + WAIT));
  }

  @Test
  void aLateFirstStatusCallExtendsTheWaitByAtMostAMinuteAfterBoot() {
    final WaitWindow window = new WaitWindow(WAIT, BOOT);
    window.statusCalled(BOOT + 90_000);
    assertEquals(BOOT + 60_000, window.startOf(BOOT + 2_000));
    assertTrue(window.timedOut(BOOT + 2_000, BOOT + 60_000 + WAIT));
  }

  @Test
  void longAfterBootTheWindowCountsFromAdmission() {
    final WaitWindow window = new WaitWindow(WAIT, BOOT);
    final long admitted = BOOT + 120_000; // never a Status call, but boot is long past
    assertEquals(admitted, window.startOf(admitted));
    assertTrue(window.timedOut(admitted, admitted + WAIT));
    assertFalse(window.timedOut(admitted, admitted + WAIT - 1));
    assertEquals(WAIT, window.waitMs());
  }
}
