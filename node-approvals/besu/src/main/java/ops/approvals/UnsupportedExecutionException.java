package ops.approvals;

/** Execution facts the calls-V3 fingerprint cannot express (lifecycle ops, limits). Fail closed. */
public final class UnsupportedExecutionException extends Exception {
  private static final long serialVersionUID = 1L;

  public UnsupportedExecutionException(final String message) {
    super(message);
  }
}
