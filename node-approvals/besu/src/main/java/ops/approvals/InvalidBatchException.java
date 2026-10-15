package ops.approvals;

/** A delivered frame that is not a well-formed approval batch. Never unblocks a transaction. */
public final class InvalidBatchException extends Exception {
  private static final long serialVersionUID = 1L;

  public InvalidBatchException(final String message) {
    super(message);
  }
}
