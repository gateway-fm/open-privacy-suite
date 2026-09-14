package ops.approvals;

import java.util.function.LongSupplier;
import org.hyperledger.besu.plugin.data.ProcessableBlockHeader;
import org.hyperledger.besu.plugin.services.txselection.PluginTransactionSelector;
import org.hyperledger.besu.plugin.services.txselection.PluginTransactionSelectorFactory;
import org.hyperledger.besu.plugin.services.txselection.SelectorsStateManager;

/** One selector + tracer per pending block; the approval store is shared. */
final class ApprovalSelectorFactory implements PluginTransactionSelectorFactory {
  private final ApprovalStore store;
  private final long chainId;
  private final long waitMs;
  private final LongSupplier clock;
  private final ApprovalSelector.Metrics metrics;

  ApprovalSelectorFactory(
      final ApprovalStore store,
      final long chainId,
      final long waitMs,
      final LongSupplier clock,
      final ApprovalSelector.Metrics metrics) {
    this.store = store;
    this.chainId = chainId;
    this.waitMs = waitMs;
    this.clock = clock;
    this.metrics = metrics;
  }

  @Override
  public PluginTransactionSelector create(
      final ProcessableBlockHeader pendingBlockHeader, final SelectorsStateManager stateManager) {
    return new ApprovalSelector(store, chainId, waitMs, clock, new ApprovalTracer(), metrics);
  }
}
