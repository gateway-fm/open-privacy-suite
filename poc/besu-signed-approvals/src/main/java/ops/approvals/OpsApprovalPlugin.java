package ops.approvals;

import com.google.auto.service.AutoService;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.PendingTransaction;
import org.hyperledger.besu.plugin.BesuPlugin;
import org.hyperledger.besu.plugin.ServiceManager;
import org.hyperledger.besu.plugin.data.AddedBlockContext;
import org.hyperledger.besu.plugin.data.BlockHeader;
import org.hyperledger.besu.plugin.services.BesuEvents;
import org.hyperledger.besu.plugin.services.BesuService;
import org.hyperledger.besu.plugin.services.BlockchainService;
import org.hyperledger.besu.plugin.services.MetricsSystem;
import org.hyperledger.besu.plugin.services.PicoCLIOptions;
import org.hyperledger.besu.plugin.services.RpcEndpointService;
import org.hyperledger.besu.plugin.services.TransactionSelectionService;
import org.hyperledger.besu.plugin.services.TransactionSimulationService;
import org.hyperledger.besu.plugin.services.metrics.Counter;
import org.hyperledger.besu.plugin.services.metrics.LabelledMetric;
import org.hyperledger.besu.plugin.services.metrics.MetricCategory;
import org.hyperledger.besu.plugin.services.metrics.MetricCategoryRegistry;
import org.hyperledger.besu.plugin.services.transactionpool.TransactionPoolService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OPS signed approvals for the block producer. Registers the transaction selector (gate), the
 * approval ingress, {@code ops_prepareApproval}, and cleanup. Any start-up problem halts Besu: a
 * producer without this plugin would include unapproved transactions.
 */
@AutoService(BesuPlugin.class)
public class OpsApprovalPlugin implements BesuPlugin {
  private static final Logger LOG = LoggerFactory.getLogger(OpsApprovalPlugin.class);
  private static final MetricCategory CATEGORY =
      new MetricCategory() {
        @Override
        public String getName() {
          return "ops_approval";
        }

        @Override
        public Optional<String> getApplicationPrefix() {
          return Optional.empty();
        }
      };

  /**
   * Blocks whose approvals are still needed are tracked from inclusion until finality. Below this
   * depth behind the head they stop being tracked and their approvals fall to the orphan sweep:
   * about 68 minutes at one-second blocks, chosen as several times any finality lag a healthy
   * consensus client should show; if the target network's finality lags more, raise it and size
   * the store's capacity to rate × retention.
   */
  static final long TRACKED_BLOCK_DEPTH = 4_096;

  private final PluginOptions options = new PluginOptions();
  private final AtomicReference<PrepareApprovalRpc> prepare = new AtomicReference<>();
  private final InclusionTracker inclusions = new InclusionTracker();
  private ServiceManager services;
  private BlockchainService blockchain;
  private ApprovalStore store;
  private ApprovalListener listener;
  private ScheduledExecutorService sweeper;

  @Override
  public String getName() {
    return "OpsApprovalPlugin";
  }

  @Override
  public void register(final ServiceManager serviceManager) {
    this.services = serviceManager;
    require(PicoCLIOptions.class).addPicoCLIOptions("ops-approval", options);
    require(MetricCategoryRegistry.class).addMetricCategory(CATEGORY);
    // Namespaces are validated against --rpc-http-api before start(): register now, resolve later.
    require(RpcEndpointService.class)
        .registerRPCEndpoint(
            PrepareApprovalRpc.NAMESPACE,
            PrepareApprovalRpc.METHOD,
            request -> {
              final PrepareApprovalRpc rpc = prepare.get();
              if (rpc == null) {
                throw new IllegalStateException("OPS approval plugin not started");
              }
              return rpc.prepare(request);
            });
  }

  @Override
  public void start() {
    try {
      doStart();
    } catch (final Exception e) {
      // Besu's default --plugin-continue-on-error=false turns a start() exception into a halt.
      LOG.error("Halting Besu: OPS approval plugin failed to start: {}", e.getMessage(), e);
      throw new IllegalStateException("OPS approval plugin failed to start", e);
    }
  }

  private void doStart() throws Exception {
    if (options.listen == null || options.chainId == null || options.trustedKeys().isEmpty()) {
      throw new IllegalArgumentException(
          "--plugin-ops-approval-listen, --plugin-ops-approval-chain-id and at least one trusted key (--plugin-ops-approval-public-key or --plugin-ops-approval-public-keys) are required");
    }
    if (options.waitMs < 0 || options.capacity < 1 || options.maxConnections < 1 || options.orphanTtlMs < 1) {
      throw new IllegalArgumentException("wait-ms >= 0, capacity/max-connections/orphan-ttl-ms >= 1 required");
    }
    final long chainId = options.chainId;
    blockchain = require(BlockchainService.class);
    blockchain
        .getChainId()
        .filter(id -> id.longValueExact() == chainId)
        .orElseThrow(() -> new IllegalArgumentException("--plugin-ops-approval-chain-id does not match the node's chain id"));
    final ApprovalVerifier verifier = new ApprovalVerifier(options.trustedKeys());
    final TransactionPoolService pool = require(TransactionPoolService.class);
    // When full, drop the oldest approval whose transaction is not live in the pool and is old
    // enough that its transaction is not merely still on its way; refuse only if nothing can go.
    // Liveness comes from the pool's own events, so overflow never scans the pool. Flooding OPS
    // with preflights is rate-limited at OPS.
    store = new ApprovalStore(options.capacity, options.orphanTtlMs, options.waitMs, System::currentTimeMillis);

    final MetricsSystem metrics = require(MetricsSystem.class);
    final LabelledMetric<Counter> decisions =
        metrics.createLabelledCounter(CATEGORY, "decisions_total", "producer decisions by outcome", "outcome");
    final LabelledMetric<Counter> ingress =
        metrics.createLabelledCounter(CATEGORY, "ingress_total", "approval ingress by outcome", "outcome");
    metrics.createLabelledSuppliedGauge(CATEGORY, "approvals_held", "approvals in memory").labels(() -> (double) store.size());

    require(TransactionSelectionService.class)
        .registerPluginTransactionSelectorFactory(
            new ApprovalSelectorFactory(
                store,
                chainId,
                options.waitMs,
                System::currentTimeMillis,
                new ApprovalSelector.Metrics() {
                  @Override
                  public void pending() {
                    decisions.labels("pending").inc();
                  }

                  @Override
                  public void timeout() {
                    decisions.labels("timeout").inc();
                  }

                  @Override
                  public void mismatch(final String reason) {
                    decisions.labels(reason).inc();
                  }

                  @Override
                  public void matched() {
                    decisions.labels("matched").inc();
                  }
                }));

    prepare.set(new PrepareApprovalRpc(require(TransactionSimulationService.class), blockchain, chainId));

    final BesuEvents events = require(BesuEvents.class);
    events.addBlockAddedListener(this::onBlockAdded);
    events.addTransactionAddedListener(tx -> store.pooled(tx.getHash()));
    events.addTransactionDroppedListener((tx, reason) -> store.unpooled(tx.getHash()));

    sweeper = Executors.newSingleThreadScheduledExecutor(r -> Thread.ofPlatform().name("ops-approval-sweeper").daemon(true).unstarted(r));
    sweeper.scheduleAtFixedRate(() -> sweep(pool), options.orphanTtlMs, options.orphanTtlMs, TimeUnit.MILLISECONDS);

    final int colon = options.listen.lastIndexOf(':');
    if (colon <= 0) {
      throw new IllegalArgumentException("--plugin-ops-approval-listen must be host:port");
    }
    listener =
        new ApprovalListener(
            new InetSocketAddress(options.listen.substring(0, colon), Integer.parseInt(options.listen.substring(colon + 1))),
            options.maxConnections,
            verifier,
            chainId,
            store,
            new ApprovalListener.Metrics() {
              @Override
              public void accepted(final int approvals) {
                ingress.labels("accepted").inc(approvals);
              }

              @Override
              public void rejected(final String reason) {
                ingress.labels(reason).inc();
              }
            });
    listener.start();
    LOG.info(
        "OPS approval gate active: listen={} chain={} trusted_keys={} wait_ms={} capacity={}",
        options.listen,
        chainId,
        options.trustedKeys().keySet(),
        options.waitMs,
        options.capacity);
  }

  private void onBlockAdded(final AddedBlockContext block) {
    // Inclusion is not the end of an approval's life: a reorganisation returns the block's
    // transactions to the pool, and they must still find their approvals there. Track the block
    // and release along the finalized chain instead.
    // FORK blocks are recorded too: a reorganisation onto that fork later needs their parents.
    if (block.getEventType() == AddedBlockContext.EventType.STORED_ONLY) {
      return;
    }
    final BlockHeader header = block.getBlockHeader();
    final List<Hash> included =
        block.getBlockBody().getTransactions().stream().map(org.hyperledger.besu.datatypes.Transaction::getHash).toList();
    inclusions.recordIncluded(header.getBlockHash(), header.getParentHash(), header.getNumber(), included);
    // Included transactions left the pool; their approvals stay (until finality) but are no
    // longer live, so they are the first to go if the store overflows.
    included.forEach(store::unpooled);
    releaseFinalized();
    // Blocks far below the head are no longer reorg candidates in practice; stop tracking them
    // and let the orphan sweep reclaim their approvals like any other unpooled approval.
    inclusions.forgetBelow(header.getNumber() - TRACKED_BLOCK_DEPTH);
  }

  private void releaseFinalized() {
    try {
      final Set<Hash> released = inclusions.finalizedUpTo(blockchain.getFinalizedBlock());
      if (!released.isEmpty()) {
        store.removeAll(released);
      }
    } catch (final RuntimeException e) {
      // Releasing is memory hygiene; failing to release never lets a transaction through.
      LOG.warn("OPS approval release on finality failed", e);
    }
  }

  private static Set<Hash> pendingHashes(final TransactionPoolService pool) {
    final Set<Hash> referenced = new HashSet<>();
    for (final PendingTransaction p : pool.getPendingTransactions()) {
      referenced.add(p.getTransaction().getHash());
    }
    return referenced;
  }

  private void sweep(final TransactionPoolService pool) {
    try {
      final int dropped = store.sweepOrphans(pendingHashes(pool));
      if (dropped > 0) {
        LOG.info("OPS approval sweep dropped {} orphaned approvals", dropped);
      }
    } catch (final RuntimeException e) {
      LOG.warn("OPS approval sweep failed", e);
    }
  }

  @Override
  public void stop() {
    if (listener != null) {
      listener.close();
    }
    if (sweeper != null) {
      sweeper.shutdownNow();
    }
  }

  private <T extends BesuService> T require(final Class<T> type) {
    return services
        .getService(type)
        .orElseThrow(() -> new IllegalStateException("Besu did not provide " + type.getSimpleName()));
  }
}
