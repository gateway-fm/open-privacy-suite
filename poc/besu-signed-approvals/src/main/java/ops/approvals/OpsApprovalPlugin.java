package ops.approvals;

import com.google.auto.service.AutoService;
import io.grpc.Status;
import java.util.ArrayList;
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
 * gRPC approval delivery service, {@code ops_prepareApproval}, and cleanup. Any start-up problem
 * halts Besu: a producer without this plugin would include unapproved transactions.
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

  /** Expired approvals and the blocks that held them are dropped this often. */
  static final long EXPIRY_SWEEP_MS = 1_000;
  /** The pooled set is checked against the pool this often, in case an event was missed. */
  static final long POOL_RECONCILE_MS = 60_000;

  private final PluginOptions options = new PluginOptions();
  private final AtomicReference<PrepareApprovalRpc> prepare = new AtomicReference<>();
  private InclusionTracker inclusions;
  private ServiceManager services;
  private BlockchainService blockchain;
  private ApprovalStore store;
  private ApprovalServer server;
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
    options.validate();
    final long chainId = options.chainId;
    blockchain = require(BlockchainService.class);
    blockchain
        .getChainId()
        .filter(id -> id.longValueExact() == chainId)
        .orElseThrow(() -> new IllegalArgumentException("--plugin-ops-approval-chain-id does not match the node's chain id"));
    final ApprovalVerifier verifier = new ApprovalVerifier(options.trustedKeys());
    final TransactionPoolService pool = require(TransactionPoolService.class);
    // The boot id and the wait window's restart extension both count from here: the store is
    // empty until OPS has called Status and resent what it retains.
    final WaitWindow window = new WaitWindow(options.waitMs, System.currentTimeMillis());
    // The grace period is the wait window: an approval younger than that may be for a transaction
    // still on its way, so a new approval never evicts it.
    store = new ApprovalStore(options.capacity, options.waitMs, System::currentTimeMillis);
    // No approval can outlive the longest TTL accepted plus how far ahead it may be issued.
    inclusions = new InclusionTracker(options.maxTtlMs + ApprovalIngress.MAX_ISSUED_AHEAD_MS);

    final MetricsSystem metrics = require(MetricsSystem.class);
    final LabelledMetric<Counter> decisions =
        metrics.createLabelledCounter(CATEGORY, "decisions_total", "producer decisions: allow, wait, drop, deny", "decision", "reason");
    final LabelledMetric<Counter> batches =
        metrics.createLabelledCounter(CATEGORY, "batches_total", "delivered approval batches by gRPC status", "status");
    final Counter stored = metrics.createCounter(CATEGORY, "approvals_stored_total", "approvals of accepted batches");
    final LabelledMetric<Counter> refused =
        metrics.createLabelledCounter(CATEGORY, "connections_refused_total", "delivery connections refused at accept", "reason");
    metrics.createIntegerGauge(CATEGORY, "store_size", "approvals in memory", store::size);

    require(TransactionSelectionService.class)
        .registerPluginTransactionSelectorFactory(
            new ApprovalSelectorFactory(
                store,
                chainId,
                window,
                System::currentTimeMillis,
                new ApprovalSelector.Metrics() {
                  @Override
                  public void decision(final String decision, final String reason) {
                    decisions.labels(decision, reason).inc();
                  }
                }));

    prepare.set(new PrepareApprovalRpc(require(TransactionSimulationService.class), blockchain, chainId));

    final BesuEvents events = require(BesuEvents.class);
    events.addBlockAddedListener(this::onBlockAdded);
    events.addTransactionAddedListener(tx -> store.pooled(tx.getHash()));
    events.addTransactionDroppedListener((tx, reason) -> store.unpooled(tx.getHash()));

    sweeper = Executors.newSingleThreadScheduledExecutor(r -> Thread.ofPlatform().name("ops-approval-sweeper").daemon(true).unstarted(r));
    sweeper.scheduleWithFixedDelay(this::sweepExpired, EXPIRY_SWEEP_MS, EXPIRY_SWEEP_MS, TimeUnit.MILLISECONDS);
    sweeper.scheduleWithFixedDelay(() -> reconcile(pool), POOL_RECONCILE_MS, POOL_RECONCILE_MS, TimeUnit.MILLISECONDS);

    final ApprovalIngress ingress =
        new ApprovalIngress(
            verifier,
            chainId,
            options.maxTtlMs,
            store,
            window,
            System::currentTimeMillis,
            new ApprovalIngress.Metrics() {
              @Override
              public void batch(final Status.Code code) {
                batches.labels(code.name()).inc();
              }

              @Override
              public void stored(final int approvals) {
                stored.inc(approvals);
              }
            });
    server =
        new ApprovalServer(
            options.listenAddress(),
            ingress,
            new ApprovalServer.Limits(
                options.allowedSources(), options.maxConnections, options.maxConcurrentCalls, ApprovalServer.PERMIT_KEEPALIVE_MS),
            new ApprovalServer.Metrics() {
              @Override
              public void refused(final String reason) {
                refused.labels(reason).inc();
              }
            });
    server.start();
    metrics.createIntegerGauge(CATEGORY, "connections", "open approval delivery connections", server::connections);
    LOG.info(
        "OPS approval gate active: listen={} port={} boot_id={} chain={} trusted_keys={} wait_ms={} capacity={} max_ttl_ms={} allowed_sources={} max_connections={}",
        options.listen,
        server.port(),
        ingress.bootId(),
        chainId,
        verifier.keyIds(),
        options.waitMs,
        options.capacity,
        options.maxTtlMs,
        options.allowedSources(),
        options.maxConnections);
  }

  private void onBlockAdded(final AddedBlockContext block) {
    // Inclusion is not the end of an approval's life: a reorganisation returns the block's
    // transactions to the pool, and they must still find their approvals there. Track the block
    // and release along the finalized chain instead — but only while its approvals live: the store
    // evicts them at expiry whatever the finality, so a block is tracked until its last approval
    // expires (finality can lag the head by hours; expiry is what bounds the tracking).
    // FORK blocks are recorded too: a reorganisation onto that fork later needs their parents.
    if (block.getEventType() == AddedBlockContext.EventType.STORED_ONLY) {
      return;
    }
    final BlockHeader header = block.getBlockHeader();
    final List<Hash> included =
        block.getBlockBody().getTransactions().stream().map(org.hyperledger.besu.datatypes.Transaction::getHash).toList();
    // Every block is recorded, empty or not: finality often lands on one that holds nothing of
    // ours, and the walk from it must still reach the blocks that do.
    final List<Hash> approved = new ArrayList<>();
    long approvalsExpireAt = Long.MIN_VALUE;
    for (final Hash tx : included) {
      final Optional<ApprovalStore.Stored> stored = store.get(tx);
      if (stored.isPresent()) {
        approved.add(tx);
        approvalsExpireAt = Math.max(approvalsExpireAt, stored.get().expiresAt());
      }
    }
    inclusions.recordIncluded(
        header.getBlockHash(), header.getParentHash(), header.getNumber(), approved, approvalsExpireAt, System.currentTimeMillis());
    // A canonical block's transactions left the pool: their approvals stay (until finality or
    // expiry) but become the first evictable after expired ones. A fork block's transactions are
    // still pooled and keep theirs live.
    if (block.getEventType() != AddedBlockContext.EventType.FORK) {
      included.forEach(store::included);
    }
    releaseFinalized();
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

  private void sweepExpired() {
    try {
      store.evictExpired();
      inclusions.forgetExpired(System.currentTimeMillis());
    } catch (final RuntimeException e) {
      LOG.warn("OPS approval expiry sweep failed", e);
    }
  }

  private void reconcile(final TransactionPoolService pool) {
    try {
      final long takenAt = System.currentTimeMillis();
      final Set<Hash> pending = new HashSet<>();
      for (final PendingTransaction p : pool.getPendingTransactions()) {
        pending.add(p.getTransaction().getHash());
      }
      store.reconcile(pending, takenAt);
    } catch (final RuntimeException e) {
      LOG.warn("OPS approval pool reconciliation failed", e);
    }
  }

  @Override
  public void stop() {
    if (server != null) {
      server.close();
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
