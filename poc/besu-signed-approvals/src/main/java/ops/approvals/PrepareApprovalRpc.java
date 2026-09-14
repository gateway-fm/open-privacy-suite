package ops.approvals;

import java.math.BigInteger;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.datatypes.Hash;
import org.hyperledger.besu.datatypes.StateOverride;
import org.hyperledger.besu.datatypes.StateOverrideMap;
import org.hyperledger.besu.datatypes.TransactionType;
import org.hyperledger.besu.datatypes.parameters.UnsignedLongParameter;
import org.hyperledger.besu.ethereum.core.Transaction;
import org.hyperledger.besu.ethereum.core.encoding.EncodingContext;
import org.hyperledger.besu.ethereum.core.encoding.TransactionDecoder;
import org.hyperledger.besu.plugin.data.ProcessableBlockHeader;
import org.hyperledger.besu.plugin.data.TransactionSimulationResult;
import org.hyperledger.besu.plugin.services.BlockchainService;
import org.hyperledger.besu.plugin.services.TransactionSimulationService;
import org.hyperledger.besu.plugin.services.exception.PluginRpcEndpointException;
import org.hyperledger.besu.plugin.services.rpc.PluginRpcRequest;
import org.hyperledger.besu.plugin.services.rpc.RpcMethodError;

/**
 * {@code ops_prepareApproval(rawTx[, blockHash])}: simulates the exact signed transaction on the
 * state of one block with the same tracer the producer uses, and returns the calls-V3 fingerprint
 * plus the geth-shaped call tree OPS recomputes and validates against. Preflight and enforcement
 * therefore share one implementation. Errors are short reason strings; lifecycle transactions are
 * refused.
 */
final class PrepareApprovalRpc {
  static final String NAMESPACE = "ops";
  static final String METHOD = "prepareApproval";

  private final TransactionSimulationService simulation;
  private final BlockchainService blockchain;
  private final long chainId;

  PrepareApprovalRpc(
      final TransactionSimulationService simulation, final BlockchainService blockchain, final long chainId) {
    this.simulation = simulation;
    this.blockchain = blockchain;
    this.chainId = chainId;
  }

  Map<String, Object> prepare(final PluginRpcRequest request) {
    final Object[] params = request.getParams();
    if (params == null || params.length != 1 || !(params[0] instanceof String raw)) {
      throw error(RpcMethodError.INVALID_PARAMS_ERROR_CODE, "expected [rawTransaction]");
    }
    final Transaction tx;
    try {
      tx = TransactionDecoder.decodeOpaqueBytes(Bytes.fromHexString(raw), EncodingContext.POOLED_TRANSACTION);
    } catch (final RuntimeException e) {
      throw error(RpcMethodError.INVALID_PARAMS_ERROR_CODE, "undecodable transaction");
    }
    if (tx.getType() != TransactionType.FRONTIER && tx.getType() != TransactionType.EIP1559) {
      throw error(-32000, "unsupported transaction type");
    }
    if (tx.getChainId().map(c -> !c.equals(BigInteger.valueOf(chainId))).orElse(true)) {
      throw error(-32000, "wrong chain");
    }
    final org.hyperledger.besu.datatypes.Address sender;
    try {
      sender = tx.getSender();
    } catch (final RuntimeException e) {
      throw error(RpcMethodError.INVALID_PARAMS_ERROR_CODE, "unrecoverable signature");
    }
    // Simulate in the context the producer will use: the block being built on the current head,
    // on the head state. The signed nonce is pinned so the execution is the one the bytes describe.
    final ProcessableBlockHeader pending = simulation.simulatePendingBlockHeader();
    final StateOverrideMap overrides = new StateOverrideMap();
    overrides.put(
        sender, StateOverride.builder().withNonce(new UnsignedLongParameter(tx.getNonce())).build());
    final ApprovalTracer tracer = new ApprovalTracer();
    final Optional<TransactionSimulationResult> simulated =
        simulation.simulate(
            tx,
            Optional.of(overrides),
            pending,
            tracer,
            EnumSet.noneOf(TransactionSimulationService.SimulationParameters.class));
    if (simulated.isEmpty()) {
      throw error(-32000, "head state not available for simulation");
    }
    final TransactionSimulationResult result = simulated.get();
    if (result.isInvalid()) {
      throw error(-32000, "transaction invalid: " + result.getInvalidReason().orElse("?"));
    }
    final ApprovalTracer.Observation seen = tracer.observation();
    if (seen.error().isPresent()) {
      throw error(-32000, "unsupported execution: " + seen.error().get());
    }
    // Contract creation and self-destruction cannot be expressed by the calls fingerprint, so those
    // executions are approved in strict mode, which binds the resulting state instead.
    if (!seen.complete()) {
      throw error(-32000, "execution not fully observed");
    }
    final int mode = ApprovalSelector.requiredMode(seen);
    final Map<String, Object> calls;
    final Map<String, Object> pre;
    final Map<String, Object> diff;
    final Hash fingerprint;
    try {
      calls = CallTreeJson.toTree(seen.records());
      pre = seen.state().pre();
      diff = seen.state().diff();
      fingerprint =
          mode == Approval.HASH_STRICT
              ? StrictFingerprint.of(calls, pre, diff)
              : CallsFingerprint.of(seen.records());
    } catch (final UnsupportedExecutionException | RuntimeException e) {
      throw error(-32000, "unsupported execution: " + e.getMessage());
    }
    final Map<String, Object> out = new LinkedHashMap<>();
    out.put("hashMode", mode);
    out.put("chainId", "0x" + Long.toHexString(chainId));
    out.put("txHash", tx.getHash().getBytes().toHexString());
    out.put("parentBlockHash", blockchain.getChainHeadHash().getBytes().toHexString());
    out.put("pendingBlockNumber", "0x" + Long.toHexString(pending.getNumber()));
    out.put("fingerprint", fingerprint.getBytes().toHexString());
    out.put("calls", calls);
    out.put("codeHashes", CallTreeJson.codeHashes(seen.records()));
    out.put("pre", pre);
    out.put("diff", diff);
    out.put("status", result.isSuccessful() ? "success" : "failed");
    out.put("gasUsed", "0x" + Long.toHexString(result.getGasEstimate()));
    return out;
  }

  private static PluginRpcEndpointException error(final int code, final String message) {
    return new PluginRpcEndpointException(
        new RpcMethodError() {
          @Override
          public int getCode() {
            return code;
          }

          @Override
          public String getMessage() {
            return message;
          }
        });
  }
}
