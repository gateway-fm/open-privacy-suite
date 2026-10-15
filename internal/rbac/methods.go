package rbac

// Canonical JSON-RPC method name constants (as defined by the Ethereum spec).
// All method names are stored in their canonical camelCase form.
// Callers that need case-insensitive matching should use strings.EqualFold.
const (
	// Transaction query methods.
	MethodGetTransactionByHash                 = "eth_getTransactionByHash"
	MethodGetTransactionReceipt               = "eth_getTransactionReceipt"
	MethodGetTransactionByBlockHashAndIndex   = "eth_getTransactionByBlockHashAndIndex"
	MethodGetTransactionByBlockNumberAndIndex = "eth_getTransactionByBlockNumberAndIndex"

	// Block query methods.
	MethodGetBlockByHash    = "eth_getBlockByHash"
	MethodGetBlockByNumber  = "eth_getBlockByNumber"
	MethodGetBlockReceipts  = "eth_getBlockReceipts"

	// Log/event methods.
	MethodGetLogs = "eth_getLogs"

	// Stateful filter methods (globally blocked — use eth_getLogs instead).
	MethodNewFilter                  = "eth_newFilter"
	MethodNewBlockFilter             = "eth_newBlockFilter"
	MethodNewPendingTransactionFilter = "eth_newPendingTransactionFilter"
	MethodGetFilterLogs              = "eth_getFilterLogs"
	MethodGetFilterChanges           = "eth_getFilterChanges"
	MethodUninstallFilter            = "eth_uninstallFilter"

	// State query methods.
	MethodGetStorageAt        = "eth_getStorageAt"
	MethodGetCode             = "eth_getCode"
	MethodGetBalance          = "eth_getBalance"
	MethodGetTransactionCount = "eth_getTransactionCount"
	MethodGetProof            = "eth_getProof"

	// Transaction send / call methods.
	MethodCall               = "eth_call"
	MethodEstimateGas        = "eth_estimateGas"
	MethodSendTransaction    = "eth_sendTransaction"
	MethodSendRawTransaction = "eth_sendRawTransaction"
)
