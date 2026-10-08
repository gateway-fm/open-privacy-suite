"""Explicit defaults for the isolated, ten-wallet Gasstorm UI fixture."""


def normalize_start(request):
    if not isinstance(request, dict):
        raise ValueError("Expected a test configuration")
    if request.get("privacyMode") is not True:
        raise ValueError("Choose Through Privacy Proxy; this session tests OPS with Reth")
    if request.get("numAccounts", 0) not in (0, 10):
        raise ValueError("This session has ten configured wallets; use the automatic account count")
    if request.get("gasless"):
        raise ValueError("Leave Gasless off: this chain charges real fees")
    if request.get("fixNonceGaps"):
        raise ValueError("Leave Fix nonce gaps off: the healer is not wired into this loadgenerator checkout")
    if request.get("pattern") not in ("constant", "ramp", "spike", "adaptive"):
        raise ValueError("Choose an individual workload with Constant, Ramp, Spike or Adaptive")
    return {**request, "numAccounts": 10}
