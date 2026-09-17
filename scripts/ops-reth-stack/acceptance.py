"""Real HTTP and finalized-chain acceptance; no direct application-table writes."""
import json
import hashlib
from datetime import datetime, timezone
from http.cookiejar import CookieJar
from pathlib import Path
import time
import urllib.request
import uuid

from stack import SCRIPT, helper, http, run, save, wait_http, write_private


def accept(state):
    base = state["urls"]["ops"]
    admin = {"X-Admin-Token": state["secrets"]["admin"]}
    evidence = {"checks": [], "stack": state["project"], "binaryDigests": state.get("binaryDigests", {})}
    started = time.monotonic()
    # A denied intent can remain in the pool until its ticket expires. Repeated
    # acceptance runs replace that old test nonce with an explicitly higher fee.
    state["acceptanceGasPrice"] = max(2000000000, state.get("acceptanceGasPrice", 1000000000)*2)
    save(state)
    def sign_transaction(**fields):
        return helper(state, {"Action": "transaction", "GasPrice": state["acceptanceGasPrice"], **fields})

    def check(name):
        evidence["checks"].append(name)
        write_private(Path(state["directory"])/"acceptance.json", json.dumps(evidence, indent=2)+"\n")
        print("PASS "+name, flush=True)

    def request(path, body=None, token=None, method=None, bootstrap=False, expect=200):
        code, response = http(base+path, body, token, method, admin if bootstrap else None)
        if code != expect:
            raise RuntimeError(f"{method or ('POST' if body is not None else 'GET')} {path}: expected {expect}, got {code}: {response}")
        return response

    def login(subject):
        session = request("/auth/request", {})
        return request("/auth/verify", {"session_id": session["session_id"], "jwz_token": "mock."+subject})["access_token"]

    def rpc(method, params, token):
        result = request("/rpc/"+org, {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, token)
        if "error" in result:
            raise RuntimeError(f"{method}: {result['error']}")
        return result["result"]

    def ready():
        wait_http(state, "OPS policy publication", base+"/ready", timeout=90)

    def activate(kind, source):
        prefix = f"/api/v1/admin/orgs/{org}/configuration/{kind}"
        candidate = request(prefix+"/revisions", source, author, expect=201)
        review = request(prefix+"/revisions/"+candidate["id"]+"/simulate", {"coactivate": []}, reviewer)
        assert review["revisions"][0]["digest"] == candidate["digest"]
        denied, _ = http(base+prefix+"/revisions/"+candidate["id"]+"/activate", {"coactivate": []}, author)
        assert denied == 403, f"Self approval must fail, got {denied}"
        request(prefix+"/revisions/"+candidate["id"]+"/activate", {"coactivate": []}, reviewer)
        ready()
        return candidate

    def final(tx_hash):
        deadline = time.monotonic()+90
        while time.monotonic() < deadline:
            result = request(f"/api/v1/me/transactions/{tx_hash}/execution", token=user)
            if result["status"] == "reverted":
                raise RuntimeError(f"Transaction reverted: {result}")
            if result["status"] == "included" and result["reconciled"]:
                return result
            time.sleep(.5)
        raise RuntimeError(f"Transaction failed to reconcile: {result}")

    # Named mock identities are authenticated through the real login endpoints.
    # They deliberately use did:test to avoid the dev convenience admin role.
    state["subjects"].setdefault("other", "did:test:ops-reth-other")
    for subject in state["subjects"].values():
        login(subject)
    org = request("/api/v1/admin/orgs", {"slug": "acceptance-"+uuid.uuid4().hex[:10], "name": "Reth DSL acceptance"}, bootstrap=True, expect=201)["id"]
    org_base = f"/api/v1/admin/orgs/{org}"
    admin_group = request(org_base+"/groups", {"slug": "reviewers", "name": "Reviewers", "is_org_admin": True}, bootstrap=True, expect=201)["id"]
    request(org_base+"/groups/"+admin_group+"/access", {"allowed_methods": ["*"], "claims": [], "verbose_errors": True}, method="PUT", bootstrap=True)
    principals = {}
    for role in ["author", "reviewer"]:
        onboard = request(org_base+"/memberships/by-did", {"did": state["subjects"][role], "group_id": admin_group}, bootstrap=True, expect=201)
        principals[role] = onboard["user_id"]
        request("/api/v1/admin/users/"+onboard["user_id"], {"kyc": True}, method="PUT", bootstrap=True)
    author, reviewer = login(state["subjects"]["author"]), login(state["subjects"]["reviewer"])
    check("bootstrap organization and two named human administrators")

    source = request(org_base+"/configuration/groups/context", token=author)["source"]
    group = str(uuid.uuid4())
    source["spec"]["groups"].append({"id": group, "slug": "operators", "name": "Operators", "description": "Acceptance deployment group", "isOrgAdmin": False, "isOrgReadonlyAdmin": False, "allowedMethods": ["*"], "claims": ["deploy"], "verboseErrors": True})
    other_group = str(uuid.uuid4())
    source["spec"]["groups"].append({"id": other_group, "slug": "observers", "name": "Observers", "description": "Shared signer, separate principal", "isOrgAdmin": False, "isOrgReadonlyAdmin": False, "allowedMethods": ["*"], "claims": [], "verboseErrors": True})
    activate("groups", source)
    check("create group through reviewed source; self approval rejected")
    onboard = request(org_base+"/memberships/by-did", {"did": state["subjects"]["user"], "group_id": group}, author, expect=201)
    principals["user"] = onboard["user_id"]
    request("/api/v1/admin/users/"+onboard["user_id"], {"kyc": True}, method="PUT", bootstrap=True)
    user = login(state["subjects"]["user"])
    challenge = request("/api/v1/eth/link/challenge", {}, user)
    signed = helper(state, {"Action": "message", "Message": challenge["message"]})
    request("/api/v1/eth/link/verify", {"nonce": challenge["nonce"], "address": signed["sender"], "signature": signed["signature"]}, user)
    onboard = request(org_base+"/memberships/by-did", {"did": state["subjects"]["other"], "group_id": other_group}, author, expect=201)
    principals["other"] = onboard["user_id"]
    request("/api/v1/admin/users/"+onboard["user_id"], {"kyc": True}, method="PUT", bootstrap=True)
    other = login(state["subjects"]["other"])
    challenge = request("/api/v1/eth/link/challenge", {}, other)
    signed = helper(state, {"Action": "message", "Message": challenge["message"]})
    request("/api/v1/eth/link/verify", {"nonce": challenge["nonce"], "address": signed["sender"], "signature": signed["signature"]}, other)
    check("onboard user, verify KYC, and prove signer ownership")

    context = request(org_base+"/configuration/execution-rules/context", token=author)
    baseline = activate("execution-rules", context["source"])
    evidence.update(orgId=org, groupId=group, principals=principals, policyDigest=baseline["digest"])
    check("import, compile, independently activate and publish baseline execution policy")
    compiled = json.loads(run(["solc", "--evm-version", "shanghai", "--combined-json", "abi,bin,hashes", SCRIPT/"Counter.sol"], capture_output=True, text=True).stdout)
    contract = next(iter(compiled["contracts"].values()))
    code, nonce_response = http(f"http://127.0.0.1:{state['ports']['reth']}", {"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount", "params": [state["sender"], "latest"]})
    assert code == 200 and "result" in nonce_response
    nonce = int(nonce_response["result"], 16)
    deploy = sign_transaction(Nonce=nonce, Data=contract["bin"])
    assert rpc("eth_sendRawTransaction", [deploy["raw"]], user) == deploy["hash"]
    final(deploy["hash"])
    evidence["deployment"] = deploy["hash"]
    evidence["contract"] = deploy["created"]
    check("scoped signed CREATE finalized and registered by OPS reconciliation")

    # Adopt chain-created drift and ABI through its own reviewed registry stream.
    registry = request(org_base+"/configuration/contract-registry/context", token=author)["source"]
    created = next(c for c in registry["spec"]["contracts"] if c["address"] == deploy["created"])
    created["name"], created["abi"] = "Acceptance Counter", contract["abi"]
    activate("contract-registry", registry)
    check("adopt deployed contract and ABI into reviewed registry source")

    call = sign_transaction(Nonce=nonce+1, To=deploy["created"], Data="0xd09de08a")
    assert rpc("eth_sendRawTransaction", [call["raw"]], user) == call["hash"]
    final(call["hash"])
    evidence["call"] = call["hash"]
    assert int(rpc("eth_call", [{"from": state["sender"], "to": deploy["created"], "data": "0x3fa4f245"}, "latest"], user), 16) == 1
    check("authorized transaction and live eth_call execute on Reth")
    status, other_result = http(base+"/rpc/"+org, {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"from": state["sender"], "to": deploy["created"], "data": "0x3fa4f245"}, "latest"]}, other)
    assert status == 403 or status == 200 and "error" in other_result, f"Expected policy denial for shared signer, got {status}: {other_result}"
    status, _ = http(base+f"/api/v1/me/transactions/{call['hash']}/execution", token=other)
    assert status == 404, "Shared signer incorrectly disclosed another principal's intent"
    check("same linked signer keeps distinct principal permissions and transaction status privacy")

    deadline = time.monotonic()+60
    while time.monotonic() < deadline:
        status, tx = http(base+"/api/v1/explorer/transactions/"+call["hash"], token=user)
        if status == 200:
            break
        time.sleep(1)
    assert status == 200, f"Indexer/explorer transaction unavailable: {status}: {tx}"
    logs = request("/api/v1/explorer/transactions/"+call["hash"]+"/logs", token=user)
    assert logs, "Expected actual Counter event in viewer-filtered explorer logs"
    hidden, _ = http(base+"/api/v1/explorer/transactions/"+call["hash"])
    assert hidden == 404, f"Anonymous viewer must not see private transaction, got {hidden}"
    check("indexer transaction and emitted event visible through authenticated OPS explorer API")

    browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    explorer = state["urls"]["explorer"]
    with browser.open(explorer+"/api/auth/login", timeout=20) as response:
        oauth = json.load(response)
    session_id = oauth["oauth_session_id"]
    request("/oauth/session/"+session_id+"/mock-complete", {"did": state["subjects"]["user"]})
    redirect = request("/oauth/session/"+session_id+"/status")["redirect_url"]
    with browser.open(redirect, timeout=20) as response:
        assert response.status == 200
    with browser.open(explorer+"/api/auth/status", timeout=20) as response:
        session_status = json.load(response)
    assert session_status.get("authenticated"), f"Explorer browser session missing: {session_status}"
    with browser.open(explorer+"/api/transactions/"+call["hash"], timeout=20) as response:
        browser_tx = json.load(response)
    assert call["hash"] in json.dumps(browser_tx), "BFF did not return viewer's transaction"
    check("explorer OAuth code exchange, HttpOnly session and authenticated BFF transaction read")

    # Pin both guarded method and getter to the adopted ABI. The getter reads
    # current contract storage, independently of msg.sender and OPS snapshots.
    abi_digest = hashlib.sha256(json.dumps(contract["abi"], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    hashes = contract["hashes"]
    complete_data = "0x"+hashes["complete(uint256)"]+"0"*64
    record_source = request(org_base+"/configuration/execution-rules/context", token=author)["source"]
    for binding in record_source["spec"]["policy"]["bindings"]:
        if binding["group"] == group:
            binding["allow"] = [{"storageAddress": deploy["created"], "selector": "0x"+hashes["complete(uint256)"], "abiDigest": abi_digest,
                "args": [{"index": 0, "recordParty": {"getter": "0x"+hashes["getParty(uint256)"], "abiDigest": abi_digest, "partyOutputs": [0]}}]},
                {"storageAddress": deploy["created"], "selector": "0x"+hashes["setParty(address)"], "abiDigest": abi_digest}]
    activate("execution-rules", record_source)
    next_nonce = nonce+2
    record_call = sign_transaction(Nonce=next_nonce, To=deploy["created"], Data=complete_data)
    assert rpc("eth_sendRawTransaction", [record_call["raw"]], user) == record_call["hash"]
    final(record_call["hash"])
    next_nonce += 1
    setter = sign_transaction(Nonce=next_nonce, To=deploy["created"], Data="0x"+hashes["setParty(address)"]+"0"*24+"1"*40)
    assert rpc("eth_sendRawTransaction", [setter["raw"]], user) == setter["hash"]
    final(setter["hash"])
    next_nonce += 1
    status, rejected = http(base+"/rpc/"+org, {"jsonrpc": "2.0", "id": 1, "method": "eth_call", "params": [{"from": state["sender"], "to": deploy["created"], "data": complete_data}, "latest"]}, user)
    assert status == 403 or status == 200 and "error" in rejected, f"Expected policy denial after party change, got {status}: {rejected}"
    evidence["recordParty"] = {"allowedTransaction": record_call["hash"], "partyChange": setter["hash"], "abiDigest": abi_digest}
    check("recordParty permits the current linked party and denies after an actual on-chain party change")

    # Preserve membership so this assertion tests policy revocation itself.
    execution = request(org_base+"/configuration/execution-rules/context", token=author)["source"]
    for binding in execution["spec"]["policy"]["bindings"]:
        if binding["group"] == group:
            binding["allow"] = []
    active = activate("execution-rules", execution)
    evidence["activeRevisionId"], evidence["activePolicyDigest"] = active["id"], active["digest"]
    denied = sign_transaction(Nonce=next_nonce, To=deploy["created"], Data="0xd09de08a")
    status, result = http(base+"/rpc/"+org, {"jsonrpc": "2.0", "id": 1, "method": "eth_sendRawTransaction", "params": [denied["raw"]]}, user)
    assert status == 200 and result.get("result") == denied["hash"], f"Revocation test did not reach node admission: {status}: {result}"
    if status == 200 and "result" in result:
        # Pool admission is asynchronous. A hash acknowledges the submitted
        # intent; only canonical execution status means the transaction ran.
        assert result["result"] == denied["hash"]
        deadline = time.monotonic()+30
        while time.monotonic() < deadline:
            result = request(f"/api/v1/me/transactions/{denied['hash']}/execution", token=user)
            assert result["status"] not in ["included", "reverted"], f"Revoked transaction executed: {result}"
            if result["status"] == "denied":
                assert result["execution"]["reason_code"] == "POLICY_DENIED"
                break
            time.sleep(.5)
        else:
            raise RuntimeError(f"Revoked transaction did not reach denied status: {result}")
    for _ in range(3):
        time.sleep(1.1)
        _, receipt = http(f"http://127.0.0.1:{state['ports']['reth']}", {"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionReceipt", "params": [denied["hash"]]})
        assert receipt.get("result") is None, "Revoked transaction was included"
    evidence["denied"] = denied["hash"]
    evidence["verifiedAt"] = datetime.now(timezone.utc).isoformat()
    evidence["elapsedSeconds"] = round(time.monotonic()-started, 2)
    check("reviewed rule revocation denies the next transaction after node synchronization")
    state["acceptance"] = evidence
    save(state)
    print("Acceptance complete. Evidence: "+str(Path(state["directory"])/"acceptance.json"), flush=True)


def verify_persistence(state):
    evidence = state.get("acceptance")
    if not evidence:
        return
    base = state["urls"]["ops"]
    def login(role):
        _, session = http(base+"/auth/request", {})
        status, auth = http(base+"/auth/verify", {"session_id": session["session_id"], "jwz_token": "mock."+state["subjects"][role]})
        assert status == 200
        return auth["access_token"]
    author, user = login("author"), login("user")
    status, context = http(base+f"/api/v1/admin/orgs/{evidence['orgId']}/configuration/execution-rules/context", token=author)
    assert status == 200 and context["active"], "Active reviewed policy was lost across restart"
    if "activeRevisionId" in evidence:
        assert context["active"]["id"] == evidence["activeRevisionId"]
        assert context["active"]["digest"] == evidence["activePolicyDigest"]
    status, execution = http(base+f"/api/v1/me/transactions/{evidence['call']}/execution", token=user)
    assert status == 200 and execution["status"] == "included" and execution["reconciled"], "Finalized execution bookkeeping was lost"
    status, transaction = http(base+"/api/v1/explorer/transactions/"+evidence["call"], token=user)
    assert status == 200 and evidence["call"] in json.dumps(transaction), "Indexed transaction was lost across restart"
    evidence["restartVerified"] = True
    state["acceptance"] = evidence
    save(state)
    write_private(Path(state["directory"])/"acceptance.json", json.dumps(evidence, indent=2)+"\n")
    print("PASS restart preserved reviewed policy, finalized execution and authenticated explorer history", flush=True)
