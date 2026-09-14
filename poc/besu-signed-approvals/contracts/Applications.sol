// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

interface IVault { function note(uint256 amount) external; }
interface IRelay { function forward(uint256 amount) external; }

// These application contracts contain no OPS policy checks, organization checks, or policy imports.
contract Router {
    uint256 public beforeCalls;
    uint256 public afterCalls;
    uint256 public caughtFailures;

    function run(uint256 amount) external {
        beforeCalls++;
        IRelay(address(0x1200)).forward(amount);
        afterCalls++;
    }

    function runCatch(uint256 amount) external {
        beforeCalls++;
        try IRelay(address(0x1200)).forward(amount) {} catch { caughtFailures++; }
        afterCalls++;
    }

    function runDelegate(address target, uint256 amount) external {
        beforeCalls++;
        (bool ok,) = target.delegatecall(abi.encodeCall(IVault.note, (amount)));
        if (!ok) caughtFailures++;
        afterCalls++;
    }
}

contract Relay {
    address public target;
    uint256 public beforeCalls;
    uint256 public afterCalls;

    function setTarget(address next) external { target = next; }

    function forward(uint256 amount) external {
        beforeCalls++;
        IVault(target).note(amount);
        afterCalls++;
    }
}

contract Vault {
    uint256 public total;
    event Noted(uint256 amount);
    function note(uint256 amount) external { total += amount; emit Noted(amount); }
}

// Independent storage keys make batched approvals valid without pretending that
// preflights against one state can approve sequential increments of the same slot.
contract BenchRouter {
    function run(uint256 key, uint256 count) external {
        BenchRelay(address(0x3200)).run(key, count);
    }
}
contract BenchRelay {
    function run(uint256 key, uint256 count) external {
        for (uint256 i; i < count; ++i) BenchVault(address(0x3300)).put(key+i, 7);
    }
}
contract BenchVault {
    mapping(uint256 => uint256) public values;
    function put(uint256 key, uint256 value) external { values[key] = value; }
}

interface IReadVault { function total() external view returns (uint256); }
contract ReadRouter {
    function probe() external view returns (uint256) {
        return ReadRelay(address(0x4200)).probe();
    }
}
contract ReadRelay {
    function probe() external view returns (uint256) {
        // Same output and no application writes at both targets. Preflight at
        // genesis calls A; actual candidate block calls B.
        return IReadVault(block.number == 0 ? address(0x1300) : address(0x2300)).total();
    }
}

// Exercise log positions, dynamic returndata and logs discarded by a caught revert.
contract FingerprintCases {
    event Entry(bytes data);
    function inner(bool fail) external returns (bytes memory) {
        emit Entry(hex"00ff");
        require(!fail, "caught fixture");
        return hex"001122ff";
    }
    function mixed() external returns (bytes memory) {
        emit Entry(hex"80");
        this.inner(false);
        try this.inner(true) {} catch {}
        emit Entry(hex"ff00");
        return hex"0080ff";
    }
}

contract ValueRouter {
    address payable public target;
    uint256 public calls;
    receive() external payable {}
    function setTarget(address payable next) external { target = next; }
    function send(uint256 amount) external payable {
        calls++;
        (bool ok,) = target.call{value: amount}("");
        require(ok, "value call failed");
    }
    function caught(address payable callee) external payable {
        calls++;
        try ValueReceiver(callee).fail{value: msg.value}() {} catch {}
    }
}
contract ValueReceiver {
    uint256 public received;
    receive() external payable { received += msg.value; }
    function fail() external payable { received += msg.value; revert("caught value"); }
}
contract LifeChild {
    uint256 public number;
    constructor(uint256 n, address target) payable {
        number = n;
        if (target != address(0)) IVault(target).note(n);
    }
    function set(uint256 n) external { number = n; }
    function destroy(address payable target) external { selfdestruct(target); }
}
contract LifeFactory {
    address public last;
    function create(uint256 n, address target) external payable returns (address) {
        last = address(new LifeChild{value: msg.value}(n, target));
        LifeChild(last).set(n + 1);
        return last;
    }
    function create2(bytes32 salt, uint256 n) external payable returns (address) {
        last = address(new LifeChild{salt: salt, value: msg.value}(n, address(0)));
        return last;
    }
    function createAndDestroy(address payable target) external payable {
        LifeChild child = new LifeChild{value: msg.value}(7, address(0));
        child.destroy(target == address(0) ? payable(address(child)) : target);
    }
    function failAfterDestroy(address payable target) external payable {
        this.createAndDestroy{value: msg.value}(target);
        revert("undo lifecycle");
    }
    function caught(address payable target) external payable {
        try this.failAfterDestroy{value: msg.value}(target) {} catch {}
    }
}
contract Destructible {
    uint256 public marker = 7;
    receive() external payable {}
    function destroy(address payable target) external { selfdestruct(target); }
}

// Application fixtures for call-only approvals. No OPS or organization checks.
contract CallHashCases {
    uint256 public total;
    uint256 public amount;
    bool public extra;
    event Changed(uint256 total, uint256 at);
    function tick() external returns (uint256) {
        total++;
        emit Changed(total, block.timestamp);
        return total;
    }
    function identity() external view returns (bytes memory) { (bool ok,bytes memory out)=address(4).staticcall(hex"1234");require(ok);return out; }
    function setAmount(uint256 next) external { amount = next; }
    function pay() external { IVault(address(0x1300)).note(amount); }
    function payNative() external payable { (bool ok,) = payable(address(0x8100)).call{value:amount}(""); require(ok); }
    function setExtra(bool next) external { extra = next; }
    function branch() external { total++; if (extra) this.tick(); }
    function maybeCreate() external { total++; if (extra) new LifeChild(7,address(0)); }
    // Deliberately documents the guarantee: an internal amount is not checked
    // by call-only equality when it never appears in a nested call's input.
    function internalAccounting() external { total += amount; }
}
contract CallHashToken {
    mapping(address => uint256) public balanceOf;
    uint256 public totalSupply;
    event Transfer(address indexed from, address indexed to, uint256 amount);
    function mint(address to, uint256 amount) external {
        require(msg.sender == address(0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266), "issuer");
        totalSupply += amount; balanceOf[to] += amount; emit Transfer(address(0),to,amount);
    }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "funds");
        balanceOf[msg.sender] -= amount; balanceOf[to] += amount;
        emit Transfer(msg.sender,to,amount); return true;
    }
}
