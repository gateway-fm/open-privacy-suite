// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.35;
contract Counter {
    uint256 public value;
    address public party;
    constructor() { party = msg.sender; }
    event Changed(address indexed actor, uint256 value);
    function increment() external {
        value++;
        emit Changed(msg.sender, value);
    }
    function getParty(uint256) external view returns (address) { return party; }
    function complete(uint256) external {
        value++;
        emit Changed(msg.sender, value);
    }
    function setParty(address next) external { party = next; }
}
