// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

// Benchmark application: successful no-op completion with a live two-slot getter.
// ABI matches the reviewed record-party policy fixture; no production state.
contract LoadRecord {
    address private _payer;
    address private _payee;

    function completePayment(string calldata) external {}

    function getPaymentInfo(string calldata) external view returns (
        uint256 amount, uint256 timestamp, address payer, address payee, bool completed
    ) {
        return (11, 22, _payer, _payee, true);
    }

    function setParties(address payer, address payee) external {
        _payer = payer;
        _payee = payee;
    }
}
