// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe: implements CEI (Checks-Effects-Interactions) order correctly.
// State is zeroed before the external call, preventing reentrancy exploitation.
// Negative control pair for simple_dao.sol.

contract SafeWithdraw {
    mapping(address => uint256) public credit;

    function donate(address to) external payable {
        credit[to] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(credit[msg.sender] >= amount, "Insufficient credit");
        credit[msg.sender] -= amount;           // effect before interaction
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
