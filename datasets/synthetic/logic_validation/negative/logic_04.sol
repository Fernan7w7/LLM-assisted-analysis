// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeAmountCheck {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external payable {
        require(amount > 0, "amount must be > 0");
        balances[msg.sender] += amount;
    }
}