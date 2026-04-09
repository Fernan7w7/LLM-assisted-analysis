// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MissingAmountCheck {
    mapping(address => uint256) public balances;

    function deposit(uint256 amount) external payable {
        balances[msg.sender] += amount;
    }
}