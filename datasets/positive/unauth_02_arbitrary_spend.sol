// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract ArbitrarySpender {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function sweep(address victim, uint256 amount) external {
        token.transferFrom(victim, msg.sender, amount);
    }
}