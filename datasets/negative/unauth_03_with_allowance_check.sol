// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract AllowanceProtected {
    IERC20 public token;

    constructor(address _token) {
        token = IERC20(_token);
    }

    function moveTokens(address from, address to, uint256 amount) external {
        require(token.allowance(from, address(this)) >= amount, "not approved");
        token.transferFrom(from, to, amount);
    }
}