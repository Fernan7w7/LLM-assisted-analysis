// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EthPayout {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function payout(address payable to, uint256 amount) external onlyOwner {
        to.transfer(amount);
    }

    receive() external payable {}
}