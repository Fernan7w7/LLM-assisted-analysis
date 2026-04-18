// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableVault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    function withdrawAll() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}