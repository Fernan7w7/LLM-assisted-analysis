// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeVault {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function withdrawAll() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }
}