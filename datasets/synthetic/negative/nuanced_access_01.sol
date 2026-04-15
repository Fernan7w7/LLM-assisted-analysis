pragma solidity ^0.8.0;

contract NuancedAccessNegative {
    address public owner;
    bool public initialized;

    constructor() {
        owner = msg.sender;
    }

    function initialize(address newOwner) external {
        require(msg.sender == owner, "not owner");
        require(!initialized, "already initialized");
        owner = newOwner;
        initialized = true;
    }

    function withdrawAll() external {
        require(msg.sender == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}