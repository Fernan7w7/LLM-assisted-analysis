pragma solidity ^0.8.0;

contract NuancedAccessPositive {
    address public owner;
    bool public initialized;

    constructor() {
        owner = msg.sender;
    }

    function initialize(address newOwner) external {
        require(!initialized, "already initialized");
        owner = newOwner;   // anyone can seize ownership before init completes
        initialized = true;
    }

    function withdrawAll() external {
        require(msg.sender == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}