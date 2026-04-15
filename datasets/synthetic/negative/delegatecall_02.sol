// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeDelegate {
    address public target;
    address public owner;

    constructor(address _target) {
        target = _target;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function execute(bytes calldata data) external onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}