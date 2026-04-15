// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableDelegate {
    address public target;
    address public owner;

    constructor(address _target) {
        target = _target;
        owner = msg.sender;
    }

    function execute(bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "delegatecall failed");
    }
}