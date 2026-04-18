// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract NonCritical {
    address public lastUser;

    function doSomething() public payable {
        lastUser = msg.sender;

        // External call, but non-critical
        (bool success, ) = msg.sender.call{value: 0}("");
        success; // ignored
    }
}