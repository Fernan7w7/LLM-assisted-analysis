// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EdgeCase {
    address public currentLeader;
    uint public highestBid;

    function bid() public payable {
        require(msg.value > highestBid);

        if (currentLeader != address(0)) {
            (bool success, ) = currentLeader.call{value: highestBid}("");
            // no require -> failure does not revert
        }

        currentLeader = msg.sender;
        highestBid = msg.value;
    }
}