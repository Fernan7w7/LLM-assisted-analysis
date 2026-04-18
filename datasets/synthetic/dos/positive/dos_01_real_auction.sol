// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract Auction {
    address public currentLeader;
    uint public highestBid;

    function bid() public payable {
        require(msg.value > highestBid);

        if (currentLeader != address(0)) {
            require(currentLeader.call.value(highestBid)());
        }

        currentLeader = msg.sender;
        highestBid = msg.value;
    }
}