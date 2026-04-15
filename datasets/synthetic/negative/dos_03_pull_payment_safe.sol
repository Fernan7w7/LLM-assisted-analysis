// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeAuction {
    address public currentLeader;
    uint public highestBid;

    mapping(address => uint) public pendingWithdrawals;

    function bid() public payable {
        require(msg.value > highestBid);

        if (currentLeader != address(0)) {
            pendingWithdrawals[currentLeader] += highestBid;
        }

        currentLeader = msg.sender;
        highestBid = msg.value;
    }

    function withdraw() public {
        uint amount = pendingWithdrawals[msg.sender];
        pendingWithdrawals[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}