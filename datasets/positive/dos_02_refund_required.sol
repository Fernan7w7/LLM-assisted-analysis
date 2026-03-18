// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Refund {
    address public lastUser;
    uint public lastAmount;

    function participate() public payable {
        require(msg.value > lastAmount);

        if (lastUser != address(0)) {
            (bool success, ) = lastUser.call{value: lastAmount}("");
            require(success);
        }

        lastUser = msg.sender;
        lastAmount = msg.value;
    }
}