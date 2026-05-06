// SPDX-License-Identifier: MIT
pragma solidity ^0.4.19;

contract SimpleDAO {
    mapping(address => uint256) public credit;

    function donate(address to) public payable {
        credit[to] += msg.value;
    }

    function withdraw(uint256 amount) public {
        if (credit[msg.sender] >= amount) {
            bool success = msg.sender.call.value(amount)(); // external call before state update
            require(success);
            credit[msg.sender] -= amount;                   // state updated AFTER call — CEI violated
        }
    }

    function queryCredit(address to) public view returns (uint256) {
        return credit[to];
    }
}
