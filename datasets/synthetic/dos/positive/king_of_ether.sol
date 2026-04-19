// SPDX-License-Identifier: MIT
pragma solidity ^0.4.19;

// Source: KingOfTheEtherThrone — canonical DoS-via-external-call example.
// Reproduced from SmartBugs dataset (github.com/smartbugs/smartbugs, denial_of_service/king_of_ether.sol)
// and referenced in SWC-113 (https://swcregistry.io/docs/SWC-113).
// Vulnerability: bid() sends ETH to the previous king inline. If that address
// is a contract with a reverting fallback, bid() is permanently DoS'd — no new
// king can ever be crowned.
// CEI is followed (state updated before transfer) so reentrancy is not the issue.

contract KingOfTheEtherThrone {
    address public currentKing;
    uint256 public currentBid;

    constructor() public payable {
        currentKing = msg.sender;
        currentBid = msg.value;
    }

    function bid() external payable {
        require(msg.value >= currentBid, "Bid too low");

        address previousKing = currentKing;
        uint256 previousBid = currentBid;

        // State updated BEFORE external call (CEI-compliant)
        currentKing = msg.sender;
        currentBid = msg.value;

        // DoS: if previousKing is a malicious contract, this reverts and blocks all future bids
        previousKing.transfer(previousBid);
    }
}
