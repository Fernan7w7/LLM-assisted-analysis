// SPDX-License-Identifier: MIT
pragma solidity ^0.4.19;

// Source: KingOfTheEtherThrone — canonical DoS-via-external-call example.
// Reproduced from SmartBugs dataset (github.com/smartbugs/smartbugs, denial_of_service/king_of_ether.sol)
// and referenced in SWC-113 (https://swcregistry.io/docs/SWC-113).
// Vulnerability: claimThrone() sends ETH to the previous king inline; if that address
// is a contract with a reverting fallback, claimThrone() is permanently DoS'd.

contract KingOfTheEtherThrone {
    address public currentKing;
    uint256 public currentClaimPrice;

    constructor() public payable {
        currentKing = msg.sender;
        currentClaimPrice = msg.value;
    }

    function claimThrone() external payable {
        require(msg.value >= currentClaimPrice, "Bid too low");

        // DoS: if currentKing is a malicious contract, this reverts and blocks all future claims
        currentKing.transfer(currentClaimPrice);

        currentKing = msg.sender;
        currentClaimPrice = msg.value;
    }
}
