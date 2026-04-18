// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Pattern: missing phase enforcement on a state-transition function.
// The settle() function can be called while the auction is still open,
// allowing the owner to drain funds before the auction legitimately ends.
// Based on a common audit finding in auction and escrow contracts.
contract PhaseAuction {
    enum Phase { Open, Ended, Settled }

    Phase public currentPhase;
    address public owner;
    address public highestBidder;
    uint256 public highestBid;
    uint256 public endTime;

    event BidPlaced(address indexed bidder, uint256 amount);
    event AuctionEnded();
    event AuctionSettled(address indexed winner, uint256 amount);

    constructor(uint256 duration) {
        require(duration > 0, "Zero duration");
        owner = msg.sender;
        endTime = block.timestamp + duration;
        currentPhase = Phase.Open;
    }

    function bid() external payable {
        require(currentPhase == Phase.Open, "Auction not open");
        require(block.timestamp < endTime, "Bidding period over");
        require(msg.value > highestBid, "Bid too low");

        if (highestBidder != address(0)) {
            payable(highestBidder).transfer(highestBid);
        }

        highestBidder = msg.sender;
        highestBid = msg.value;
        emit BidPlaced(msg.sender, msg.value);
    }

    function endAuction() external {
        require(msg.sender == owner, "Not owner");
        require(block.timestamp >= endTime, "Auction still ongoing");
        require(currentPhase == Phase.Open, "Already ended");
        currentPhase = Phase.Ended;
        emit AuctionEnded();
    }

    // Vulnerable: missing phase check allows calling settle() before the auction ends.
    // Owner can call settle() while Phase is still Open, cutting off active bidders.
    function settle() external {
        require(msg.sender == owner, "Not owner");
        require(highestBidder != address(0), "No bids");
        // Missing: require(currentPhase == Phase.Ended, "Auction not ended");
        payable(highestBidder).transfer(address(this).balance);
        currentPhase = Phase.Settled;
        emit AuctionSettled(highestBidder, highestBid);
    }
}
