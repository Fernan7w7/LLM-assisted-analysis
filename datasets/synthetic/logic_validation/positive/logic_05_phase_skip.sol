// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Pattern: missing phase enforcement on a state-transition function.
// settle() can be called while the auction is still Open, allowing the owner
// to drain funds before the auction legitimately ends.
// Uses pull-payment for bids to keep the DoS concern out of this contract.
// Based on a common audit finding in auction and escrow contracts.
contract PhaseAuction {
    enum Phase { Open, Ended, Settled }

    Phase public currentPhase;
    address public owner;
    address public highestBidder;
    uint256 public highestBid;
    uint256 public endTime;
    mapping(address => uint256) public pendingReturns;

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
            pendingReturns[highestBidder] += highestBid;  // pull-payment: no inline transfer
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
        emit BidPlaced(msg.sender, msg.value);
    }

    function withdrawBid() external {
        uint256 amount = pendingReturns[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        pendingReturns[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }

    function endAuction() external {
        require(msg.sender == owner, "Not owner");
        require(block.timestamp >= endTime, "Auction still ongoing");
        require(currentPhase == Phase.Open, "Already ended");
        currentPhase = Phase.Ended;
        emit AuctionEnded();
    }

    // Vulnerable: missing phase check — settle() can be called while Phase is still Open.
    // Owner can drain funds before the auction legitimately ends.
    function settle() external {
        require(msg.sender == owner, "Not owner");
        require(highestBidder != address(0), "No bids");
        // Missing: require(currentPhase == Phase.Ended, "Auction not ended");
        payable(highestBidder).transfer(address(this).balance);
        currentPhase = Phase.Settled;
        emit AuctionSettled(highestBidder, highestBid);
    }
}
