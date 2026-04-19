// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe: settle() enforces the correct phase and endAuction() enforces the time condition.
// No phase transition can be skipped or called out of order.
// Uses pull-payment for bids. Provides a cancelAuction() recovery path if no bids are placed.
contract SafePhaseAuction {
    enum Phase { Open, Ended, Settled, Cancelled }

    Phase public currentPhase;
    address public owner;
    address public highestBidder;
    uint256 public highestBid;
    uint256 public endTime;
    mapping(address => uint256) public pendingReturns;

    event BidPlaced(address indexed bidder, uint256 amount);
    event AuctionEnded();
    event AuctionSettled(address indexed winner, uint256 amount);
    event AuctionCancelled();

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
            pendingReturns[highestBidder] += highestBid;
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

    // Safe: phase check enforced — settle can only run after endAuction() is called
    function settle() external {
        require(msg.sender == owner, "Not owner");
        require(currentPhase == Phase.Ended, "Auction not ended");
        require(highestBidder != address(0), "No bids");
        payable(highestBidder).transfer(address(this).balance);
        currentPhase = Phase.Settled;
        emit AuctionSettled(highestBidder, highestBid);
    }

    // Recovery path: if auction ends with no bids, owner can cancel and recover ETH
    function cancelAuction() external {
        require(msg.sender == owner, "Not owner");
        require(currentPhase == Phase.Ended, "Auction not ended");
        require(highestBidder == address(0), "Bids already placed");
        currentPhase = Phase.Cancelled;
        payable(owner).transfer(address(this).balance);
        emit AuctionCancelled();
    }
}
