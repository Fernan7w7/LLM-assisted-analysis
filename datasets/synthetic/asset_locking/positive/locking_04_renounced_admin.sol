// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Pattern: reward funds permanently locked when the admin who controls claim-opening
// renounces their role before enabling withdrawals.
// Based on documented findings where a privileged gate-keeper can be irrevocably removed,
// leaving deposited funds in a permanently unclaimed state.
contract LockedRewards {
    address public admin;
    bool public claimsOpen;
    mapping(address => uint256) public rewards;
    uint256 public totalLocked;

    event RewardDeposited(address indexed user, uint256 amount);
    event RewardClaimed(address indexed user, uint256 amount);
    event ClaimsOpened();
    event AdminRenounced();

    constructor() {
        admin = msg.sender;
    }

    function depositReward(address user) external payable {
        require(msg.sender == admin, "Not admin");
        require(user != address(0), "Zero address");
        require(msg.value > 0, "Zero value");
        rewards[user] += msg.value;
        totalLocked += msg.value;
        emit RewardDeposited(user, msg.value);
    }

    // Only admin can open claims — if admin is renounced first, this can never be called
    function openClaims() external {
        require(msg.sender == admin, "Not admin");
        claimsOpen = true;
        emit ClaimsOpened();
    }

    // Vulnerable: renouncing admin before opening claims permanently locks all deposited rewards.
    // No fallback recovery path exists once admin == address(0).
    function renounceAdmin() external {
        require(msg.sender == admin, "Not admin");
        admin = address(0);
        // claimsOpen may still be false; no one can ever call openClaims() again
        emit AdminRenounced();
    }

    function claim() external {
        require(claimsOpen, "Claims not open");
        uint256 amount = rewards[msg.sender];
        require(amount > 0, "Nothing to claim");
        rewards[msg.sender] = 0;
        totalLocked -= amount;
        payable(msg.sender).transfer(amount);
        emit RewardClaimed(msg.sender, amount);
    }

    receive() external payable {}
}
