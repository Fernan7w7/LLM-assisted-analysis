// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Pattern: shares/credits destroyed before the external token transfer.
// If the transfer fails (token paused, blacklisted recipient, out-of-balance),
// the user's shares are permanently lost with no recovery path.
// Based on a class of findings in DeFi vaults and staking protocols.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract StakingVault {
    IERC20 public immutable stakingToken;
    mapping(address => uint256) public stakedShares;
    uint256 public totalShares;

    event Staked(address indexed user, uint256 amount);
    event Redeemed(address indexed user, uint256 amount);

    constructor(address _token) {
        require(_token != address(0), "Zero address");
        stakingToken = IERC20(_token);
    }

    function stake(uint256 amount) external {
        require(amount > 0, "Zero amount");
        require(stakingToken.transferFrom(msg.sender, address(this), amount), "Transfer in failed");
        stakedShares[msg.sender] += amount;
        totalShares += amount;
        emit Staked(msg.sender, amount);
    }

    // Vulnerable: shares are destroyed before the token transfer.
    // A failed transfer (e.g. token is paused or recipient is blacklisted) leaves
    // the user with zero shares and zero tokens — permanent asset loss.
    function redeem(uint256 shareAmount) external {
        require(stakedShares[msg.sender] >= shareAmount, "Insufficient shares");
        require(shareAmount > 0, "Zero amount");

        // Irreversible state mutation happens first
        stakedShares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;

        // If this reverts, shares are already gone — no recovery path
        require(stakingToken.transfer(msg.sender, shareAmount), "Transfer out failed");
        emit Redeemed(msg.sender, shareAmount);
    }

    function getShares(address user) external view returns (uint256) {
        return stakedShares[user];
    }
}
