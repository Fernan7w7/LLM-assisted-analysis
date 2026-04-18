// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe: token transfer happens before state is mutated.
// If the transfer fails, no shares are destroyed — the user retains their position.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract SafeStakingVault {
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
        require(stakingToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        stakedShares[msg.sender] += amount;
        totalShares += amount;
        emit Staked(msg.sender, amount);
    }

    // Safe: external transfer executes first.
    // If it reverts, shares remain intact — the user can retry.
    function redeem(uint256 shareAmount) external {
        require(stakedShares[msg.sender] >= shareAmount, "Insufficient shares");
        require(shareAmount > 0, "Zero amount");

        // Transfer out first — failure leaves state unchanged
        require(stakingToken.transfer(msg.sender, shareAmount), "Transfer failed");

        // State updated only after successful transfer
        stakedShares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        emit Redeemed(msg.sender, shareAmount);
    }

    function getShares(address user) external view returns (uint256) {
        return stakedShares[user];
    }
}
