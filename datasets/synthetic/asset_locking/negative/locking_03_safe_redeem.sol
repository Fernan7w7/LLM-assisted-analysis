// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe: follows CEI order (state updated before external call) and uses a
// nonReentrant lock. If the transfer fails, the transaction reverts and state
// is fully restored — shares are never permanently lost.
interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract SafeStakingVault {
    IERC20 public immutable stakingToken;
    mapping(address => uint256) public stakedShares;
    uint256 public totalShares;
    bool private _locked;

    event Staked(address indexed user, uint256 amount);
    event Redeemed(address indexed user, uint256 amount);

    modifier nonReentrant() {
        require(!_locked, "Reentrant call");
        _locked = true;
        _;
        _locked = false;
    }

    constructor(address _token) {
        require(_token != address(0), "Zero address");
        stakingToken = IERC20(_token);
    }

    function stake(uint256 amount) external nonReentrant {
        require(amount > 0, "Zero amount");
        require(stakingToken.transferFrom(msg.sender, address(this), amount), "Transfer failed");
        stakedShares[msg.sender] += amount;
        totalShares += amount;
        emit Staked(msg.sender, amount);
    }

    // Safe: CEI order — state updated before external call.
    // nonReentrant prevents re-entry. If transfer fails, tx reverts and shares are restored.
    function redeem(uint256 shareAmount) external nonReentrant {
        require(stakedShares[msg.sender] >= shareAmount, "Insufficient shares");
        require(shareAmount > 0, "Zero amount");
        stakedShares[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        require(stakingToken.transfer(msg.sender, shareAmount), "Transfer failed");
        emit Redeemed(msg.sender, shareAmount);
    }

    function getShares(address user) external view returns (uint256) {
        return stakedShares[user];
    }
}
