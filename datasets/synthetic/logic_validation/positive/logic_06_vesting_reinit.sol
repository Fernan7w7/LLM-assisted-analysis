// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Pattern: vesting schedule can be overwritten after claims have begun.
// The setupVesting() function lacks an initialization guard, allowing the owner
// to reset the schedule mid-vesting — potentially reducing totalAmount after
// the beneficiary has already claimed, or extending duration to delay further claims.
// Based on documented findings in token vesting and grant contracts.
contract VestingSchedule {
    address public owner;
    address public beneficiary;
    uint256 public totalAmount;
    uint256 public startTime;
    uint256 public duration;
    uint256 public claimed;

    event VestingConfigured(address indexed beneficiary, uint256 total, uint256 duration);
    event Claimed(address indexed beneficiary, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    // Vulnerable: no guard prevents re-configuration after vesting has started.
    // Owner can call this again after partial claims to manipulate totalAmount or duration,
    // and also resets `claimed` to 0 — allowing the owner to undo already-distributed tokens.
    function setupVesting(
        address _beneficiary,
        uint256 _totalAmount,
        uint256 _duration
    ) external {
        require(msg.sender == owner, "Not owner");
        require(_beneficiary != address(0), "Zero address");
        require(_totalAmount > 0, "Zero amount");
        require(_duration > 0, "Zero duration");
        // Missing: require(beneficiary == address(0), "Already initialized");
        beneficiary = _beneficiary;
        totalAmount = _totalAmount;
        startTime = block.timestamp;
        duration = _duration;
        claimed = 0; // resets already-distributed amount
        emit VestingConfigured(_beneficiary, _totalAmount, _duration);
    }

    function claimable() public view returns (uint256) {
        if (startTime == 0 || block.timestamp < startTime) return 0;
        uint256 elapsed = block.timestamp - startTime;
        uint256 vested = (totalAmount * elapsed) / duration;
        if (vested > totalAmount) vested = totalAmount;
        if (vested <= claimed) return 0;
        return vested - claimed;
    }

    function claim() external {
        require(msg.sender == beneficiary, "Not beneficiary");
        uint256 amount = claimable();
        require(amount > 0, "Nothing to claim");
        claimed += amount;
        payable(beneficiary).transfer(amount);
        emit Claimed(beneficiary, amount);
    }

    receive() external payable {}
}
