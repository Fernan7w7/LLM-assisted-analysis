// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Pattern: two-step ownership transfer where the acceptance function is guarded
// by the CURRENT owner instead of the pending owner.
// Based on a documented audit finding: the current owner can prevent the new owner
// from ever accepting, or call acceptOwnership themselves to cancel a pending transfer.
contract GovernedTreasury {
    address public owner;
    address public pendingOwner;
    uint256 public withdrawLimit;

    event OwnershipTransferStarted(address indexed current, address indexed pending);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor(address _owner) {
        require(_owner != address(0), "Zero address");
        owner = _owner;
        withdrawLimit = 10 ether;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function transferOwnership(address _pendingOwner) external onlyOwner {
        require(_pendingOwner != address(0), "Zero address");
        pendingOwner = _pendingOwner;
        emit OwnershipTransferStarted(owner, _pendingOwner);
    }

    // Vulnerable: guarded by onlyOwner instead of checking msg.sender == pendingOwner.
    // The pending owner can never call this — only the current owner can,
    // defeating the purpose of a two-step transfer and allowing silent cancellation.
    function acceptOwnership() external onlyOwner {
        require(pendingOwner != address(0), "No pending owner");
        address oldOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(oldOwner, owner);
    }

    function setWithdrawLimit(uint256 _limit) external onlyOwner {
        withdrawLimit = _limit;
    }

    function withdraw(uint256 amount) external onlyOwner {
        require(amount <= withdrawLimit, "Exceeds limit");
        require(address(this).balance >= amount, "Insufficient balance");
        payable(owner).transfer(amount);
    }

    receive() external payable {}
}
