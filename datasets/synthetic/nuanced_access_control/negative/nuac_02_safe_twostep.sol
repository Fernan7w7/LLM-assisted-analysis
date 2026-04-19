// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Safe: proper two-step ownership transfer where acceptOwnership is restricted
// to pendingOwner. Ownership set in constructor — no frontrunnable initialize.
contract SafeOwnableVault {
    address public owner;
    address public pendingOwner;

    event OwnershipTransferStarted(address indexed current, address indexed pending);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor(address _owner) {
        require(_owner != address(0), "Zero address");
        owner = _owner;
        emit OwnershipTransferred(address(0), _owner);
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

    // Safe: only pendingOwner can accept — cannot be blocked or intercepted by current owner
    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        address oldOwner = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(oldOwner, owner);
    }

    function withdraw(uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient balance");
        payable(owner).transfer(amount);
    }

    receive() external payable {}
}
