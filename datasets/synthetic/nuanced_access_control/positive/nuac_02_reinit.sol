// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Pattern: missing initialization guard on a proxy-style contract.
// Based on a recurring finding in upgradeable contract audits where initialize()
// can be called again after deployment, allowing anyone to seize ownership.
contract VaultProxy {
    address public owner;
    address public feeRecipient;
    uint256 public feeBps;

    event OwnerUpdated(address indexed oldOwner, address indexed newOwner);

    // Vulnerable: no guard prevents re-initialization after deployment.
    // Anyone can call initialize() and overwrite owner to take control.
    function initialize(address _owner, address _feeRecipient, uint256 _feeBps) external {
        require(_owner != address(0), "Zero owner");
        require(_feeRecipient != address(0), "Zero recipient");
        require(_feeBps <= 1000, "Fee too high");
        owner = _owner;
        feeRecipient = _feeRecipient;
        feeBps = _feeBps;
        emit OwnerUpdated(address(0), _owner);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function setFeeRecipient(address _feeRecipient) external onlyOwner {
        require(_feeRecipient != address(0), "Zero address");
        feeRecipient = _feeRecipient;
    }

    function setFeeBps(uint256 _feeBps) external onlyOwner {
        require(_feeBps <= 1000, "Fee too high");
        feeBps = _feeBps;
    }

    function withdraw(uint256 amount) external onlyOwner {
        require(address(this).balance >= amount, "Insufficient balance");
        payable(owner).transfer(amount);
    }

    receive() external payable {}
}
