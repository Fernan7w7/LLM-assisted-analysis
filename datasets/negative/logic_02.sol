// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeZeroAddressCheck {
    address public recipient;

    function setRecipient(address _recipient) external {
        require(_recipient != address(0), "zero address");
        recipient = _recipient;
    }
}