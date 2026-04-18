// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract MissingZeroAddressCheck {
    address public recipient;

    function setRecipient(address _recipient) external {
        recipient = _recipient;
    }
}