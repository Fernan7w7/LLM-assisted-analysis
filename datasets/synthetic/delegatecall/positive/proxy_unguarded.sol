// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Source: Adapted from Parity Multisig Wallet library pattern — unguarded delegatecall.
// Referenced in SWC-112 (https://swcregistry.io/docs/SWC-112) and Trail of Bits
// not-so-smart-contracts (github.com/trailofbits/not-so-smart-contracts/tree/master/unprotected_function).
// Vulnerability: fallback delegates all calls to an implementation address that any
// caller can set — an attacker can point it to a malicious contract and take ownership.

contract ProxyUnguarded {
    address public implementation;

    constructor(address _impl) {
        implementation = _impl;
    }

    // No access control — any caller can redirect all delegatecall logic
    function setImplementation(address _newImpl) external {
        implementation = _newImpl;
    }

    fallback() external payable {
        address impl = implementation;
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
}
