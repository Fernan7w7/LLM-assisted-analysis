// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRouter {
    function swapExactETHForTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable returns (uint[] memory amounts);
}

contract WithSlippageProtection {
    IRouter public router;

    constructor(address _router) {
        router = IRouter(_router);
    }

    function swap(address[] calldata path, uint minOut) external payable {
        router.swapExactETHForTokens{value: msg.value}(
            minOut, // protected
            path,
            msg.sender,
            block.timestamp
        );
    }
}