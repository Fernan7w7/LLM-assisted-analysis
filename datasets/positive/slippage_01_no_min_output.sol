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

contract NoSlippageProtection {
    IRouter public router;

    constructor(address _router) {
        router = IRouter(_router);
    }

    function swap(address[] calldata path) external payable {
        router.swapExactETHForTokens{value: msg.value}(
            0, // ❌ no protection
            path,
            msg.sender,
            block.timestamp
        );
    }
}