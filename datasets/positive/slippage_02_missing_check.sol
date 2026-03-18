// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRouter {
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
}

contract MissingSlippageCheck {
    IRouter public router;

    constructor(address _router) {
        router = IRouter(_router);
    }

    function swap(uint amountIn, address[] calldata path) external {
        router.swapExactTokensForTokens(
            amountIn,
            0, // no minOut
            path,
            msg.sender,
            block.timestamp
        );
    }
}