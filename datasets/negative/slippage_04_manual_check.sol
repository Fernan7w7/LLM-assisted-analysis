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

contract ManualSlippageCheck {
    IRouter public router;

    constructor(address _router) {
        router = IRouter(_router);
    }

    function swap(uint amountIn, address[] calldata path, uint minOut) external {
        uint[] memory amounts = router.swapExactTokensForTokens(
            amountIn,
            0, // initially 0
            path,
            address(this),
            block.timestamp
        );

        require(amounts[amounts.length - 1] >= minOut, "Slippage too high"); // ✅ manual check
    }
}