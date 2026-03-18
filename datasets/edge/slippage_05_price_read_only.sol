// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IRouter {
    function getAmountsOut(uint amountIn, address[] calldata path)
        external
        view
        returns (uint[] memory amounts);
}

contract PriceViewer {
    IRouter public router;

    constructor(address _router) {
        router = IRouter(_router);
    }

    function estimate(uint amountIn, address[] calldata path)
        external
        view
        returns (uint)
    {
        uint[] memory amounts = router.getAmountsOut(amountIn, path);
        return amounts[amounts.length - 1]; // no swap → no slippage risk
    }
}