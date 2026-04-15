pragma solidity ^0.8.0;

contract AssetLockingPositive {
    mapping(address => uint256) public balances;
    bool public withdrawalsEnabled = false;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        require(withdrawalsEnabled, "withdrawals disabled");
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}