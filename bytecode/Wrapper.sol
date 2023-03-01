/// SPDX-License-Identifier: MIT

pragma solidity 0.8.19;

contract Target {
  uint256 public balance;

  function fund() external returns (uint256) {
    balance = 1_000_000e18;
    return balance;
  }

  function fund(uint256 amount) external returns (uint256) {
    balance = amount;
    return balance;
  }

function rug() external returns (uint256)  {
    balance = 0;
    return balance;
  }

  function version() external pure returns(uint256) {
    return 1;
  }
}

contract Wrapper is Target {
  function delta(bytes calldata data) external returns (int256) {
    // get balance
    uint256 beforeBalance = state();

    // exec tx
    execute(data);

    // get balance
    uint256 afterBalance = state();

    // return delta
    return int256(beforeBalance) - int256(afterBalance);
  }
  
  function state() public view returns(uint256){
    return balance;
  }

  function execute(
        bytes calldata _data
    ) public returns (bool, bytes memory) {
        (bool success, bytes memory result) = address(this).call{value: 0}(_data);

        return (success, result);
    }
}