/// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

contract Target {
  uint256 public balance;

  function fund() external returns (uint256) {
    balance = 1_000_000e18;
    return balance;
  }

function rug() external returns (uint256)  {
    balance = 0;
    return balance;
  }
}