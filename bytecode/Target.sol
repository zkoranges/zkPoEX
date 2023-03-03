// SPDX-License-Identifier: MIT
// DO NOT USE IN PRODUCTION
// Ethernaut Lvl. 10 - Reentrance
pragma solidity 0.8.19;

contract Target {
  
  mapping(address => uint) public balances;

  function deposit(address _to) public payable {
    balances[_to] = balances[_to] + msg.value;
  }

  function balanceOf(address _who) public view returns (uint balance) {
    return balances[_who];
  }

  function withdraw(uint _amount) public {
    if(balances[msg.sender] >= _amount) {
      (bool result,) = msg.sender.call{value:_amount}("");
      if(result) {
        _amount;
      }
      unchecked {
        balances[msg.sender] -= _amount;
      }
    }
  }

  constructor() payable {}

  receive() external payable {}
}