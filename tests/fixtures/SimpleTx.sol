// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Exploit {
    function exploit() external view {
        require(block.number > 0, "Expected nonzero block");
    }
}
