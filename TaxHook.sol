// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {BaseHook} from "@uniswap/v4-periphery/src/utils/BaseHook.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";

import {Hooks} from "@uniswap/v4-core/src/libraries/Hooks.sol";
import {IPoolManager} from "@uniswap/v4-core/src/interfaces/IPoolManager.sol";
import {PoolKey} from "@uniswap/v4-core/src/types/PoolKey.sol";
import {PoolId, PoolIdLibrary} from "@uniswap/v4-core/src/types/PoolId.sol";
import {BalanceDelta} from "@uniswap/v4-core/src/types/BalanceDelta.sol";
import {
    BeforeSwapDelta, BeforeSwapDeltaLibrary, toBeforeSwapDelta
} from "@uniswap/v4-core/src/types/BeforeSwapDelta.sol";
import {Currency, CurrencyLibrary} from "@uniswap/v4-core/src/types/Currency.sol";
import {SafeCast} from "@uniswap/v4-core/src/libraries/SafeCast.sol";
import {SwapParams} from "@uniswap/v4-core/src/types/PoolOperation.sol";
import {CurrencySettler} from "@uniswap/v4-core/test/utils/CurrencySettler.sol";
import {TickMath} from "@uniswap/v4-core/src/libraries/TickMath.sol";
import {Constants} from "./Constants.sol";

/**
 * @title TaxHook
 * @notice A Uniswap V4 hook that applies configurable taxes on TOKEN/ETH swaps
 * @dev Supports multiple tokens sharing one hook. Always taxes native ETH, not the custom token.
 *      Owner can take a configurable cut of all taxes collected.
 */
contract TaxHook is BaseHook, Ownable, ReentrancyGuard {
    using PoolIdLibrary for PoolKey;
    using SafeCast for uint256;
    using CurrencyLibrary for Currency;

    // Tax rate in basis points (1/100 of a percent)
    // 100 = 1%, 500 = 5%, etc.
    uint16 public constant TAX_RATE_DENOMINATOR = 10000;

    // Flag to tell Uniswap to use the returned fee
    uint24 public constant LP_FEE_OVERRIDE_FLAG = 0x400000; // 23rd bit set

    // Fee override value for zero LP fees
    uint24 public constant FEE_OVERRIDE = LP_FEE_OVERRIDE_FLAG; // 0 fee with override flag

    // Price limit constants for internal token->ETH swaps
    uint160 private constant MAX_PRICE_LIMIT = TickMath.MAX_SQRT_PRICE - 1;
    uint160 private constant MIN_PRICE_LIMIT = TickMath.MIN_SQRT_PRICE + 1;

    /**
     * @notice Override LP fees explanation
     * When returning a fee from beforeSwap:
     * 1. The 23rd bit (0x400000) tells Uniswap to use the returned fee value
     * 2. Setting the value to ZERO_LP_FEE means users pay 0% LP fees
     * 3. Only taxes specified by the hook will be collected
     *
     * This allows tokens to have completely custom fee structures
     * without any of the standard Uniswap LP fees.
     */

    // Owner's cut of all collected taxes (in basis points, e.g., 300 = 3%)
    uint16 public ownerCutBps;

    // Structure to store tax configuration per token
    struct TokenTaxConfig {
        bool enabled; // Whether tax is enabled for this token
        uint16 taxBps; // Total tax rate in basis points
        uint256 collected; // Amount collected for token owner
        uint256 withdrawn; // Amount withdrawn by token owner
        bool exemptFromOwnerCut; // If true, owner gets no cut from this token
        address tokenOwner; // Address that registered and owns this token config
    }

    // Mapping from custom token address to its tax configuration
    mapping(address => TokenTaxConfig) public tokenTaxConfigs;

    // Global owner tax tracking (across all tokens)
    uint256 public ownerTaxCollected;
    uint256 public ownerTaxWithdrawn;

    // Flag to prevent taxing internal swaps (for token->ETH conversions)
    bool private _inInternalSwap;

    // Event emitted when tax is collected
    event TaxCollected(
        PoolId indexed poolId,
        address indexed customToken,
        uint256 totalTaxAmount,
        uint256 ownerCut,
        uint256 tokenWalletCut,
        bool isInflow
    );

    // Event emitted when a token is registered
    event TokenRegistered(
        address indexed customToken, PoolId indexed poolId, uint16 taxBps, address indexed tokenOwner
    );

    // Event emitted when taxes are withdrawn
    event TaxWithdrawn(address indexed beneficiary, uint256 amount, bool isOwnerTax);

    // Event emitted when a token is exempted from owner cut
    event TokenExemptionUpdated(address indexed customToken, bool exempt);

    // Event emitted when token ownership is transferred
    event TokenOwnershipTransferred(
        address indexed customToken, address indexed previousOwner, address indexed newOwner
    );

    constructor(IPoolManager _poolManager, address _owner, uint16 _ownerCutBps) BaseHook(_poolManager) {
        require(_ownerCutBps < TAX_RATE_DENOMINATOR, "TaxHook: Owner cut too high");

        ownerCutBps = _ownerCutBps;

        // Transfer ownership if not deployer
        if (_owner != msg.sender) {
            _transferOwnership(_owner);
        }
    }

    /**
     * @notice Register a token with this tax hook
     * @param customToken The custom token address (not ETH)
     * @param key The pool key for TOKEN/ETH pair
     * @param taxBps Tax rate in basis points
     */
    function registerToken(address customToken, PoolKey calldata key, uint16 taxBps) external {
        require(customToken != address(0), "TaxHook: Invalid custom token");
        require(taxBps <= Constants.MAX_TOKEN_TAX_BPS, "TaxHook: Tax rate exceeds maximum");

        // Verify pool contains native ETH (address(0)) and customToken
        address token0 = Currency.unwrap(key.currency0);
        address token1 = Currency.unwrap(key.currency1);
        require(
            (token0 == address(0) && token1 == customToken) || (token0 == customToken && token1 == address(0)),
            "TaxHook: Pool must be TOKEN/ETH pair"
        );

        // Verify exactly one currency is ETH (Fix #9)
        require(
            (token0 == address(0)) != (token1 == address(0)),
            "TaxHook: Pool must have exactly one native ETH currency"
        );

        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(!config.enabled, "TaxHook: Token already registered");

        config.enabled = true;
        config.taxBps = taxBps;
        config.collected = 0;
        config.withdrawn = 0;
        config.exemptFromOwnerCut = false;
        config.tokenOwner = msg.sender;

        PoolId poolId = key.toId();
        emit TokenRegistered(customToken, poolId, taxBps, msg.sender);
    }

    // ============================================
    // TOKEN OWNER FUNCTIONS
    // ============================================

    /**
     * @notice Transfer ownership of a token registration
     * @param customToken The token to transfer ownership of
     * @param newOwner The new owner address
     */
    function transferTokenOwnership(address customToken, address newOwner) external nonReentrant {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHook: Token not registered");
        require(msg.sender == config.tokenOwner, "TaxHook: Only token owner can transfer");

        // Validation for new owner (Fix #12)
        require(newOwner != address(0), "TaxHook: Cannot transfer to zero address");
        require(newOwner != address(this), "TaxHook: Cannot transfer to hook contract");

        // Auto-withdraw any unclaimed taxes to the current owner before transferring
        uint256 unwithdrawnTax = config.collected - config.withdrawn;
        if (unwithdrawnTax > 0) {
            _withdrawTokenTaxInternal(config, config.tokenOwner, unwithdrawnTax);
        }

        address previousOwner = config.tokenOwner;
        config.tokenOwner = newOwner;

        emit TokenOwnershipTransferred(customToken, previousOwner, newOwner);
    }

    /**
     * @notice Update a token's tax rate (can only decrease, not increase)
     * @param customToken The token to update
     * @param newTaxBps New tax rate in basis points (must be less than or equal to current rate)
     */
    function updateTokenTaxRate(address customToken, uint16 newTaxBps) external {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHook: Token not registered");
        require(msg.sender == config.tokenOwner, "TaxHook: Only token owner can update");
        require(newTaxBps <= config.taxBps, "TaxHook: Can only decrease tax rate");

        config.taxBps = newTaxBps;
    }

    /**
     * @notice Withdraws accumulated token-specific taxes (in native ETH)
     * @param customToken The custom token whose tax to withdraw
     * @param recipient The address to send the withdrawn tax to
     * @param amount The amount to withdraw (0 = withdraw all available)
     * @dev Only callable by the token owner
     */
    function withdrawTokenTax(address customToken, address recipient, uint256 amount) external nonReentrant {
        require(recipient != address(0), "TaxHook: Invalid recipient");

        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHook: Token not registered");
        require(msg.sender == config.tokenOwner, "TaxHook: Only token owner can withdraw");

        uint256 unwithdrawnTotal = config.collected - config.withdrawn;
        require(unwithdrawnTotal > 0, "TaxHook: No taxes to withdraw");

        // Determine actual withdrawal amount (cap to available if needed)
        uint256 actualAmount = (amount == 0) ? unwithdrawnTotal : (amount > unwithdrawnTotal ? unwithdrawnTotal : amount);

        _withdrawTokenTaxInternal(config, recipient, actualAmount);
    }

    // ============================================
    // HOOK OWNER FUNCTIONS
    // ============================================

    /**
     * @notice Exempt a token from owner cut
     * @param customToken The token to exempt
     * @param exempt Whether to exempt the token
     */
    function exemptToken(address customToken, bool exempt) external onlyOwner {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHook: Token not registered");

        config.exemptFromOwnerCut = exempt;
        emit TokenExemptionUpdated(customToken, exempt);
    }

    /**
     * @notice Withdraws accumulated owner taxes (in native ETH)
     * @param amount The amount to withdraw (0 = withdraw all available)
     * @dev Only callable by owner. Withdraws accumulated ETH across all tokens.
     */
    function withdrawOwnerTax(uint256 amount) external onlyOwner nonReentrant {
        // Calculate unwithdrawn amount
        uint256 unwithdrawnTotal = ownerTaxCollected - ownerTaxWithdrawn;
        require(unwithdrawnTotal > 0, "TaxHook: No owner taxes to withdraw");

        // Determine actual withdrawal amount (cap to available if needed)
        uint256 actualAmount = (amount == 0) ? unwithdrawnTotal : (amount > unwithdrawnTotal ? unwithdrawnTotal : amount);

        // Check ETH balance
        uint256 balance = address(this).balance;
        require(balance >= actualAmount, "TaxHook: Insufficient ETH balance");

        // Update withdrawn amount
        ownerTaxWithdrawn += actualAmount;

        // Transfer ETH to owner
        (bool success,) = owner().call{value: actualAmount}("");
        require(success, "TaxHook: ETH transfer failed");

        emit TaxWithdrawn(owner(), actualAmount, true);
    }

    // ============================================
    // HOOK PERMISSIONS & CORE LOGIC
    // ============================================

    /**
     * @notice Define the hook permissions
     * @return Hooks.Permissions The hook's permissions
     */
    function getHookPermissions() public pure override returns (Hooks.Permissions memory) {
        return Hooks.Permissions({
            beforeInitialize: false,
            afterInitialize: false,
            beforeAddLiquidity: false,
            afterAddLiquidity: false,
            beforeRemoveLiquidity: false,
            afterRemoveLiquidity: false,
            beforeSwap: true, // Using beforeSwap to tax inflows
            afterSwap: true, // Using afterSwap to tax outflows
            beforeDonate: false,
            afterDonate: false,
            beforeSwapReturnDelta: true, // Now enabling this to return a delta in beforeSwap
            afterSwapReturnDelta: true, // Now enabling this to return a delta in afterSwap
            afterAddLiquidityReturnDelta: false,
            afterRemoveLiquidityReturnDelta: false
        });
    }

    /**
     * @notice Calculate tax amount based on value and tax rate
     * @param value The value to calculate tax on
     * @param taxRateBps The tax rate in basis points
     * @return taxAmount The calculated tax amount
     */
    function _calculateTax(uint256 value, uint16 taxRateBps) internal pure returns (uint256) {
        return (value * taxRateBps) / TAX_RATE_DENOMINATOR;
    }

    /**
     * @notice Calculate tax breakdown: total, owner cut, and token wallet cut
     * @param amount The amount to calculate tax on
     * @param config The token tax configuration
     * @return totalTaxAmount Total tax to collect
     * @return ownerCut Amount going to hook owner
     * @return tokenWalletCut Amount going to token owner
     */
    function _calculateTaxBreakdown(uint256 amount, TokenTaxConfig storage config)
        internal
        view
        returns (uint256 totalTaxAmount, uint256 ownerCut, uint256 tokenWalletCut)
    {
        totalTaxAmount = _calculateTax(amount, config.taxBps);

        if (totalTaxAmount > 0) {
            ownerCut = 0;
            if (!config.exemptFromOwnerCut && ownerCutBps > 0) {
                ownerCut = _calculateTax(totalTaxAmount, ownerCutBps);
            }
            tokenWalletCut = totalTaxAmount - ownerCut;
        }
    }

    /**
     * @notice Record collected taxes in storage
     * @param customToken The token address
     * @param ownerCut Amount to add to owner's collected taxes
     * @param tokenWalletCut Amount to add to token owner's collected taxes
     */
    function _recordCollectedTax(address customToken, uint256 ownerCut, uint256 tokenWalletCut) internal {
        if (ownerCut > 0) {
            ownerTaxCollected += ownerCut;
        }
        if (tokenWalletCut > 0) {
            tokenTaxConfigs[customToken].collected += tokenWalletCut;
        }
    }

    /**
     * @notice Emit tax collected event
     * @param key The pool key
     * @param customToken The token address
     * @param totalTaxAmount Total tax collected
     * @param ownerCut Amount for hook owner
     * @param tokenWalletCut Amount for token owner
     * @param isInflow Whether this is an inflow (beforeSwap) or outflow (afterSwap)
     */
    function _emitTaxCollectedEvent(
        PoolKey calldata key,
        address customToken,
        uint256 totalTaxAmount,
        uint256 ownerCut,
        uint256 tokenWalletCut,
        bool isInflow
    ) internal {
        PoolId poolId = key.toId();
        emit TaxCollected(poolId, customToken, totalTaxAmount, ownerCut, tokenWalletCut, isInflow);
    }

    /**
     * @notice Swaps tokens to ETH via the pool
     * @dev Used when we need to convert token-denominated tax to ETH
     * @param key The pool key
     * @param tokenAmount Amount of tokens to swap
     * @return ethReceived Amount of ETH received from the swap
     */
    function _swapTokensToEth(PoolKey calldata key, uint256 tokenAmount) internal returns (uint256 ethReceived) {
        uint256 ethBefore = address(this).balance;

        // Set flag to prevent taxing this internal swap
        _inInternalSwap = true;

        // Execute token -> ETH swap (exact input)
        BalanceDelta delta = poolManager.swap(
            key,
            SwapParams({
                zeroForOne: false, // Token (currency1) -> ETH (currency0)
                amountSpecified: -int256(tokenAmount), // Negative = exact input
                sqrtPriceLimitX96: MAX_PRICE_LIMIT
            }),
            bytes("")
        );

        // Manually settle the swap deltas
        Currency ethCurrency = CurrencyLibrary.ADDRESS_ZERO;
        Currency tokenCurrency = key.currency1;

        // Settle token input (negative delta = we owe tokens to pool)
        if (delta.amount1() < 0) {
            CurrencySettler.settle(tokenCurrency, poolManager, address(this), uint256(int256(-delta.amount1())), false);
        }

        // Take ETH output (positive delta = pool owes us ETH)
        if (delta.amount0() > 0) {
            CurrencySettler.take(ethCurrency, poolManager, address(this), uint256(int256(delta.amount0())), false);
        }

        // Clear flag
        _inInternalSwap = false;

        ethReceived = address(this).balance - ethBefore;
    }

    /**
     * @notice Hook called before a swap to tax inflows
     * @dev Handles: Scenario 1 - Exact input swap where ETH is input (buying tokens with exact ETH)
     * @param key The pool key
     * @param params The swap parameters
     * @return selector The function selector
     * @return delta Any delta to apply
     * @return gasLimit The gas limit for the swap
     */
    function _beforeSwap(address, PoolKey calldata key, SwapParams calldata params, bytes calldata)
        internal
        override
        returns (bytes4, BeforeSwapDelta, uint24)
    {
        // Skip taxing internal swaps (prevents recursion when converting token tax to ETH)
        if (_inInternalSwap) {
            return (BaseHook.beforeSwap.selector, BeforeSwapDeltaLibrary.ZERO_DELTA, FEE_OVERRIDE);
        }

        // Initialize with default values
        BeforeSwapDelta deltaOut = BeforeSwapDeltaLibrary.ZERO_DELTA;

        // Identify the custom token (non-ETH token)
        address token0 = Currency.unwrap(key.currency0);
        address token1 = Currency.unwrap(key.currency1);
        address customToken = (token0 == address(0)) ? token1 : token0;

        TokenTaxConfig storage config = tokenTaxConfigs[customToken];

        // Skip if tax is not enabled for this token
        if (!config.enabled) {
            return (BaseHook.beforeSwap.selector, deltaOut, FEE_OVERRIDE);
        }

        // We always tax native ETH
        Currency taxCurrency = CurrencyLibrary.ADDRESS_ZERO;
        bool ethIsToken0 = (token0 == address(0));

        // Determine if ETH is being used as input in this swap
        bool isEthInput = (ethIsToken0 && params.zeroForOne) || (!ethIsToken0 && !params.zeroForOne);

        // Scenario 1: Exact input swap where ETH is input (buying tokens with exact ETH amount)
        // - amountSpecified < 0 (negative indicates exact input in V4)
        // - ETH is the input currency
        if (isEthInput && params.amountSpecified < 0) {
            // Calculate absolute swap amount
            uint256 absAmount = uint256(-params.amountSpecified);

            // Calculate tax breakdown using helper
            (uint256 totalTaxAmount, uint256 ownerCut, uint256 tokenWalletCut) =
                _calculateTaxBreakdown(absAmount, config);

            if (totalTaxAmount > 0) {
                // Record collected taxes first (CEI pattern - Fix #8)
                _recordCollectedTax(customToken, ownerCut, tokenWalletCut);

                // Take the total tax from the pool
                poolManager.take(taxCurrency, address(this), totalTaxAmount);

                // Return a POSITIVE delta to balance out the debt created by take()
                deltaOut = toBeforeSwapDelta(int128(int256(totalTaxAmount)), 0);

                // Emit event using helper
                _emitTaxCollectedEvent(key, customToken, totalTaxAmount, ownerCut, tokenWalletCut, true);
            }
        }

        return (BaseHook.beforeSwap.selector, deltaOut, FEE_OVERRIDE);
    }

    /**
     * @notice Hook called after a swap to tax ETH flows
     * @dev Handles:
     *   - Scenario 2: Exact output swap where ETH is input (buying exact tokens with ETH)
     *   - Scenario 3: Exact input swap where ETH is output (selling exact tokens for ETH)
     *   - Scenario 4: Exact output swap where ETH is output (selling tokens for exact ETH)
     * @param key The pool key
     * @param params The swap parameters
     * @param delta The balance delta from the swap
     * @return selector The function selector
     * @return afterDelta Any additional amount to withdraw
     */
    function _afterSwap(address, PoolKey calldata key, SwapParams calldata params, BalanceDelta delta, bytes calldata)
        internal
        override
        returns (bytes4, int128)
    {
        // Skip taxing internal swaps (prevents recursion when converting token tax to ETH)
        if (_inInternalSwap) {
            return (BaseHook.afterSwap.selector, 0);
        }

        // Default value for afterDelta
        int128 afterDelta = 0;

        // Identify the custom token (non-ETH token)
        address token0 = Currency.unwrap(key.currency0);
        address token1 = Currency.unwrap(key.currency1);
        address customToken = (token0 == address(0)) ? token1 : token0;

        TokenTaxConfig storage config = tokenTaxConfigs[customToken];

        // Skip if tax is not enabled for this token
        if (!config.enabled) {
            return (BaseHook.afterSwap.selector, afterDelta);
        }

        // We always tax native ETH
        Currency taxCurrency = CurrencyLibrary.ADDRESS_ZERO;
        bool ethIsToken0 = (token0 == address(0));

        // Get the ETH delta (amount0 if ETH is token0, otherwise amount1)
        int128 relevantDelta = ethIsToken0 ? delta.amount0() : delta.amount1();

        // Determine swap direction
        bool isEthInput = (ethIsToken0 && params.zeroForOne) || (!ethIsToken0 && !params.zeroForOne);
        bool isEthOutput = !isEthInput;

        // Scenario 2: Exact output swap where ETH is input (buying exact amount of tokens with ETH)
        // - amountSpecified > 0 (positive indicates exact output in V4)
        // - ETH is the input currency
        // - relevantDelta < 0 (ETH flowing INTO the pool, negative delta)
        if (isEthInput && params.amountSpecified > 0 && relevantDelta < 0) {
            // Tax the absolute amount of ETH consumed
            uint256 absAmount = uint256(int256(-relevantDelta));

            // Calculate tax breakdown using helper
            (uint256 totalTaxAmount, uint256 ownerCut, uint256 tokenWalletCut) =
                _calculateTaxBreakdown(absAmount, config);

            if (totalTaxAmount > 0) {
                // Record collected taxes first (CEI pattern - Fix #8)
                _recordCollectedTax(customToken, ownerCut, tokenWalletCut);

                // Take the tax from the pool
                poolManager.take(taxCurrency, address(this), totalTaxAmount);

                // Return a POSITIVE delta to balance out the debt created by take()
                afterDelta = int128(int256(totalTaxAmount));

                // Emit event using helper (isInflow=true because ETH is flowing in)
                _emitTaxCollectedEvent(key, customToken, totalTaxAmount, ownerCut, tokenWalletCut, true);
            }
        }
        // Scenario 3: Exact input sell (selling exact tokens for ETH)
        // - amountSpecified < 0 (negative indicates exact input)
        // - ETH is the output currency
        // - relevantDelta > 0 (ETH flowing OUT of the pool, positive delta)
        else if (isEthOutput && relevantDelta > 0 && params.amountSpecified < 0) {
            // Tax the absolute amount of ETH received
            uint256 absAmount = uint256(int256(relevantDelta));

            // Calculate tax breakdown using helper
            (uint256 totalTaxAmount, uint256 ownerCut, uint256 tokenWalletCut) =
                _calculateTaxBreakdown(absAmount, config);

            if (totalTaxAmount > 0) {
                // Record collected taxes first (CEI pattern - Fix #8)
                _recordCollectedTax(customToken, ownerCut, tokenWalletCut);

                // Take the tax from the pool
                poolManager.take(taxCurrency, address(this), totalTaxAmount);

                // Return a POSITIVE delta to balance out the debt created by take()
                afterDelta = int128(int256(totalTaxAmount));

                // Emit event using helper (isInflow=false because ETH is flowing out)
                _emitTaxCollectedEvent(key, customToken, totalTaxAmount, ownerCut, tokenWalletCut, false);
            }
        }
        // Scenario 4: Exact output sell (selling tokens for exact ETH amount)
        // - amountSpecified > 0 (positive indicates exact output)
        // - ETH is the output currency
        // - relevantDelta > 0 (ETH flowing OUT)
        // - Problem: Can't take more ETH from pool (user specified exact ETH amount)
        // - Solution: Take equivalent token tax and swap to ETH immediately
        else if (isEthOutput && relevantDelta > 0 && params.amountSpecified > 0) {
            // User specified exact ETH output, so we tax the token input instead
            // Get token delta (the amount of tokens user sent)
            int128 tokenDelta = ethIsToken0 ? delta.amount1() : delta.amount0();

            // Token delta should be negative (user sending tokens to pool)
            if (tokenDelta < 0) {
                uint256 tokenAmount = uint256(int256(-tokenDelta));

                // Calculate tax on tokens
                (uint256 totalTokenTax, uint256 ownerCut, uint256 tokenWalletCut) =
                    _calculateTaxBreakdown(tokenAmount, config);

                if (totalTokenTax > 0) {
                    // Note: Scenario 4 requires taking tokens and swapping them before we know the final ETH amount
                    // We cannot follow strict CEI pattern here because state update depends on swap result
                    // The _inInternalSwap flag protects against reentrancy during the swap

                    // Take token tax from pool
                    Currency tokenCurrency = ethIsToken0 ? key.currency1 : key.currency0;
                    poolManager.take(tokenCurrency, address(this), totalTokenTax);

                    // Immediately swap tokens to ETH
                    uint256 ethReceived = _swapTokensToEth(key, totalTokenTax);

                    // Now distribute the ETH received as normal
                    if (ethReceived > 0) {
                        // Recalculate breakdown based on actual ETH received (accounts for slippage)
                        uint256 finalOwnerCut = 0;
                        if (!config.exemptFromOwnerCut && ownerCutBps > 0) {
                            finalOwnerCut = _calculateTax(ethReceived, ownerCutBps);
                        }
                        uint256 finalTokenWalletCut = ethReceived - finalOwnerCut;

                        // Record collected taxes (must be after swap to get correct amounts)
                        _recordCollectedTax(customToken, finalOwnerCut, finalTokenWalletCut);

                        // Emit event
                        _emitTaxCollectedEvent(key, customToken, ethReceived, finalOwnerCut, finalTokenWalletCut, false);

                        // Return token tax amount as delta
                        afterDelta = int128(int256(totalTokenTax));
                    }
                }
            }
        }

        return (BaseHook.afterSwap.selector, afterDelta);
    }

    // Required receive function to handle ETH transfers
    receive() external payable {}

    // ============================================
    // VIEW FUNCTIONS
    // ============================================

    /**
     * @notice Get the owner's global tax info
     * @return collected Total amount of owner tax collected (in native ETH)
     * @return withdrawn Total amount of owner tax withdrawn
     */
    function getOwnerTaxInfo() external view returns (uint256 collected, uint256 withdrawn) {
        return (ownerTaxCollected, ownerTaxWithdrawn);
    }

    /**
     * @notice Get the token-specific tax info
     * @param customToken The custom token address
     * @return collected Amount collected for the token owner (in native ETH)
     * @return withdrawn Amount withdrawn by the token owner
     */
    function getTokenTaxInfo(address customToken) external view returns (uint256 collected, uint256 withdrawn) {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        return (config.collected, config.withdrawn);
    }

    /**
     * @notice Get the owner of a token registration
     * @param customToken The custom token address
     * @return tokenOwner Address that owns this token's configuration
     */
    function getTokenOwner(address customToken) external view returns (address tokenOwner) {
        TokenTaxConfig storage config = tokenTaxConfigs[customToken];
        require(config.enabled, "TaxHook: Token not registered");
        return config.tokenOwner;
    }

    // ============================================
    // INTERNAL HELPER FUNCTIONS
    // ============================================

    /**
     * @notice Internal helper to withdraw token taxes
     * @param config The token tax configuration
     * @param recipient The address to send the withdrawn tax to
     * @param amount The amount to withdraw
     * @dev This function performs the actual withdrawal logic and is called by both
     *      withdrawTokenTax and transferTokenOwnership to avoid code duplication
     */
    function _withdrawTokenTaxInternal(TokenTaxConfig storage config, address recipient, uint256 amount) private {
        // Check ETH balance
        uint256 balance = address(this).balance;
        require(balance >= amount, "TaxHook: Insufficient ETH balance");

        // Update the withdrawn amount
        config.withdrawn += amount;

        // Transfer ETH to recipient
        (bool success,) = recipient.call{value: amount}("");
        require(success, "TaxHook: ETH transfer failed");

        emit TaxWithdrawn(recipient, amount, false);
    }
}
