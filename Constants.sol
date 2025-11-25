// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/**
 * @title Constants
 * @notice Shared constants used across the Token Index Fund Protocol
 */
library Constants {
    /// @notice Maximum deposit or redemption fee (5%)
    uint256 internal constant MAX_FEE_BPS = 500;

    /// @notice Default deposit fee (2%)
    uint256 internal constant DEFAULT_DEPOSIT_FEE_BPS = 200;

    /// @notice Default redemption fee (2%)
    uint256 internal constant DEFAULT_REDEMPTION_FEE_BPS = 200;

    /// @notice Default maximum price impact per trade (5%)
    uint256 internal constant DEFAULT_MAX_PRICE_IMPACT_BPS = 500;

    /// @notice Oracle staleness threshold (1 hour)
    uint256 internal constant ORACLE_STALE_THRESHOLD = 1 hours;

    /// @notice Basis points denominator
    uint256 internal constant BPS_DENOMINATOR = 10_000;

    /// @notice Price scaling factor (1e18)
    uint256 internal constant PRICE_SCALE = 1e18;

    /// @notice Participation token decimals
    uint8 internal constant PARTICIPATION_TOKEN_DECIMALS = 18;

    /// @notice Minimum deposit amount (0.05 ETH)
    uint256 internal constant DEFAULT_MIN_DEPOSIT_AMOUNT = 0.05 ether;

    /// @notice Minimum redemption value (0.05 ETH)
    uint256 internal constant DEFAULT_MIN_REDEMPTION_VALUE = 0.05 ether;

    /// @notice Minimum token weight (5% of fund), or 0% to remove token from fund
    /// @dev Combined with minimum deposit (0.05 ETH), ensures minimum allocation of 0.0025 ETH per token
    /// @dev This eliminates dust trades without requiring code-level checks
    uint256 internal constant MIN_TOKEN_WEIGHT_BPS = 500;

    /// @notice Maximum number of tokens in a fund
    uint256 internal constant MAX_TOKENS = 10;

    /// @notice The ratio of participation tokens minted per 1 ETH during seeding
    /// @dev 1 ETH = 100,000 participation tokens (initial share price of 0.00001 ETH per token)
    uint256 internal constant SHARES_PER_ETH = 100_000;

    /// @notice Default tax rate for ParticipationToken V4 trading (5%)
    uint256 internal constant DEFAULT_PARTICIPATION_TAX_RATE_BPS = 500;

    /// @notice Default owner cut for TaxHook (5%)
    uint256 internal constant DEFAULT_HOOK_OWNER_CUT_BPS = 500;

    /// @notice Maximum token tax rate (10%)
    uint256 internal constant MAX_TOKEN_TAX_BPS = 1000;

    /// @notice Maximum tax rate for increases after initial registration (20%)
    /// @dev Token owners can decrease tax to any level, but increases are capped here
    uint256 internal constant MAX_TAX_INCREASE_BPS = 2000;

    /// @notice Maximum owner cut for TaxHook (20%)
    /// @dev Owner cut can be adjusted but never exceed this cap
    uint256 internal constant MAX_OWNER_CUT_BPS = 2000;

    /// @notice Flywheel team share (20%)
    uint256 internal constant FLYWHEEL_TEAM_SHARE_BPS = 2000;

    /// @notice Flywheel execution threshold (0.5 ETH)
    uint256 internal constant FLYWHEEL_TRIGGER_THRESHOLD = 0.5 ether;

    /// @notice Universal Router command for V2 exact input swap
    bytes1 internal constant V2_SWAP_EXACT_IN = 0x08;

    /// @notice Universal Router command for V3 exact input swap
    bytes1 internal constant V3_SWAP_EXACT_IN = 0x00;

    /// @notice PERMIT2 contract address (same across all networks)
    address internal constant PERMIT2 = 0x000000000022D473030F116dDEE9F6B43aC78BA3;
}
