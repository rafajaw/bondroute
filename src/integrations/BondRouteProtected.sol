// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title BondRouteProtected
 * @notice Single-file MEV protection for smart contracts - just copy and inherit
 *
 * QUICK INTEGRATION:
 * 1. Copy this file to your project
 * 2. Inherit: `contract YourProtocol is BondRouteProtected`
 * 3. Implement two functions:
 *    - `BondRoute_get_protected_selectors()` - which functions are protected
 *    - `BondRoute_get_call_constraints()` - what's required to execute
 * 4. Call `BondRoute_initialize()` at start of protected functions
 * 5. Use `ctx.pull(token, amount)` to pull user funds
 *
 * VALUE:
 * - Prevents up to 5% MEV extraction
 * - Stakes prevent bond farming (main security feature)
 * - Standardized query interface across all protocols
 * - Optional 0.1% tip (vs 1-5% saved from MEV)
 * - Gas efficient: ~45k overhead for full commit-reveal (for context: a single storage write costs 20k)
 * - Chain-wide privacy: bots don't even know which protocol users are interacting with
 *
 * RECOMMENDED TIP MODEL:
 * - Protocols typically share 10% of their fee with BondRoute
 * - Example: 1% protocol fee → keep 0.9%, share 0.1% with BondRoute
 * - BondRoute asks for 0.1% while MEV bots would take up to 5%
 *
 * WHY THIS IS FAIR:
 * - BondRoute is immutable infrastructure (no governance, free public good, optional tips)
 * - Tips sustain SDKs and off-chain tooling protecting users from MEV
 * - Your users get better execution, you get better reputation
 * - Everyone wins except MEV bots
 *
 * EXAMPLE:
 * ```solidity
 * contract XCoin is ERC20, BondRouteProtected {
 *     uint256 public totalDeposits;
 *
 *     constructor() ERC20("XCoin", "XCOIN") BondRouteProtected("XCoin", "Early depositor bonus vault") {}
 *
 *     function deposit( uint256 amount ) external {
 *         BondContext memory ctx = BondRoute_initialize();
 *         ctx.pull( USDC, amount );  // Pulls from user.
 *
 *         uint256 bonus = 1000 - totalDeposits / 1e18;  // Early depositors bonus (1000% → 0%).
 *         uint256 mintAmount = amount * (1000 + bonus) / 1000;
 *
 *         totalDeposits += amount;
 *         _mint( ctx.user, mintAmount );  // Mints to user.
 *     }
 *
 *     function BondRoute_get_protected_selectors() external pure override returns (bytes4[] memory selectors) {
 *         selectors = new bytes4[]( 1 );
 *         selectors[0] = this.deposit.selector;
 *     }
 *
 *     function BondRoute_get_call_constraints( bytes calldata call, IERC20, TokenAmount[] memory )
 *         public pure override returns ( BondConstraints memory constraints )
 *     {
 *         uint256 amount = abi.decode( call[4:], (uint256) );
 *         constraints.min_stake = TokenAmount({ token: USDC, amount: amount / 100 });  // requires at least 1% stake
 *         constraints.min_fundings = new TokenAmount[](1);
 *         constraints.min_fundings[0] = TokenAmount({ token: USDC, amount: amount });
 *     }
 * }
 * ```
 */


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  DATA STRUCTURES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

struct TokenAmount {
    IERC20 token;
    uint256 amount;
}

struct Range {
    uint256 min;
    uint256 max;
}

struct BondContext {
    address user;
    uint256 creation_time;
    uint256 creation_block;
    TokenAmount stake;
    TokenAmount[] fundings;
}

struct BondConstraints {
    TokenAmount min_stake;
    TokenAmount[] min_fundings;
    Range execution_delay;
    Range creation_time;
    Range execution_time;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  ERRORS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

error Unauthorized( address caller, address expected );
error PossiblyBondFarming( string reason, bytes32 additional_info );
error BondCreatedTooEarly( uint256 created_at, uint256 min_creation_time );
error BondCreatedTooLate( uint256 created_at, uint256 max_creation_time );
error InsufficientStake( uint256 provided, uint256 required );
error InvalidStakeToken( address provided, address required );
error InsufficientFunding( address token, uint256 provided, uint256 required );


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  CONFIGURATION
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

address constant BONDROUTE_ADDRESS              =   address(0x0000000000000000000000426F6E64526F7574650000);  // ***TODO*** Set after deployment.
uint256 constant BONDROUTE_DEFAULT_TIP_BPS      =   1000;  // 0.1% tip (10 basis points).

IBondRoute constant BondRoute                   =   IBondRoute(BONDROUTE_ADDRESS);
IERC20 constant NATIVE_TOKEN                    =   IERC20(address(0));

// PossiblyBondFarming reasons - `additional_info` field contains context-specific data:
string constant EXECUTION_TOO_SOON              =   "Execution too soon";              // additional_info: min delay (uint256)
string constant EXECUTION_TOO_LATE              =   "Execution too late";              // additional_info: max delay (uint256)
string constant BEFORE_EXECUTION_WINDOW         =   "Before execution window";         // additional_info: min execution time (uint256)
string constant AFTER_EXECUTION_WINDOW          =   "After execution window";          // additional_info: max execution time (uint256)

uint256 constant WORD_SIZE                      =   32;
uint256 constant CONTEXT_BASE_SIZE              =   8 * WORD_SIZE;  // - offset, user, creation_time, creation_block, stake.token,
                                                                    //   stake.amount, fundings offset, fundings length
uint256 constant TOKEN_AMOUNT_SIZE              =   2 * WORD_SIZE;  // - token, amount


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  INTERFACES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * @title IBondRouteProtected
 * @notice Interface for contracts integrating with BondRoute.
 *
 * @dev ━━━━  SECURITY MODEL — EXECUTION AS COMMITMENT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * BondRoute enforces a single economic invariant:
 *
 *      Creating a bond commits the creator to attempting execution within a bounded execution window,
 *      or to forfeiting stake.
 *
 * Bonds have no cancellation path. Stake is recoverable only through execution attempts.
 *
 * This invariant applies uniformly across protocol actions such as:
 *   swaps, liquidations, claims, mints, auctions, votes.
 *
 *
 * ━━━━  ADVERSARIAL BEHAVIORS ADDRESSED  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * BondRoute does not attempt to infer user intent.
 * Instead, it allows protocols to constrain *when* execution may occur and to attach a cost to abandoning
 * execution.
 *
 * This removes cost-free optionality relied upon by several adversarial strategies, including:
 *
 *   1. SELECTIVE EXECUTION (BOND / OPTION FARMING)
 *      - Creating many bonds with different parameters
 *      - Executing only one or a few
 *      - Allowing the rest to expire without execution
 *
 *   2. FRONTRUNNING / BACKRUNNING
 *      - Pre-creating execution intents
 *      - Observing user transactions or protocol state transitions
 *      - Executing only when execution becomes favorable
 *
 *   3. MULTI-PATH STRATEGIES (including sandwich-style attacks)
 *      - Maintaining multiple execution alternatives
 *        (e.g. prices, sizes, routes, directions)
 *      - Executing only the profitable realizations
 *
 * All of these strategies rely on the same capability:
 *   → abandoning execution paths without paying a proportional cost.
 *
 *
 * ━━━━  CORE INSIGHT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Legitimate users create bonds they expect to execute.
 *
 * Adversarial users may create many bonds with varying parameters,
 * intending from the outset to execute only one or a few and abandon the remainder.
 *
 * BondRoute allows integrators to attach a real economic cost to abandonment.
 *
 *
 * ━━━━  CONCRETE EXAMPLE — SELECTIVE EXECUTION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Consider a blind auction:
 *
 *   - An attacker pre-creates many bonds with increasing bid values
 *   - Only one bid will be competitive after bids are revealed
 *
 * Without execution commitment:
 *   - The attacker executes only the winning bond
 *   - All other bonds are abandoned at no cost
 *
 * With BondRoute:
 *   - Each bond requires a stake (defined by the integrator)
 *   - Stake is recoverable only by executing the bond
 *
 * Result:
 *   - The attacker can still choose which bond to execute
 *   - But abandoning the others carries a proportional economic cost
 *
 * Maintaining many alternative bids therefore becomes economically expensive.
 *
 *
 * ━━━━  HOW STAKE RECOVERY WORKS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Stake recovery is strictly tied to execution attempts.
 *
 * Typical execution outcomes:
 *   - Execution succeeds
 *       → stake is returned
 *
 *   - Execution reverts with a legitimate protocol error
 *       (e.g. slippage, insufficient funds, InsufficientStake)
 *       → stake is returned
 *
 *   - Execution reverts with `PossiblyBondFarming`
 *       → transaction REVERTS, stake remains LOCKED (not immediately forfeited)
 *       → legitimate users can fix the issue and retry within execution window
 *
 *     Common triggers for `PossiblyBondFarming`:
 *       - Execution outside timing constraints (too early, too late, wrong window)
 *       - Transfer failures (insufficient balance, missing approval, transfer hook revert)
 *       - Out of gas conditions (including naked `revert()` with no error data)
 *       - Any condition suggesting selective execution or bond farming
 *
 *     IMPORTANT: `PossiblyBondFarming` reverts the ENTIRE transaction.
 *                Stake is NOT forfeited immediately - it remains locked in the bond.
 *                Legitimate users experiencing issues (low gas, temporary approval issues)
 *                can fix the problem and retry execution within the protocol's execution window.
 *                Only bonds that expire without successful execution forfeit stake permanently.
 *
 *     *WARNING*  Naked `revert()` and out-of-gas produce empty revert data and MUST be avoided.
 *                Always revert with explicit custom errors or revert strings.

 *   - Bond expires without execution
 *       → stake is NOT returned (permanently forfeited)
 *
 * Implication:
 *   Creating N bonds requires either:
 *     - executing N protocol actions, or
 *     - forfeiting stake on the bonds not executed.
 *
 *
 *
 * ━━━━  HOW PROTECTION EMERGES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Protection is fully parameterized by the integrator via `BondRoute_get_call_constraints`.
 *
 * This interface does not mandate any specific validation strategy.
 * Validation is the responsibility of the integrating protocol.
 *
 * A typical integration uses the provided abstract contract `BondRouteProtected`, which:
 *   - fetches execution constraints during execution, and
 *   - validates them against the actual bond context
 *     (creation time, execution time, stake, fundings),
 *   - reverting with either a regular error (stake returned)
 *     or `PossiblyBondFarming` (stake forfeited).
 *
 * Integrators may alternatively implement custom validation logic.
 *
 *
 * Key dimensions commonly used:
 *
 *   1. Execution windows
 *      - Absolute timestamp windows, relative delays, or both
 *      - Defined by the protocol and returned via constraints
 *
 *   2. Per-bond stake requirements
 *      - Amount and token chosen by the integrator
 *
 *   3. Validation behavior
 *      - Execution outside intended constraints SHOULD revert with
 *        `PossiblyBondFarming` to prevent stake recovery
 *
 * By tuning these parameters, integrators can make maintaining many alternative execution paths
 * economically irrational.
 *
 *
 * ━━━━  INTEGRATOR TAKEAWAY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * BondRoute does not restrict execution.
 * It allows integrators to impose cost on *not executing*.
 *
 * By defining execution windows and stake requirements, you can deter frontrunning, selective execution,
 * and multi-path strategies without embedding attack-specific logic.
 *
 *
 * ━━━━  UPGRADES & VERSIONING  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * BondRoute itself is immutable.
 * Protected contracts may upgrade freely.
 *
 * If, at execution time, the called selector is not listed in `BondRoute_get_protected_selectors()`,
 * the bond settles gracefully and the user's stake is returned.
 *
 * This enables:
 *   - Immutable deployments with migration via redeploy
 *   - Proxy-based upgrades with modified constraints
 *   - Temporary pauses by removing selectors
 *
 * Bonds targeting removed selectors fail safely and refund stake.
 */
interface IBondRouteProtected {

    /**
     * @notice Entry point called by BondRoute during bond execution
     * @param call The original function call
     * @param context Bond context (user, stake, fundings, timing)
     * @return output Protocol return data from the protected function
     * @dev SECURITY: Bonds cannot reenter. Overriders do not need reentrancy guards here.
     */
    function BondRoute_entry_point( bytes calldata call, BondContext memory context ) external returns ( bytes memory );

    /**
     * @notice Define execution requirements for a given call
     *
     * @dev ━━━━  CORE RESPONSIBILITY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *
     * This function defines the rules for executing a bond targeting your protocol.
     *
     * It answers three questions:
     *   1. What stake is required to attach cost to abandonment?
     *   2. What funds must the user provide?
     *   3. When is execution intended to occur?
     *
     * This function is commonly used:
     *   - OFF-CHAIN, as a quotation / discovery function for UX
     *   - ON-CHAIN, by protocol validation logic during execution
     *
     * Note:
     *   This interface does not mandate when or how this function is called.
     *   Calling it during execution is a choice made by the protocol implementation
     *   (e.g. via the provided `BondRouteProtected` base contract).
     *
     *
     * ━━━━  PARAMETERS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *
     * @param call Encoded function call (selector + parameters).
     * @dev        Decode using `bytes4(call)` for selector and `abi.decode(call[4:], (...))` for parameters.
     *
     * @param preferred_stake_token User's preferred token for stake (`address(0)` for native).
     * @dev                         Protocols may ignore this and require a specific token.
     *
     * @param preferred_fundings User's preferred fundings, ordered by preference (`address(0)` for native).
     * @dev                      Protocols may honor or ignore.
     *
     *
     * ━━━━  RETURN VALUE: BondConstraints  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *
     * FIELD: min_stake
     *   - Required stake to attach cost to abandonment (`address(0)` for native)
     *   - `amount = 0` indicates no stake requirement
     *   - Stake size is entirely protocol-defined
     *
     * FIELD: min_fundings
     *   - Required fundings the user must provide (`address(0)` for native)
     *   - Max 4 entries, no duplicates
     *   - Empty array = no funding requirement
     *   - All returned entries are required simultaneously
     *
     * FIELD: execution_delay
     *   - Relative delay after bond creation
     *   - Range: (min, max) in seconds
     *   - `(0, 0)` indicates no relative delay constraint
     *
     * FIELD: creation_time
     *   - Absolute creation window
     *   - Range: (min, max) as Unix timestamps (seconds, per EVM `block.timestamp`)
     *   - `(0, 0)` indicates no absolute creation constraint
     *
     * FIELD: execution_time
     *   - Absolute execution window
     *   - Range: (min, max) as Unix timestamps (seconds)
     *   - `(0, 0)` indicates no absolute execution constraint
     *
     *
     * ━━━━  SECURITY NOTES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *
     * - Returning stakeless constraints enables free optionality.
     *   This may be acceptable for some use-cases, but carries no economic deterrence.
     *
     * - Malformed constraints (e.g. duplicate funding tokens, fundings with zero amounts) MUST be avoided as they will 
     *   cause the bond to be deemed invalid during execution (with subsequent staked refunding).
     */
    function BondRoute_get_call_constraints( bytes calldata call, IERC20 preferred_stake_token, TokenAmount[] memory preferred_fundings ) 
    external view returns (BondConstraints memory);

    /**
     * @notice Declare which functions are BondRoute-protected
     * @return selectors Array of function selectors that can be called via bonds
     *
     * @dev Bonds targeting selectors not returned by this function are settled gracefully with stake refunded.
     *
     * This enables:
     *   - Upgradability
     *   - Emergency pauses
     *   - Selector-level access control
     *
     * @dev GAS REQUIREMENT:
     *      Implementations MUST consume below 100,000 gas on all reasonable EVM-compatible chains.
     */
    function BondRoute_get_protected_selectors( ) external pure returns ( bytes4[] memory selectors );

    /**
     * @notice Optional: provide custom EIP-712 types for better wallet UX
     * @param call The encoded function call
     * @return typed_string Complete EIP-712 type definition
     * @return struct_hash Hash of the structured data
     * @return TokenAmount_offset Byte offset where TokenAmount type is defined
     *
     * @dev Return empty values ("", bytes32(0), 0) to use default calldata_hash
     */
    function BondRoute_get_signing_info( bytes calldata call ) external view returns ( string memory typed_string, bytes32 struct_hash, uint256 TokenAmount_offset );
}

interface IBondRoute {
    function announce_protocol( string calldata name, string calldata description ) external;
    function transfer_funding( address to, IERC20 token, uint256 amount, BondContext memory context ) external returns ( uint256 updated_index, uint256 new_available_amount );
    function tip( IERC20 token, uint256 amount, string calldata message ) external payable;
}

interface IERC20 {
    event Transfer( address indexed from, address indexed to, uint256 value );
    event Approval( address indexed owner, address indexed spender, uint256 value );
    function totalSupply( ) external view returns ( uint256 );
    function balanceOf( address account ) external view returns ( uint256 );
    function transfer( address to, uint256 value ) external returns ( bool );
    function allowance( address owner, address spender ) external view returns ( uint256 );
    function approve( address spender, uint256 value ) external returns ( bool );
    function transferFrom( address from, address to, uint256 value ) external returns ( bool );
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  BASE CONTRACT: BondRouteProtected
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * @title BondRouteProtected
 * @notice Abstract base contract for protocols integrating with BondRoute
 *
 * @dev ━━━━  PURPOSE  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * This contract provides a standard integration layer between a protocol
 * and BondRoute’s bond-based execution model.
 *
 * BondRoute interacts with the protocol exclusively via `BondRoute_entry_point`,
 * supplying a fully-typed `BondContext` alongside the user’s intended call.
 *
 * This contract:
 *   - validates execution constraints defined by the protocol
 *   - adapts BondRoute’s clean ABI call into a form consumable by protected functions
 *   - provides helpers for decoding the execution context inside protected logic
 *
 * Integrators are expected to:
 *   - define execution constraints via `BondRoute_get_call_constraints`
 *   - declare which selectors are bond-executable
 *   - optionally override validation, dispatch, or signing UX helpers
 *
 * This base contract provides a conservative default implementation.
 * Final safety properties depend on integrator-defined constraints.
 *
 *
 * @dev ━━━━  TRUST & AUTHORITY MODEL  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * - BondRoute is the only authorized external caller of `BondRoute_entry_point`
 * - Protected functions MUST obtain execution context by calling `BondRoute_initialize`
 * - Direct calls to protected functions (bypassing BondRoute) are rejected
 *
 * Execution context flow:
 *
 *   1. BondRoute calls `BondRoute_entry_point(call, context)`
 *   2. This contract validates constraints using the clean `context`
 *   3. This contract appends the ABI-encoded context to `call`
 *   4. This contract `delegatecall`s into the protected function
 *   5. The protected function calls `BondRoute_initialize()` to recover context
 *
 * `delegatecall` is used so that `msg.sender` remains BondRoute throughout.
 *
 * Stake custody, accounting, and settlement are handled entirely by BondRoute.
 * This contract never transfers stake or funds.
 */
abstract contract BondRouteProtected is IBondRouteProtected {

    using FundingsLib for BondContext;

    /**
     * @notice Optional: announce your protocol on-chain for discoverability
     *
     * @param name Human-readable protocol name (max 64 UTF-8 bytes)
     * @param description Short description (max 280 UTF-8 bytes)
     *
     * @dev Informational only. No effect on execution or security.
     * @dev Passing empty strings ("", "") deploys anonymously.
     * @dev Announcement is performed once at construction time.
     */
    constructor( string memory name, string memory description )
    {
        if(  bytes(name).length > 0  )  BondRoute.announce_protocol( name, description );
    }


    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  REQUIRED OVERRIDES
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * @notice Declare which functions are callable via BondRoute bonds
     *
     * @return selectors Array of function selectors that are protected
     *
     * @dev ONLY selectors returned here may be executed via bonds
     * @dev Bonds targeting other selectors fail gracefully and refund stake
     * @dev This enables selector-level access control, upgrades, and pauses
     *
     * @dev Example:
     *      function BondRoute_get_protected_selectors( ) external pure override returns ( bytes4[] memory selectors )
     *      {
     *          selectors      =  new bytes4[]( 1 );
     *          selectors[ 0 ] =  this.swap.selector;
     *      }
     */
    function BondRoute_get_protected_selectors( )
    external pure virtual returns ( bytes4[] memory selectors );


    /**
     * @notice Define execution constraints for a given call
     *
     * @param call Encoded function selector + arguments of the intended call
     * @param preferred_stake_token User-preferred stake token
     * @param preferred_fundings User-preferred funding set
     *
     * @return constraints Protocol-defined execution requirements
     *
     * @dev This function defines the necessary stake, fundings, and timings to successfully execute a given call
     *
     * It may include:
     *   - required stake (token + amount)
     *   - required fundings
     *   - execution delay after creation
     *   - absolute creation window
     *   - absolute execution window
     *
     * @dev It is mainly used for off-chain discovery and UX.
     * @dev This abstract contract also uses it for on-chain validation during execution.
     *
     * @dev MUST be implemented by integrators.
     *      See IBondRouteProtected for full semantic documentation.
     *
     * @dev Example:
     *      function BondRoute_get_call_constraints( bytes calldata call, IERC20 preferred_stake_token, TokenAmount[] memory preferred_fundings )
     *      public view virtual returns ( BondConstraints memory constraints )
     *      {
     *          if(  bytes4(call) != this.bid.selector  )  revert( "Selector unknown" );
     *          constraints.min_stake  =  TokenAmount({ token: USDC, amount: 10e6 });  // Requires 10 USDC stake.
     *          constraints.execution_delay  =  Range({ min: 0, max: 2 hours });  // Must execute within 2 hours.
     *      }
     */
    function BondRoute_get_call_constraints( bytes calldata call, IERC20 preferred_stake_token, TokenAmount[] memory preferred_fundings )
    public view virtual returns ( BondConstraints memory );


    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  OPTIONAL EXTENSIONS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * @notice Optional: provide EIP-712 signing metadata for improved wallet UX
     *
     * @param call Encoded function call being signed
     *
     * @return typed_string EIP-712 type string (empty = fallback to hash)
     * @return struct_hash Hash of decoded parameters (0 = fallback to hash)
     * @return TokenAmount_offset Byte offset of "TokenAmount" type within `typed_string` for validation
     *
     * @dev This affects signing UX only
     * @dev Does NOT affect execution, validation, or security
     * @dev Override to display human-readable parameters in wallets
     */
    function BondRoute_get_signing_info( bytes calldata call )
    external pure virtual returns ( string memory typed_string, bytes32 struct_hash, uint256 TokenAmount_offset )
    {
        call;  // Silence unused parameter warning.
        return ( "", bytes32(0), 0 );
    }


    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  EXTERNAL ENTRY POINT
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * @notice Entry point invoked by BondRoute during bond execution
     *
     * @param call Encoded selector + arguments of the user-intended function call
     * @param context Execution context supplied by BondRoute
     *
     * @return output Return data of the protected function
     *
     * @dev Default flow:
     *   1. Verify caller is BondRoute
     *   2. Validate execution constraints
     *   3. Append execution context to calldata
     *   4. Delegatecall into the protected function
     *
     * @dev Advanced integrators may override to dispatch directly
     *      to internal functions for gas savings.
     *
     * If overridden, implementations MUST preserve:
     *   - caller authorization
     *   - constraint validation semantics
     */
    function BondRoute_entry_point( bytes calldata call, BondContext memory context ) external virtual override returns ( bytes memory output )
    {
        // *NOTE*  -  Validates early for security and future-proofing. Also checked in `BondRoute_initialize()`.
        if(  msg.sender != address(BondRoute)  )  revert Unauthorized( msg.sender, address(BondRoute) );

        BondRoute_validate( context, call );

        // Encode calldata structure: [ original_call | abi.encode(context) | uint8(fundings.length) ]
        // The 1-byte `fundings.length` trailer allows calculating context_size when decoding.
        bytes memory call_with_appended_context  =  bytes.concat(  call,  abi.encode( context ),  abi.encodePacked( uint8(context.fundings.length) )  );

        // *NOTE*  -  `delegatecall` preserves `msg.sender = BondRoute` for semantic correctness during protected call.
        bool success;
        ( success, output )  =  address(this).delegatecall( call_with_appended_context );
        if(  success == false  )
        {
            assembly ("memory-safe")
            {
                revert( add( output, 0x20 ), mload( output ) )  // Propagate the exact same revert code.
            }
        }
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  CONTEXT INITIALIZATION
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * @notice Recover execution context appended by `BondRoute_entry_point`
     *
     * @return context Decoded `BondContext` struct
     *
     * @dev MUST be called at the beginning of every protected function.
     *
     * @dev SECURITY:
     *      - Validates caller is BondRoute (delegatecall preserves that)
     *      - Provides inherent reentrancy safety
     */
    function BondRoute_initialize( ) internal view virtual returns ( BondContext memory context )
    {
        if(  msg.sender != address(BondRoute)  )  revert Unauthorized( msg.sender, address(BondRoute) );

        // The context is appended to `msg.data` by `BondRoute_entry_point`:  [ original_call | abi.encode(context) | uint8(fundings.length) ]
        uint8 fundings_count  =  uint8( msg.data[ msg.data.length - 1 ] );  // Validated at BondRoute to be 4 max.

        uint256 context_size;
        unchecked {  context_size  =  CONTEXT_BASE_SIZE + ( fundings_count * TOKEN_AMOUNT_SIZE );  }  // *GAS SAVING*  -  Safe constant values and max 4.

        // Extract context bytes from `msg.data` (excluding the trailing `fundings_count` byte).
        uint256 context_end_position    =  msg.data.length - 1;
        uint256 context_start_position  =  context_end_position - context_size;
        bytes calldata context_bytes    =  msg.data[ context_start_position : context_end_position ];

        context  =  abi.decode( context_bytes, (BondContext) );
    }

    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  VALIDATION
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * @notice Validate execution against protocol-defined constraints
     *
     * @param context Execution context supplied by BondRoute
     * @param call Original function call
     *
     * @dev Default behavior:
     *      - fetch constraints at `BondRoute_get_call_constraints()` using actual call, stake and fundings
     *      - validate timing, stake, and funding requirements
     *
     * @dev Integrators may override to:
     *      - implement protocol-specific validation
     *
     * @dev Reverts MUST be used deliberately:
     *      - Legitimate failures → revert with custom error or string → Settles bond and refunds stake
     *      - Suspected bond farming → revert with `PossiblyBondFarming()` → Reverts the entire transaction, 
     *        stake remains locked and execution may be retried.
     */
    function BondRoute_validate( BondContext memory context, bytes calldata call ) internal view virtual
    {
        BondConstraints memory constraints  =  BondRoute_get_call_constraints({
            call:                       call,
            preferred_stake_token:      context.stake.token,
            preferred_fundings:         context.fundings
        });

        _validate_timing( context, constraints );
        _validate_stake( context, constraints );
        _validate_fundings( context, constraints );
    }


    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    //  PRIVATE VALIDATION HELPERS
    // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * @dev Validate creation time, execution delay, and execution window
     *
     * Timing violations that indicate optionality abuse
     * revert with `PossiblyBondFarming` to forfeit stake.
     */
    function _validate_timing( BondContext memory context, BondConstraints memory constraints ) private view
    {
        // Validate bond creation absolute time.
        if(  constraints.creation_time.min > 0  &&  context.creation_time < constraints.creation_time.min  )
        {
            revert BondCreatedTooEarly( context.creation_time, constraints.creation_time.min );
        }
        if(  constraints.creation_time.max > 0  &&  context.creation_time > constraints.creation_time.max  )
        {
            revert BondCreatedTooLate( context.creation_time, constraints.creation_time.max );
        }

        // Validate execution delay after bond creation.
        uint execution_delay;
        unchecked {  execution_delay  =  block.timestamp - context.creation_time;  }
        if(  constraints.execution_delay.min > 0  &&  execution_delay < constraints.execution_delay.min  )
        {
            revert PossiblyBondFarming( EXECUTION_TOO_SOON, bytes32(constraints.execution_delay.min) );
        }
        if(  constraints.execution_delay.max > 0  &&  execution_delay > constraints.execution_delay.max  )
        {
            revert PossiblyBondFarming( EXECUTION_TOO_LATE, bytes32(constraints.execution_delay.max) );
        }

        // Validate bond execution absolute time.
        if(  constraints.execution_time.min > 0  &&  block.timestamp < constraints.execution_time.min  )
        {
            revert PossiblyBondFarming( BEFORE_EXECUTION_WINDOW, bytes32(constraints.execution_time.min) );
        }
        if(  constraints.execution_time.max > 0  &&  block.timestamp > constraints.execution_time.max  )
        {
            revert PossiblyBondFarming( AFTER_EXECUTION_WINDOW, bytes32(constraints.execution_time.max) );
        }
    }

    /**
     * @dev Validate stake token and minimum amount
     */
    function _validate_stake( BondContext memory context, BondConstraints memory constraints ) private pure
    {
        if(  constraints.min_stake.amount > 0  )
        {
            if(  address(context.stake.token) != address(constraints.min_stake.token)  )
            {
                revert InvalidStakeToken( address(context.stake.token), address(constraints.min_stake.token) );
            }
            if(  context.stake.amount < constraints.min_stake.amount  )
            {
                revert InsufficientStake( context.stake.amount, constraints.min_stake.amount );
            }
        }
    }

    /**
     * @dev Validate required funding tokens and minimum amounts
     */
    function _validate_fundings( BondContext memory context, BondConstraints memory constraints ) private pure
    {
        if(  constraints.min_fundings.length == 0  )  return;

        // *NOTE*  -  O(N*M) worst case validation costs ~150 gas (vs sorted O(N+M)), but allows natural ordering
        //            semantics: no sorting bugs for integrators + user preference signaling for protocols.
        unchecked
        {
            for(  uint256 i = 0  ;  i < constraints.min_fundings.length  ;  i++  )
            {
                IERC20 required_token    =  constraints.min_fundings[ i ].token;
                uint256 required_amount  =  constraints.min_fundings[ i ].amount;

                bool found  =  false;

                for(  uint256 j = 0  ;  j < context.fundings.length  ;  j++  )
                {
                    if(  address(context.fundings[ j ].token) == address(required_token)  )
                    {
                        if(  context.fundings[ j ].amount < required_amount  )
                        {
                            revert InsufficientFunding( address(required_token), context.fundings[ j ].amount, required_amount );
                        }
                        found  =  true;
                        break;
                    }
                }

                if(  found == false  )
                {
                    revert InsufficientFunding( address(required_token), 0, required_amount );
                }
            }
        }
    }

}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  HELPER LIBRARY: Convenient funding transfers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * @title FundingsLib
 * @notice Helper library for transferring user funds via BondRoute
 * @dev Usage: `using FundingsLib for BondContext;` then call `ctx.pull(token, amount)` or `ctx.send(token, amount, recipient)`
 */
library FundingsLib {

    /**
     * @notice Send funds from user to recipient
     * @dev `context.fundings` is automatically updated.
     */
    function send( BondContext memory context, IERC20 token, uint256 amount, address to ) internal
    {
        if(  amount == 0  )  return;

        ( uint256 updated_index, uint256 remaining )  =  BondRoute.transfer_funding( to, token, amount, context );
        context.fundings[ updated_index ].amount  =  remaining;
    }

    /// @notice Pull funds to this contract
    function pull( BondContext memory context, IERC20 token, uint256 amount ) internal
    {
        send( context, token, amount, address(this) );
    }
}