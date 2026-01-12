// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title BondRouteProtected
 * @notice Single-file binding commitment primitive for smart contracts - just copy and inherit
 *
 * QUICK INTEGRATION:
 * 1. Copy this file to your project
 * 2. Inherit: `contract YourProtocol is BondRouteProtected`
 * 3. Implement two functions:
 *    - `BondRoute_get_protected_selectors()` - which functions are protected
 *    - `BondRoute_quote_call()` - what's required to execute
 * 4. Call `BondRoute_initialize()` at start of protected functions
 * 5. Use `ctx.pull(token, amount)` to pull user funds
 *
 * WHAT IT DOES:
 * - Makes user commitments binding (commit-reveal with stakes)
 * - Users must execute or forfeit stake — no free optionality
 *
 * WHY IT MATTERS:
 * - MEV protection: hidden intent prevents frontrunning
 * - Credible coordination: votes, bids, claims can't be strategically abandoned
 * - Standardized query interface across all protocols
 *
 * EXAMPLE:
 * ```solidity
 * string constant PROTOCOL_NAME         =  "YourToken";
 * string constant PROTOCOL_DESCRIPTION  =  "Early depositor bonus mints";
 * IERC20 constant DEPOSIT_TOKEN         =  NATIVE_TOKEN;  // Could be native like ETH or any ERC20 token address.
 *
 * contract YourToken is ERC20, BondRouteProtected {
 *     using FundingsLib for BondContext;
 *
 *     uint256 private _total_deposits;
 *
 *     constructor() ERC20( PROTOCOL_NAME, "TOKEN" ) BondRouteProtected( PROTOCOL_NAME, PROTOCOL_DESCRIPTION ) {}
 *
 *     function deposit( ) external {
 *         BondContext memory ctx = BondRoute_initialize();
 *         uint256 amount = ctx.fundings[0].amount;
 *         ctx.pull( DEPOSIT_TOKEN, amount );
 *
 *         // Early depositors get 2x tokens. Decreases to 1x after 100 ETH total.
 *         uint256 multiplier  =  _total_deposits < 100 ether  ?  2  :  1;
 *         uint256 mint_amount  =  amount * multiplier;
 *
 *         _total_deposits += amount;
 *         _mint( ctx.user, mint_amount );
 *     }
 *
 *     function BondRoute_get_protected_selectors() external pure override returns (bytes4[] memory selectors) {
 *         selectors = new bytes4[](1);
 *         selectors[0] = this.deposit.selector;
 *     }
 *
 *     function BondRoute_quote_call( bytes calldata call, IERC20, TokenAmount[] memory preferred_fundings )
 *     public pure override returns ( BondConstraints memory constraints ) {
 *         if( bytes4(call) != this.deposit.selector ) revert( "Unknown selector" );
 *
 *         uint256 amount = preferred_fundings[0].amount;
 *         constraints.min_stake = TokenAmount({ token: DEPOSIT_TOKEN, amount: amount / 100 });  // 1% stake.
 *         constraints.min_fundings = new TokenAmount[](1);
 *         constraints.min_fundings[0] = TokenAmount({ token: DEPOSIT_TOKEN, amount: amount });
 *         constraints.min_execution_delay_in_blocks = amount >= 10 ether  ?  3  :  2;  // Reorg protection scales with value.
 *         constraints.max_execution_delay_in_seconds = 2 hours;  // Sensible security/UX balance.
 *     }
 * }
 * ```
 *
 * OPTIONAL AIRDROPS & COLLECTOR:
 *
 * BondRoute is immutable infrastructure — no governance, no fees, no rent extraction.
 *
 * The core exposes two optional entrypoints for protocol-initiated airdrops:
 * - airdrop(token, amount, message) — for sending existing balances
 * - notify_protocol_airdrop(amount, message) — for tokens minted directly to BondRoute (caller IS the token)
 *
 * These calls are entirely optional and do not change how bonds are created, executed or settled.
 * Integrators can treat them as one-way contributions into the BondRoute ecosystem.
 *
 * Many protocols already reserve a portion of their token supply for airdrops or ecosystem incentives.
 * If desired, a slice of that allocation can be routed through BondRoute instead of (or in addition to)
 * direct address-based distributions.
 *
 * A typical pattern from a token contract is:
 *
 * _mint( address(BondRoute), airdrop_amount );
 * BondRoute.notify_protocol_airdrop( airdrop_amount, bytes32("YourProtocol") );
 *
 * For external ERC20 balances, use the BondRoute_airdrop() helper defined in this file, which
 * handles both native and ERC20 tokens:
 *
 * BondRoute_airdrop( IERC20(address(this)), airdrop_amount, "YourProtocol" );
 *
 * Each airdrop can include a short message string. Tooling can index these messages together with
 * on-chain metadata to provide discoverability for participating protocols (for example, listing
 * new protocols, version upgrades, or campaigns to users already familiar with BondRoute).
 * BondRoute itself does not interpret or enforce any semantics around these messages.
 *
 * Internally, a dedicated collector address is allowed to claim:
 * - forfeited stakes from expired bonds, and
 * - tokens credited via `airdrop()` / `notify_protocol_airdrop()`.
 *
 * The collector is set once at BondRoute deployment and can later be transferred to a different
 * address. It can be a simple EOA, a multisig, or a more complex distribution contract (for example,
 * a MasterChef-style rewards or staking contract that redistributes value to its participants).
 *
 * This design enables protocols to airdrop once to BondRoute and let the collector contract handle
 * fan-out to an actively staked user set, which can be more gas-efficient and less sybil-prone than
 * direct airdrops to large, static address lists. BondRoute core does not prescribe any particular
 * collector design and does not rely on airdrops or forfeited stakes for its security properties.
 * From an integrator's perspective, airdrops are optional and orthogonal to the binding-commitment
 * primitive.
 */


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  DATA STRUCTURES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
    TokenAmount stake;
    TokenAmount[] fundings;
    uint256 creation_block;
    uint256 creation_timestamp;
}

struct BondConstraints {
    TokenAmount min_stake;
    TokenAmount[] min_fundings;
    uint256 min_execution_delay_in_blocks;        // BondRoute enforces 1 - can require more to deter chain reorgs.
    uint256 max_execution_delay_in_seconds;       // Constrains sitting on a bond for opportunistic execution.
    Range valid_creation_timestamp_range;
    Range valid_execution_timestamp_range;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  INTERFACES
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
/**
 * @title IBondRouteProtected
 * @notice Interface for contracts integrating with BondRoute.
 *
 * @dev ━━━━  SECURITY MODEL — EXECUTION AS COMMITMENT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
 * ━━━━  ADVERSARIAL BEHAVIORS ADDRESSED  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * BondRoute does not attempt to infer user intent.
 * Instead, it allows protocols to constrain *when* execution may occur and to attach a cost to abandoning
 * execution.
 *
 * This removes underpriced optionality relied upon by several adversarial strategies, including:
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
 * ━━━━  CORE INSIGHT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Legitimate users create bonds they expect to execute.
 *
 * Adversarial users may create many bonds with varying parameters,
 * intending from the outset to execute only one or a few and abandon the remainder.
 *
 * BondRoute allows integrators to attach a real economic cost to abandonment.
 *
 *
 * ━━━━  CONCRETE EXAMPLE — SELECTIVE EXECUTION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
 * ━━━━  HOW STAKE RECOVERY WORKS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
 *       → transaction REVERTS, stake remains LOCKED
 *       → legitimate users can fix the issue and retry within execution window
 *
 *     Common triggers for `PossiblyBondFarming`:
 *       - Execution outside timing constraints (too early, too late, wrong window)
 *       - Transfer failures (insufficient balance, missing approval)
 *       - Transaction sent with not enough gas
 *       - Any condition suggesting selective execution or bond farming
 *
 *     IMPORTANT: `PossiblyBondFarming` reverts the ENTIRE transaction.
 *                Stake remains locked in the bond.
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
 * ━━━━  HOW PROTECTION EMERGES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Protection is fully parameterized by the integrator via `BondRoute_quote_call`.
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
 * ━━━━  INTEGRATOR TAKEAWAY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * BondRoute enables integrators to impose cost on *not executing*.
 *
 * By defining execution windows and stake requirements, you can deter frontrunning, selective execution,
 * and multi-path strategies without embedding attack-specific logic.
 *
 *
 * ━━━━  REENTRANCY PROTECTION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * Protected functions are inherently reentrancy-safe.
 *
 * BondRoute holds a global lock during bond execution. Protected functions cannot be reentered via other
 * bonds within the same transaction. Integrators do not need to add their own reentrancy guards.
 *
 *
 * ━━━━  UPGRADES & VERSIONING  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 *
 * BondRoute itself is immutable.
 * Protected contracts may upgrade freely.
 *
 * If, at execution time, `BondRoute_get_protected_selectors()` doesn't return a valid array containing the called selector,
 * the bond settles gracefully and the user's stake is returned.
 *
 * To deprecate, pause, or migrate a function: ensure it is not returned by `BondRoute_get_protected_selectors()`.
 *
 * Bonds targeting removed selectors fail safely and refund stake.
 */
interface IBondRouteProtected {

    /**
     * @notice Entry point called by BondRoute during bond execution
     * @param call The original function call (4-byte selector + ABI-encoded arguments)
     * @param context Bond context (user, stake, fundings, timing)
     * @return output Protocol return data from the protected function
     * @dev SECURITY: Bonds cannot reenter. Overriders do not need reentrancy guards here.
     */
    function BondRoute_entry_point( bytes calldata call, BondContext memory context )
    external returns ( bytes memory );

    /**
     * @notice Define requirements for a given call
     *
     * @dev ━━━━  CORE RESPONSIBILITY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
     * ━━━━  PARAMETERS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
     * ━━━━  RETURN VALUE: BondConstraints  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
     * FIELD: min_execution_delay_in_blocks
     *   - Minimum blocks from creation before execution allowed (reorg protection)
     *   - BondRoute enforces 1 block minimum; use this to require more
     *
     * FIELD: max_execution_delay_in_seconds
     *   - Maximum seconds from creation to execute (constrains opportunistic execution)
     *   - BondRoute enforces 111 days maximum; use this to require less
     *
     * FIELD: valid_creation_timestamp_range
     *   - Absolute creation window
     *   - Range: (min, max) as Unix timestamps (seconds, per EVM `block.timestamp`)
     *   - `(0, 0)` indicates no absolute creation constraint
     *
     * FIELD: valid_execution_timestamp_range
     *   - Absolute execution window
     *   - Range: (min, max) as Unix timestamps (seconds, per EVM `block.timestamp`)
     *   - `(0, 0)` indicates no absolute execution constraint
     *
     *
     * ━━━━  SECURITY NOTES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     *
     * - Returning stakeless constraints enables underpriced optionality.
     *   This may be acceptable for some use-cases, but carries no economic deterrence.
     *
     * - Malformed constraints (e.g. duplicate funding tokens, fundings with zero amounts) MUST be avoided as they will 
     *   cause the bond to be deemed invalid during execution (with subsequent staked refunding).
     */
    function BondRoute_quote_call( bytes calldata call, IERC20 preferred_stake_token, TokenAmount[] memory preferred_fundings ) 
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
    function BondRoute_get_protected_selectors( )
    external pure returns ( bytes4[] memory selectors );

    /**
     * @notice Optional: provide custom EIP-712 types for better wallet UX
     * @param call The encoded function call
     * @return typed_string Complete EIP-712 type definition
     * @return struct_hash Hash of the structured data
     * @return TokenAmount_offset Byte offset where TokenAmount type is defined
     *
     * @dev Return empty values ("", bytes32(0), 0) to use default calldata_hash
     */
    function BondRoute_get_signing_info( bytes calldata call )
    external view returns ( string memory typed_string, bytes32 struct_hash, uint256 TokenAmount_offset );
}

interface IBondRoute {
    function announce_protocol( string calldata name, string calldata description ) external;
    function transfer_funding( address to, IERC20 token, uint256 amount, BondContext memory context ) external returns ( uint256 updated_index, uint256 new_available_amount );
    function airdrop( IERC20 token, uint256 amount, string calldata message ) external payable;
    function notify_protocol_airdrop( uint256 amount, bytes32 message ) external;
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


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  BASE CONTRACT: BondRouteProtected
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


// ━━━━  ERRORS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

error Unauthorized( address caller, address expected );
error BondCreatedTooEarly( uint256 created_at, uint256 min_creation_time );
error BondCreatedTooLate( uint256 created_at, uint256 max_creation_time );
error InsufficientStake( uint256 provided, uint256 required );
error InvalidStakeToken( address provided, address required );
error InsufficientFunding( address token, uint256 provided, uint256 required );
error PossiblyBondFarming( string reason, bytes32 additional_info );

// PossiblyBondFarming reasons - `additional_info` field contains context-specific data:
string constant EXECUTION_TOO_SOON              =   "Execution too soon";              // additional_info: min delay (uint256)
string constant EXECUTION_TOO_LATE              =   "Execution too late";              // additional_info: max delay (uint256)
string constant BEFORE_EXECUTION_WINDOW         =   "Before execution window";         // additional_info: min execution time (uint256)
string constant AFTER_EXECUTION_WINDOW          =   "After execution window";          // additional_info: max execution time (uint256)


// ━━━━  CONSTANTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

address constant BONDROUTE_ADDRESS              =   address(0x0000000000000000000000426F6E64526F7574650000);  // ***TODO*** Set after deployment.
IBondRoute constant BondRoute                   =   IBondRoute(BONDROUTE_ADDRESS);
IERC20 constant NATIVE_TOKEN                    =   IERC20(address(0));

uint256 constant WORD_SIZE                      =   32;
uint256 constant CONTEXT_BASE_SIZE              =   8 * WORD_SIZE;  // - offset, user, creation_time, creation_block, stake.token,
                                                                    //   stake.amount, fundings offset, fundings length
uint256 constant TOKEN_AMOUNT_SIZE              =   2 * WORD_SIZE;  // - token, amount


/**
 * @title BondRouteProtected
 * @notice Abstract base contract for protocols integrating with BondRoute
 *
 * @dev ━━━━  PURPOSE  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
 *   - define execution constraints via `BondRoute_quote_call`
 *   - declare which selectors are bond-executable
 *   - optionally override validation, dispatch, or signing UX helpers
 *
 * This base contract provides a conservative default implementation.
 * Final safety properties depend on integrator-defined constraints.
 *
 *
 * @dev ━━━━  TRUST & AUTHORITY MODEL  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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


    // ━━━━  REQUIRED OVERRIDES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
     *   - minimum blocks to execute (reorg protection)
     *   - maximum seconds to execute (bounds optionality)
     *   - absolute creation timestamp range
     *   - absolute execution timestamp range
     *
     * @dev It is mainly used for off-chain discovery and UX.
     * @dev This abstract contract also uses it for on-chain validation during execution.
     *
     * @dev MUST be implemented by integrators.
     *      See IBondRouteProtected for full semantic documentation.
     *
     * @dev Example:
     *      function BondRoute_quote_call( bytes calldata call, IERC20 preferred_stake_token, TokenAmount[] memory preferred_fundings )
     *      public view virtual returns ( BondConstraints memory constraints )
     *      {
     *          if(  bytes4(call) != this.bid.selector  )  revert( "Selector unknown" );
     *          constraints.min_stake  =  TokenAmount({ token: USDC, amount: 10e6 });  // Requires 10 USDC stake.
     *          constraints.max_execution_delay_in_seconds = 2 hours;
     *      }
     */
    function BondRoute_quote_call( bytes calldata call, IERC20 preferred_stake_token, TokenAmount[] memory preferred_fundings )
    public view virtual returns ( BondConstraints memory );


    // ━━━━  OPTIONAL EXTENSIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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


    // ━━━━  DEFAULT IMPLEMENTATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
    function BondRoute_entry_point( bytes calldata call, BondContext memory context )
    external virtual override returns ( bytes memory output )
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

        // *NOTE*  -  Return raw bytes in both cases (no ABI wrapping). Core.sol handles both symmetrically.
        assembly ("memory-safe")
        {
            if success { return( add( output, 0x20 ), mload( output ) ) }
            revert( add( output, 0x20 ), mload( output ) )
        }
    }

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

        uint context_size;
        unchecked {  context_size  =  CONTEXT_BASE_SIZE + ( fundings_count * TOKEN_AMOUNT_SIZE );  }  // *GAS SAVING*  -  Safe constant values and max 4.

        // Extract context bytes from `msg.data` (excluding the trailing `fundings_count` byte).
        uint context_end_position    =  msg.data.length - 1;
        uint context_start_position  =  context_end_position - context_size;
        bytes calldata context_bytes    =  msg.data[ context_start_position : context_end_position ];

        context  =  abi.decode( context_bytes, (BondContext) );
    }

    /**
     * @notice Validate execution against protocol-defined constraints
     *
     * @param context Execution context supplied by BondRoute
     * @param call Original function call
     *
     * @dev Default behavior:
     *      - fetch constraints at `BondRoute_quote_call()` using actual call, stake and fundings
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
        BondConstraints memory constraints  =  BondRoute_quote_call({
            call:                       call,
            preferred_stake_token:      context.stake.token,
            preferred_fundings:         context.fundings
        });

        _validate_timing( context, constraints );
        _validate_stake( context, constraints );
        _validate_fundings( context, constraints );
    }

    /**
     * @notice Helper to send an optional airdrop / contribution to BondRoute
     * @param token Token to send (NATIVE_TOKEN for native ETH)
     * @param amount Amount to send
     * @param message Optional message for on-chain discoverability (max 280 bytes)
     * @dev Entirely voluntary and orthogonal to bond execution. For protocol tokens,
     * minting directly to BondRoute and calling `notify_protocol_airdrop()` is usually
     * more gas-efficient than using this helper.
     */
    function BondRoute_airdrop( IERC20 token, uint256 amount, string memory message ) internal
    {
        if(  amount == 0  )  return;
        if(  address(token) == address(NATIVE_TOKEN)  )
        {
            BondRoute.airdrop{ value: amount }( token, amount, message );
        }
        else
        {
            token.approve( address(BondRoute), amount );
            BondRoute.airdrop( token, amount, message );
        }
    }


    // ━━━━  PRIVATE VALIDATION HELPERS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * @dev Validate creation time, execution delay, and execution window
     *
     * Timing violations that indicate optionality abuse
     * revert with `PossiblyBondFarming` to forfeit stake.
     */
    function _validate_timing( BondContext memory context, BondConstraints memory constraints ) private view
    {
        // Validate bond creation absolute timestamp range.
        if(  constraints.valid_creation_timestamp_range.min > 0  &&  context.creation_timestamp < constraints.valid_creation_timestamp_range.min  )
        {
            revert BondCreatedTooEarly( context.creation_timestamp, constraints.valid_creation_timestamp_range.min );
        }
        if(  constraints.valid_creation_timestamp_range.max > 0  &&  context.creation_timestamp > constraints.valid_creation_timestamp_range.max  )
        {
            revert BondCreatedTooLate( context.creation_timestamp, constraints.valid_creation_timestamp_range.max );
        }

        // Validate minimum blocks elapsed since creation (reorg protection).
        if(  constraints.min_execution_delay_in_blocks > 0  )
        {
            uint blocks_elapsed;
            unchecked {  blocks_elapsed  =  block.number - context.creation_block;  }
            if(  blocks_elapsed < constraints.min_execution_delay_in_blocks  )
            {
                revert PossiblyBondFarming( EXECUTION_TOO_SOON, bytes32(constraints.min_execution_delay_in_blocks) );
            }
        }

        // Validate maximum seconds elapsed since creation (constrains opportunistic execution).
        if(  constraints.max_execution_delay_in_seconds > 0  )
        {
            uint seconds_elapsed;
            unchecked {  seconds_elapsed  =  block.timestamp - context.creation_timestamp;  }
            if(  seconds_elapsed > constraints.max_execution_delay_in_seconds  )
            {
                revert PossiblyBondFarming( EXECUTION_TOO_LATE, bytes32(constraints.max_execution_delay_in_seconds) );
            }
        }

        // Validate bond execution absolute timestamp range.
        if(  constraints.valid_execution_timestamp_range.min > 0  &&  block.timestamp < constraints.valid_execution_timestamp_range.min  )
        {
            revert PossiblyBondFarming( BEFORE_EXECUTION_WINDOW, bytes32(constraints.valid_execution_timestamp_range.min) );
        }
        if(  constraints.valid_execution_timestamp_range.max > 0  &&  block.timestamp > constraints.valid_execution_timestamp_range.max  )
        {
            revert PossiblyBondFarming( AFTER_EXECUTION_WINDOW, bytes32(constraints.valid_execution_timestamp_range.max) );
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
            for(  uint i = 0  ;  i < constraints.min_fundings.length  ;  i++  )
            {
                IERC20 required_token    =  constraints.min_fundings[ i ].token;
                uint256 required_amount  =  constraints.min_fundings[ i ].amount;

                bool found  =  false;

                for(  uint j = 0  ;  j < context.fundings.length  ;  j++  )
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


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  HELPER LIBRARY: Convenient funding transfers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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