// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20 } from "@OpenZeppelin/token/ERC20/IERC20.sol";



/**
 * @notice Token and amount pair for funding and staking operations
 * @dev Used throughout BondRoute for specifying ERC20 token amounts
 */
struct TokenAmount {
    IERC20 token;       // The ERC20 token contract address
    uint256 amount;     // The amount of tokens
}


/**
 * @notice Execution constraints that integrators can define for their protected functions
 * @dev Use zero values for constraints you don't need. All timing constraints are in seconds since Unix epoch.
 */
struct ExecutionConstraints {

    // Bond creation timing constraints
    uint256 min_bond_creation_time;     // Earliest commit time (0 = no constraint)
    uint256 max_bond_creation_time;     // Latest commit time (0 = no constraint) 
    
    // Bond execution timing constraints
    uint256 min_execution_delay;        // Minimum seconds after commit (0 = no constraint)
    uint256 max_execution_delay;        // Maximum seconds after commit (0 = no constraint)
    uint256 min_bond_execution_time;    // Earliest execution time (0 = no constraint)
    uint256 max_bond_execution_time;    // Latest execution time (0 = no constraint)
    
    // Staking requirements
    TokenAmount stake;                  // Required stake for this call (empty = no stake required)

    // Funding requirements
    TokenAmount[] fundings;             // Required fundings (empty = no funding required)
}


/**
 * @notice Execution context passed to BondRoute-protected functions during bond execution
 * @dev Contains all relevant information about the bond and its execution environment.
 *      This context is automatically populated by BondRoute and made available to protected contracts
 *      through the `BondRoute_initialize()` function (or `BondRoute_initialize_without_funds()` for gas optimization).
 */
struct BondRouteContext {
    address user;               // Address of the user who created and owns this bond
    uint40 commit_time;         // Timestamp when the bond was created (commitment phase)
    uint40 commit_block;        // Block number when the bond was created (for time-based validation)
    TokenAmount stake;          // Token and amount staked for this specific call (zero if no stake required)
    TokenAmount[] fundings;     // Array of available funds for pulling or sending (empty if not initialized with funds)
}


// ═══════════════════════════════════════════════════════════════════════════════
//                                  STRING CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

string constant POSSIBLY_OUT_OF_GAS                         =   "Possibly out of gas";
string constant TRANSFER_FAILED                             =   "Transfer failed";

// forge-lint: disable-next-line(unsafe-typecast)
bytes32 constant BONDROUTEPROTECTED_MAGIC_SIGNATURE         =   bytes32( "<~$ BondRouteProtected $~>" );


error Unauthorized( address caller );
error PossiblyBondPicking( string reason );

// ═══════════════════════════════════════════════════════════════════════════════
//                            VALIDATION ERRORS
// ═══════════════════════════════════════════════════════════════════════════════

error BondCreatedTooEarly( uint256 created_at, uint256 min_creation_time );
error BondCreatedTooLate( uint256 created_at, uint256 max_creation_time );
error ExecutionTooSoon( uint256 delay, uint256 min_delay );
error ExecutionTooLate( uint256 delay, uint256 max_delay );
error InsufficientStake( uint256 provided, uint256 required );
error InvalidStakeToken( address provided, address required );
error BeforeExecutionWindow( uint256 current_time, uint256 min_execution_time );
error AfterExecutionWindow( uint256 current_time, uint256 max_execution_time );


/**
 * @title IBondRouteProtected
 * @notice Interface for contracts that integrate with BondRoute MEV protection
 * @dev This interface enables your contract to receive MEV protection from BondRoute.
 *      
 *      Integration Steps:
 *      1. Inherit from `BondRouteProtected` abstract contract
 *      2. Add `onlyBondRoute` modifier to functions you want protected
 *      3. Call `BondRoute_initialize()` at function start
 *      4. Override `BondRoute_get_execution_constraints()` to define your security requirements
 *      5. Use `BondRoute_pull()`, `BondRoute_push()` or `BondRoute_send()` for funding operations
 *      
 *      What You Get:
 *      - Protection from front-running and sandwich attacks
 *      - Cryptographic commit-reveal scheme enforcement
 *      - Customizable timing and staking requirements
 *      - Access to virtual escrow funding system
 *      - Context variables for inter-contract communication
 *      
 *      Important Notes:
 *      - This is NOT part of the main BondRoute contract
 *      - This is a helper interface for integrators to extend from
 *      - BondRoute will call your `BondRoute_entry_point()` during execution
 *      - Your functions become callable only through BondRoute bonds
 */
interface IBondRouteProtected {

    /**
     * @notice Returns the magic signature identifying BondRoute-protected contracts
     * @return _BONDROUTEPROTECTED_MAGIC_SIGNATURE The protocol identification signature
     * @dev Used by BondRoute to verify contract compatibility before calling `BondRoute_entry_point()`.
     *      Must return the exact value `BONDROUTEPROTECTED_MAGIC_SIGNATURE`.
     *      This prevents accidental calls to contracts that happen to have matching function selectors.
     */
    function BondRoute_is_BondRouteProtected( ) external pure returns ( bytes32 _BONDROUTEPROTECTED_MAGIC_SIGNATURE );

    /**
     * @notice Entry point for BondRoute calls with MEV protection
     * @param target_calldata_with_appended_context The target function calldata with encoded context appended
     * @dev Called by BondRoute contract only during bond execution. Validates sender and delegates to target function.
     *      
     *      Context format: `abi.encode(packed_user_and_commit_info, staked_token, staked_amount)`
     *      - `packed_user_and_commit_info`: User address + commit timestamp + commit block number
     *      - `staked_token`: Address of token staked for this bond (zero address if no stake)
     *      - `staked_amount`: Amount of tokens staked (zero if no stake)
     *      
     *      Reverts with error `Unauthorized` if caller is not the BondRoute contract.
     */
    function BondRoute_entry_point( bytes calldata target_calldata_with_appended_context ) external;

    /**
     * @notice Returns the BondRoute execution constraints for a specific function call
     * @param target_calldata The complete calldata including function selector and all parameters
     * @param preferred_stake_token The preferred token to stake for this execution
     * @param preferred_fundings The preferred tokens and amounts funding this execution
     * @return execution_constraints The execution constraints for this call
     * @dev This is the ONLY function you must override when inheriting from `BondRouteProtected`.
     *      
     *      Implementation Guide:
     *      - Decode `target_calldata` to determine which function is being called
     *      - Define your security requirements based on the function and parameters
     *      - Return zero values for constraints you don't need
     *      - Use `preferred_stake_token` and `preferred_fundings` to inform your requirements
     *      
     *      Example Constraints:
     *      - Time restrictions: Trading hours, maintenance windows
     *      - Staking requirements: Minimum stake for high-value operations
     *      - Funding requirements: Specific tokens or amounts needed
     */
    function BondRoute_get_execution_constraints( bytes calldata target_calldata, IERC20 preferred_stake_token, TokenAmount[] memory preferred_fundings ) external view returns ( ExecutionConstraints memory execution_constraints );

}