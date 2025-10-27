// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { TokenAmount, IBondRouteProtected } from "../integrations/IBondRouteProtected.sol";


// ═══════════════════════════════════════════════════════════════════════════════
//                              STRING CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

string constant COMMITMENT_PROOF_PARAM                      =   "commitment_proof";
string constant STAKE_AMOUNT                                =   "Stake amount";
string constant DUPLICATE_STAKE_TOKEN                       =   "Duplicate stake token";
string constant INVALID_CONTRACT_ADDRESS                    =   "Invalid contract address";
string constant CANT_CALL_ENTRY_POINT                       =   "Calling BondRoute_entry_point";
string constant OUT_OF_GAS_OR_UNSPECIFIED_FAILURE           =   "Out of gas or unspecified failure";
string constant OUT_OF_GAS_OR_NOT_BONDROUTEPROTECTED        =   "Out of gas or not BondRouteProtected";


// ═══════════════════════════════════════════════════════════════════════════════
//                                    EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// @dev Event fields are minimal and non `indexed` bc it is disproportionally cheaper to filter off-chain than to charge gas on every transaction.
event BondCreated( uint64 bond_id, bytes21 commitment_proof, uint256 count_of_staked_tokens );
event BondExecuted( uint64 bond_id, address user );
event BondExecutionCallFailed( uint64 bond_id, uint256 call_index, bytes call_output );
event BondExecutionInsufficientStake( uint64 bond_id, address failing_token );


// ═══════════════════════════════════════════════════════════════════════════════
//                                    ERRORS  
// ═══════════════════════════════════════════════════════════════════════════════

error Invalid( string parameter_name, uint256 value );
error TooManyStakes( uint256 provided, uint256 allowed );
error BondNotFound( uint256 bond_id );
error BondCreationPastDeadline( uint256 creation_deadline );
error InvalidSignature( uint256 bond_id );
error SameBlockExecute( uint256 bond_id );
error BondExpired( uint256 bond_id, uint256 execution_deadline );
error CommitmentProofMismatch( uint256 bond_id, bytes32 expected, bytes32 calculated );
error BondExecutionForbiddenCall( uint256 bond_id, uint256 call_index, string reason );


// ═══════════════════════════════════════════════════════════════════════════════
//                                    STRUCTS
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * @notice Bond storage structure for multistake per call architecture
 * @dev Contains bond metadata.
 */
struct Bond {                           // *GAS SAVING*  -  The bond struct occupies only a single slot (except the actual stake data).
    bytes21 commitment_proof;           // 21 bytes - Hash binding user to specific execution data (2^84 collision resistance - secure for 101-day bond window)
    uint40 created_at_timestamp;        // 5 bytes - Block timestamp when bond was created (until year 36,812)
    uint40 created_at_block_number;     // 5 bytes - Block number when bond was created (1.1T blocks - handles fastest chains)
    uint8 count_of_staked_tokens;       // 1 byte - Total count of staked tokens for this bond (max 255 different tokens)
}

/**
 * @notice Contract call specification for bond execution
 * @dev Defines a single protected contract call within the calls array
 */
struct CallEntry {
    IBondRouteProtected _contract;      // The BondRoute-protected contract to call
    bytes _calldata;                    // The complete calldata including function selector and parameters
    TokenAmount stake;                  // Required stake for this specific call (token and amount)
}

/**
 * @notice Execution data for bond reveal
 * @dev Field order optimized for wallet signing UX:
 *      1. User sees capital commitment first (fundings)
 *      2. Then operations to execute (calls)
 *      3. Finally privacy/security (secret)
 */
struct ExecutionData {
    TokenAmount[] fundings;     // Capital commitment (can be empty)
    CallEntry[] calls;          // Operations to execute atomically
    bytes32 secret;             // Anti-bruteforce salt
}


/**
 * @title IUser
 * @notice Interface for EOAs and smart wallets creating and executing bonds
 * @dev This interface covers the complete bond lifecycle for end users.
 *      
 *      Bond Lifecycle:
 *      1. Create bond with commitment proof (optionally with token stake)
 *      2. Wait for any required delay period
 *      3. Execute bond by revealing commitment data and calling protected contracts
 *      4. Protected contracts receive context and can pull/push/send funds
 *      5. All remaining funds and unused stake are sent to user automatically
 *      
 *      Capital Efficiency:
 *      BondRoute automatically optimizes capital usage when stake token matches funding token.
 *      
 *      Example: User stakes 100 USDC and funding requires 1000 USDC
 *      - BondRoute pushes 900 USDC to virtual escrow with user as source
 *      - BondRoute pushes 100 USDC (stake) to virtual escrow from BondRoute itself
 *      - Due to LIFO ordering, stake gets consumed first during pulls/sends
 *      - Result: User can trade all 1000 USDC (stake gets consumed during execution)
 *      
 *      Key Features:
 *      - Support for both EOA (ECDSA) and smart wallet (EIP-1271) signatures
 *      - Delegation support via `execute_bond_on_behalf_of_user`
 *      - Off-chain commitment proof calculation for frontend integration
 *      - Gas-efficient bond storage (only 3 storage slots per bond)
 */
interface IUser {

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              BOND LIFECYCLE
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Create a bond with cryptographic commitment proof (no stake)
     * @param commitment_proof The value returned by `__OFF_CHAIN__calculate_commitment_proof()`
     * @dev Reverts with error `Invalid` if `commitment_proof` is zero.
     */
    function create_bond( bytes21 commitment_proof ) external;

    /**
     * @notice Create a bond with multiple token stakes
     * @param commitment_proof The value returned by `__OFF_CHAIN__calculate_commitment_proof()`
     * @param stakes Array of ERC20 tokens and amounts to stake (max of 255 entries)
     * @param creation_deadline Makes the call revert with `BondCreationPastDeadline` after deadline. Use 0 for no deadline.
     * @dev Reverts with error `Invalid` if `commitment_proof` is zero.
     *      Reverts with error `TooManyStakes` if more than `Config.MAX_STAKES_PER_BOND` tokens in `stakes` array.
     *      Reverts with error `BondCreationPastDeadline` if called after `creation_deadline`.
     *      Reverts with error `TokenTransferFailed` if any stake transfer fails.
     */
    function create_bond( bytes21 commitment_proof, TokenAmount[] memory stakes, uint256 creation_deadline ) external;

    /**
     * @notice Execute a bond with target contract call and funding
     * @param bond_id The bond ID to execute
     * @param execution_data Bond execution data containing target contract, calldata, funding details, and secret
     * @dev CRITICAL BEHAVIOR: Individual contract calls within the execution MAY FAIL without causing
     *      the entire bond execution to revert. This design prioritizes user stake recovery over strict
     *      atomicity. Failed calls emit `BondExecutionCallFailed` events for transparency, but execution
     *      continues to maximize the chance of users recovering their staked funds.
     *      
     *      BOND-PICKING PREVENTION: However, calls that fail with empty revert data (possible out-of-gas)
     *      or explicitly revert with `PossiblyBondPicking` WILL cause the entire execution to revert.
     *      This prevents attackers from selectively executing only profitable bonds.
     *      
     *      EXECUTION FLOW:
     *      1. Each call in `execution_data.calls` is executed sequentially
     *      2. Normal reverts: Emit `BondExecutionCallFailed`, continue to next call
     *      3. Empty revert data: Revert entire execution with `PossiblyBondPicking`
     *      4. `PossiblyBondPicking` error: Propagate revert, fail entire execution
     *      5. If execution completes (no bond-picking detected), transfer all funds and stakes to user
     *      
     *      STAKE RECOVERY: Stakes can ONLY be recovered if the entire `execute_bond` transaction succeeds.
     *      Individual call failures do NOT prevent stake recovery - only bond-picking prevention does.
     *      If execution reverts due to bond-picking detection, stakes remain LOCKED in BondRoute until
     *      the user can retry with a valid execution that doesn't trigger bond-picking detection.
     *      This design intentionally punishes attackers attempting selective execution.
     *      
     *      Reverts with error `BondNotFound` if `bond_id` does not exist.
     *      Reverts with error `SameBlockExecute` if called in same block as bond creation.
     *      Reverts with error `BondExpired` if called after the hard cap execution window.
     *      Reverts with error `CommitmentProofMismatch` if `execution_data` doesn't match the original commitment.
     *      Reverts with error `BondExecutionForbiddenCall` for invalid contract calls.
     *      Reverts with error `PossiblyBondPicking` for suspected manipulation attacks.
     */
    function execute_bond( uint64 bond_id, ExecutionData calldata execution_data ) external;

    /**
     * @notice Execute a bond using user signature authorization
     * @param bond_id The bond ID to execute
     * @param execution_data Bond execution data
     * @param user The address that should have authorized this execution
     * @param signature A signature authorizing execution
     * @param is_eip1271 true for EIP-1271 contract validation, false for direct ECDSA validation
     * @dev Same validation as `execute_bond()` plus:
     *      Reverts with error `InvalidSignature` if signature validation fails.
     */
    function execute_bond_on_behalf_of_user( uint64 bond_id, ExecutionData calldata execution_data, address user, bytes calldata signature, bool is_eip1271 ) external;

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Retrieve bond details and associated stakes
     * @param bond_id The bond ID to query
     * @return bond The bond metadata including commitment proof, creation time, and stake count
     * @return stakes Array of staked tokens and amounts for this bond
     * @dev This is a view function for frontend integration. Returns complete bond information including all staked tokens.
     *      
     *      Reverts with error `BondNotFound` if `bond_id` does not exist.
     */
    function __OFF_CHAIN__get_bond( uint64 bond_id ) external view returns ( Bond memory bond, TokenAmount[] memory stakes );

    /**
     * @notice Generates a commitment proof hash for the given user and execution data
     * @param user The user address that will be bound to this commitment
     * @param execution_data Bond execution data containing funding details, calls, and secret
     * @return bytes21 The commitment proof hash for use in `create_bond()`
     * @dev This is a view function for frontend integration. The returned value should be used
     *      as the `commitment_proof` parameter when calling `create_bond()`.
     */
    function __OFF_CHAIN__calculate_commitment_proof( address user, ExecutionData calldata execution_data ) external view returns ( bytes21 );
}