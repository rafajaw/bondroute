// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Core, Invalid, BondCreated, ExecutionData } from "./Core.sol";
import { TokenAmount, NATIVE_TOKEN } from "@BondRouteProtected/BondRouteProtected.sol";
import { SignatureValidator } from "./utils/SignatureValidator.sol";
import { TransferLib } from "./utils/TransferLib.sol";
import { HashLib } from "./HashLib.sol";
import { ValidationLib } from "./ValidationLib.sol";
import { BondStatus, LOCK_BONDS } from "./Definitions.sol";

error NativeAmountMismatch( uint256 sent, uint256 expected );
error InvalidSignature( );

struct EIP712Domain {
    string name;
    string version;
    uint256 chainId;
    address verifyingContract;
}

/**
 * @title User
 * @notice User-facing bond operations and off-chain helper functions
 */
abstract contract User is Core {

    /**
     * @notice Create a bond with optional stake
     * @param commitment_hash Hash of the execution data (`__OFF_CHAIN__calc_commitment_hash()`)
     * @param stake Token and amount to stake (`token = address(0)` for native, `amount = 0` for stakeless)
     *
     * @dev USER STAKING MODEL:
     *      - Native stake: `stake.token = address(0)` and `stake.amount == msg.value`
     *      - ERC20 stake: `msg.value == 0` and BondRoute must have token approval
     *      - Fee-on-transfer tokens: accepted, actual received amount measured
     *      - Rebase tokens: NOT supported (amount fixed at stake time)
     *
     * @dev APPROVAL REQUIREMENTS:
     *      - Stake token: transferred immediately and held by BondRoute
     *      - Funding tokens: remain with user, pulled during `execute_bond()`
     *      Example: 1,000 USDC swap with 10% stake → approve BondRoute for USDC,
     *               create with 100 USDC stake, execute pulls remaining 900 USDC
     *
     * @dev EMITTED EVENTS:
     *      - `BondCreated(commitment_hash, stake_token, stake_amount)` on success
     *
     * @dev ERROR CODES:
     *      - `Invalid(string field, uint256 value)` if `commitment_hash` is zero
     *      - `Invalid(string field, uint256 value)` if `stake.amount` is zero for ERC20 stake
     *      - `NativeAmountMismatch(uint256 sent, uint256 expected)` if `msg.value` doesn't match stake semantics
     *      - `BondAlreadyExists()` if bond with same `commitment_hash` + `stake` exists
     *      - `UnsupportedStake(uint256 intended, uint256 received, uint256 max_delta)` if fee-on-transfer delta exceeds `int128`
     *      - `TransferFailed(address from, address token, uint256 amount, address to)` if ERC20 transfer fails
     *      - `Reentrancy()` if called during active bond processing
     */
    function create_bond( bytes32 commitment_hash, TokenAmount memory stake )
    external  payable  nonReentrant( LOCK_BONDS )
    {
        if(  commitment_hash == bytes32(0)  )  revert Invalid( "commitment_hash", 0 );

        uint256 amount_received;
        if(  address(stake.token) == address(NATIVE_TOKEN)  )
        {
            if(  msg.value != stake.amount  )  revert NativeAmountMismatch( msg.value, stake.amount );

            amount_received  =  stake.amount;
        }
        else
        {
            if(  msg.value > 0  )  revert NativeAmountMismatch( msg.value, 0 );
            if(  stake.amount == 0  )  revert Invalid( "stake.amount", 0 );

            // *NOTE*  -  Actual amount received might be different than intended due to "fee-on-transfer" or other exotic tokens.
            amount_received  =  TransferLib.transfer_erc20_and_get_amount_delivered({
                token:          stake.token,
                from:           msg.sender,
                to:             address(this),
                amount:         stake.amount
            });
        }

        _create_bond_internal( commitment_hash, stake, amount_received );

        // *NOTE*  -  Emit `stake.amount` and not `amount_received` bc that is what the collector needs to liquidate the bond.
        emit BondCreated( commitment_hash, address(stake.token), stake.amount );
    }

    /**
     * @notice Execute a bond and recover stake
     * @param execution_data Execution data matching the original commitment
     * @return status Final bond status (`EXECUTED`, `INVALID_BOND`, or `PROTOCOL_REVERTED`)
     * @return output Validation reason on invalid bond, revert data on protocol failure, or protocol return data on success
     *
     * @dev BOND FARMING PROTECTION:
     *      Prevents creating bonds as free options (execute only profitable, abandon rest).
     *      Errors suggesting selective failure (missing approvals, insufficient funds, missed execution window, OOG)
     *      cause transaction revert with stake remaining locked. Legitimate users can fix the issue and retry.
     *
     * @dev STATUS SEMANTICS:
     *      - `EXECUTED`: protocol call succeeded, stake refunded; `output` is protocol result
     *      - `INVALID_BOND`: structural/validation failure, stake refunded; `output` is reason string
     *      - `PROTOCOL_REVERTED`: protocol reverted gracefully, stake refunded; `output` is revert data
     *
     * @dev EMITTED EVENTS:
     *      - `BondValidationFailed(commitment_hash, reason)` on invalid bond
     *      - `BondProtocolReverted(commitment_hash, output)` on graceful revert
     *      - `BondExecuted(commitment_hash)` on success
     *
     * @dev ERROR CODES (call reverts):
     *      - `BondNotFound()` if no bond exists for `commitment_hash` + `stake`
     *      - `BondAlreadySettled(BondStatus status)` if bond was already executed, failed, or liquidated
     *      - `SameBlockExecution()` if attempting execution in same block as creation
     *      - `BondExpired(uint256 deadline, uint256 current_time)` if bond exceeded `MAX_BOND_LIFETIME`
     *      - `InsufficientNativeFunding(uint256 held, uint256 expected)` if `msg.value` incorrect for native funding
     *      - `PossiblyBondFarming(string reason, bytes32 info)` if selective failure detected (fix and retry)
     *      - `TransferFailed(address from, address token, uint256 amount, address to)` if transfer fails
     *      - `Reentrancy()` if reentering during active execution
     */
    function execute_bond( ExecutionData memory execution_data )
    external  payable  nonReentrant( LOCK_BONDS )  returns ( BondStatus status, bytes memory output )
    {
        return _execute_bond_internal( msg.sender, execution_data );
    }

    /**
     * @notice Execute a bond on behalf of another user (gasless/relayer execution)
     * @param execution_data Execution data committed by `user`
     * @param user Owner of the bond
     * @param signature User's authorization for this execution
     * @param is_eip1271 Use EIP-1271 validation instead of ECDSA
     * @return status Final bond status
     * @return output Validation reason on invalid bond, revert data on protocol failure, or protocol return data on success
     *
     * @dev RELAYER EXECUTION MODEL:
     *      - `msg.sender` pays gas and may front native funds via `msg.value`
     *      - ALL refunds (stake + unused native) always go to `user`
     *      - Relayers have no on-chain protection against user griefing → MUST charge off-chain
     *
     * @dev RECOMMENDED RELAYER PATTERNS:
     *      - Custodial/CEX: debit user before submitting tx
     *      - Credit-card based: pre-charge and execute on-chain
     *      - EIP-7702: set EOA code to smart wallet for atomic control
     *      - Fee extraction: multicall `execute_bond_as` + `transferFrom` of outputs
     *
     * @dev EMITTED EVENTS:
     *      - All events from `execute_bond()` apply
     *
     * @dev ERROR CODES (call reverts):
     *      - `InvalidSignature()` if signature invalid (ECDSA or EIP-1271)
     *      - All error codes from `execute_bond()` apply
     */
    function execute_bond_as( ExecutionData memory execution_data, address user, bytes memory signature, bool is_eip1271 )
    external  payable  nonReentrant( LOCK_BONDS )  returns ( BondStatus status, bytes memory output )
    {
        ( bytes32 digest, , )  =  _get_signing_data_for_execute_bond_as( execution_data );
        bool is_valid_signature  =  SignatureValidator.is_valid_signature( user, digest, signature, is_eip1271 );
        if(  is_valid_signature == false  )     revert InvalidSignature( );

        return _execute_bond_internal( user, execution_data );
    }


    // ━━━━  OFF-CHAIN HELPER FUNCTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    /**
     * @notice Compute commitment hash for off-chain bond preparation
     * @param user Bond owner
     * @param execution_data Data to commit
     * @return commitment_hash Hash for `create_bond()`
     * @dev For off-chain use (frontends, SDKs). Includes chain ID and BondRoute address to prevent replay.
     *
     * @dev ERROR CODES:
     *      - `Invalid(string field, uint256 value)` if `user` is zero address
     *      - `Error(string)` if `execution_data` is invalid (invalid protocol, too many fundings, funding with 0 amount, duplicate tokens)
     */
    function __OFF_CHAIN__calc_commitment_hash( address user, ExecutionData memory execution_data )
    external view returns ( bytes32 commitment_hash )
    {
        if(  user == address(0)  )  revert Invalid( "user", 0 );

        ( bool is_valid, string memory invalid_reason )  =  ValidationLib.is_valid_execution( execution_data );
        if(  is_valid == false  )  revert( invalid_reason );

        return HashLib.calc_commitment_hash( user, address(this), execution_data );
    }

    /**
     * @notice Retrieve stored bond information
     * @param commitment_hash Commitment identifier
     * @param stake Stake originally provided
     * @return bond_info Creation time, creation block, received stake amount, status
     *
     * @dev ERROR CODES:
     *      - `BondNotFound()` if no matching bond exists
     */
    function __OFF_CHAIN__get_bond_info( bytes32 commitment_hash, TokenAmount memory stake )
    external view returns ( BondInfo memory bond_info )
    {
        ( bond_info, , )  =  _get_bond_info( commitment_hash, stake );
    }

    /**
     * @notice Get signing data for gasless bond execution
     * @param execution_data Execution data to sign
     * @return digest Hash to sign
     * @return type_hash EIP-712 type hash (default or protocol-customized)
     * @return type_string Complete EIP-712 type description for wallet display
     * @return domain EIP-712 domain for this deployment
     * @dev Frontends call this to build EIP-712 typed-data payloads. Returns custom types if protocol provides them.
     *
     * @dev ERROR CODES:
     *      - `InvalidTypedString()` if protocol provides malformed custom EIP-712 type string
     */
    function __OFF_CHAIN__get_signing_info( ExecutionData memory execution_data )
    external view returns ( bytes32 digest, bytes32 type_hash, string memory type_string, EIP712Domain memory domain )
    {
        ( digest, type_hash, type_string )  =  _get_signing_data_for_execute_bond_as( execution_data );

        // *SECURITY*  -  Use canonical `eip712Domain()` to ensure consistency with signature verification.
        ( , string memory name, string memory version, uint256 chainId, address verifyingContract, , )  =  eip712Domain( );

        domain  =  EIP712Domain({
            name:               name,
            version:            version,
            chainId:            chainId,
            verifyingContract:  verifyingContract
        });
    }

}
