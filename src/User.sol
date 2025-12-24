// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Core, Invalid, BondCreated, ExecutionData } from "./Core.sol";
import { TokenAmount, NATIVE_TOKEN } from "@BondRouteProtected/BondRouteProtected.sol";
import { SignatureValidator } from "./utils/SignatureValidator.sol";
import { TransferLib } from "./utils/TransferLib.sol";
import { HashLib } from "./HashLib.sol";
import { BondStatus, LOCK_BONDS } from "./Definitions.sol";

error PastCreationDeadline( bytes32 commitment_hash, uint256 deadline );
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

    constructor( address eip1153_detector )
    Core( eip1153_detector ) { }

    /**
     * @notice Create a bond with optional stake
     * @param commitment_hash Hash of the execution data (`__OFF_CHAIN__calc_commitment_hash()`)
     * @param stake Token and amount to stake (`token = address(0)` for native, `amount = 0` for stakeless)
     * @param creation_deadline Rejects bond creation if included after this timestamp
     *
     * @dev Emits `BondCreated(commitment_hash, stake_token, stake_amount)` on success.
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
     * @dev ERROR CONDITIONS:
     *      - `Invalid("commitment_hash", 0)` if hash is zero
     *      - `PastCreationDeadline(commitment_hash, creation_deadline)` on late inclusion
     *      - `NativeAmountMismatch(sent, expected)` for incorrect native stake semantics
     *      - `Invalid("stake.amount", 0)` for zero ERC20 stake
     *      - `BondAlreadyExists` if bond with same `(commitment_hash, stake)` exists
     *      - `UnsupportedStake` if fee-on-transfer delta exceeds `int128` range
     *      - `TransferFailed` on ERC20 transfer failure
     *      - `Reentrancy` if called during active bond processing
     */
    function create_bond( bytes32 commitment_hash, TokenAmount memory stake, uint256 creation_deadline )
    external  payable  nonReentrant( LOCK_BONDS )
    {
        if(  commitment_hash == bytes32(0)  )           revert Invalid( "commitment_hash", 0 );
        if(  block.timestamp >= creation_deadline  )    revert PastCreationDeadline( commitment_hash, creation_deadline );

        uint256 amount_received;
        bool is_stake_in_native_token  =  ( address(stake.token) == address(NATIVE_TOKEN) );
        if(  is_stake_in_native_token  )
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

        // *NOTE*  -  Emit `stake.amount` and not `amount_received` bc that is what the sweeper needs to liquidate the bond.
        emit BondCreated( commitment_hash, address(stake.token), stake.amount );
    }

    /**
     * @notice Execute a bond using its revealed execution data
     * @param execution_data Execution data previously committed to via `commitment_hash`
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
     *      - `BondExecuted(commitment_hash)` on success
     *      - `BondProtocolReverted(commitment_hash, output)` on graceful revert
     *      - `BondValidationFailed(commitment_hash, reason)` on invalid bond
     *
     * @dev ERROR CONDITIONS (transaction reverts):
     *      - `BondNotFound`, `BondAlreadySettled`, `SameBlockExecution`, `BondExpired` - bond state issues
     *      - `InsufficientNativeFunding` - incorrect msg.value
     *      - `PossiblyBondFarming` - possibly selective failure, stake kept locked (legit users: fix issue and retry)
     *      - `TransferFailed`, `Reentrancy` - execution issues
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
     * @dev ERROR CONDITIONS:
     *      - `InvalidSignature` if signature invalid (ECDSA or EIP-1271)
     *      - All errors from `execute_bond()` apply
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
     */
    function __OFF_CHAIN__calc_commitment_hash( address user, ExecutionData memory execution_data )
    external view returns ( bytes32 commitment_hash )
    {
        return HashLib.calc_commitment_hash( user, address(this), execution_data );
    }

    /**
     * @notice Retrieve stored bond information
     * @param commitment_hash Commitment identifier
     * @param stake Stake originally provided
     * @return bond_info Creation time, creation block, received stake amount, status
     * @dev Reverts with `BondNotFound` if no matching bond exists.
     */
    function __OFF_CHAIN__get_bond_info( bytes32 commitment_hash, TokenAmount memory stake )
    external view returns ( BondInfo memory bond_info )
    {
        ( bond_info, , )  =  _get_bond_info( commitment_hash, stake );
    }

    /**
     * @notice Construct EIP-712 signing data for `execute_bond_as()`
     * @param execution_data Execution data to sign
     * @return digest Hash to sign
     * @return type_hash EIP-712 type hash (default or protocol-customized)
     * @return type_string Complete type description for wallet UIs
     * @return domain EIP-712 domain for this deployment
     * @dev Frontends call this to build typed-data payloads. Returns custom types if protocol provides them.
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
