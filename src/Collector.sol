// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { Provider } from "./Provider.sol";
import { Invalid } from "./Core.sol";
import { NativeAmountMismatch } from "./User.sol";
import { BondAlreadySettled } from "./Storage.sol";
import { IERC20, TokenAmount, Unauthorized, NATIVE_TOKEN } from "@BondRouteProtected/BondRouteProtected.sol";
import { TransferLib } from "./utils/TransferLib.sol";
import "./Definitions.sol";


// ━━━━  ERRORS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

error BondNotExpired( uint256 expiration_time );


// ━━━━  EVENTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

event NewCollectorAppointed( address indexed new_collector );
event NewCollector( address indexed collector );
event BondLiquidated( bytes32 indexed commitment_hash, address indexed token, uint256 amount, address recipient );
event AirdropReceived( address indexed sender, address indexed token, uint256 amount, string message );
event AirdropCredited( address indexed protocol, uint256 amount, bytes32 message );
event AirdropClaimed( address indexed token, uint256 amount, address recipient );


/**
 * @title Collector
 * @notice Collector functionality for expired bonds and accumulated airdrops
 * @dev The collector role can liquidate expired bonds and claim accumulated airdrops
 */
abstract contract Collector is Provider {

    /**
     * @notice Initialize Collector with collector address
     * @param collector Address that will manage expired bonds and accumulated airdrops
     *
     * @dev ERROR CODES:
     *      - `Invalid(string field, uint256 value)` if `collector` is zero address
     */
    constructor( address collector )
    {
        if(  collector == address(0)  )  revert Invalid( "collector", 0 );

        _collector  =  collector;
    }

    /**
     * @notice Appoint a new collector (two-step process)
     * @param new_collector Address of the new collector
     *
     * @dev EMITTED EVENTS:
     *      - `NewCollectorAppointed(new_collector)` upon successful appointment
     *
     * @dev ERROR CODES:
     *      - `Unauthorized(address caller, address expected)` if caller is not current collector
     *      - `Invalid(string field, uint256 value)` if `new_collector` is zero address
     */
    function appoint_new_collector( address new_collector )
    external
    {
        if(  msg.sender != _collector  )      revert Unauthorized( msg.sender, _collector );
        if(  new_collector == address(0)  )   revert Invalid( "new_collector", 0 );

        _pending_collector  =  new_collector;

        emit NewCollectorAppointed( new_collector );
    }

    /**
     * @notice Claim the collector role (second step of two-step process)
     *
     * @dev EMITTED EVENTS:
     *      - `NewCollector(collector)` upon successful role claim
     *
     * @dev ERROR CODES:
     *      - `Unauthorized(address caller, address expected)` if caller is not the pending collector
     */
    function claim_collector_role( )
    external
    {
        if(  msg.sender != _pending_collector  )  revert Unauthorized( msg.sender, _pending_collector );

        _collector  =  msg.sender;
        _pending_collector  =  address(0);

        emit NewCollector( _collector );
    }

    /**
     * @notice Airdrop tokens to BondRoute with optional message
     * @param token Token to airdrop - `IERC20(address(0))` for native token
     * @param amount Amount to airdrop
     * @param message Optional message (max 280 characters, empty string for no message)
     *
     * @dev NATIVE TOKEN: `amount` MUST equal `msg.value`.
     * @dev ERC20 TOKEN: Transfers from `msg.sender`, requires prior approval, measures actual received amount.
     *
     * @dev Returns silently if `amount` is zero (graceful no-op).
     * @dev Truncates message to MAX_MESSAGE_LENGTH bytes if exceeded (graceful truncation).
     *
     * @dev EMITTED EVENTS:
     *      - `AirdropReceived(sender, token, amount_received, message)` upon successful airdrop
     *
     * @dev ERROR CODES:
     *      - `NativeAmountMismatch(uint256 sent, uint256 expected)` if native token and `msg.value` != `amount`
     *      - `NativeAmountMismatch(uint256 sent, uint256 expected)` if ERC20 token and `msg.value` > 0
     *      - `TransferFailed(address from, address token, uint256 amount, address to)` if ERC20 transfer fails
     *      - `Reentrancy()` if reentering airdrop functions
     */
    function airdrop( IERC20 token, uint256 amount, string memory message )
    external  payable  nonReentrant( LOCK_AIRDROP )
    {
        if(  amount == 0  )  return;  // Graceful handling of 0 amount.

        uint256 amount_received;
        if(  address(token) == address(NATIVE_TOKEN)  )
        {
            if(  msg.value != amount  )  revert NativeAmountMismatch( msg.value, amount );

            amount_received  =  amount;
        }
        else
        {
            if(  msg.value > 0  )  revert NativeAmountMismatch( msg.value, 0 );

            // *NOTE*  -  Actual amount received might be different than intended due to "fee-on-transfer" or other exotic tokens.
            amount_received  =  TransferLib.transfer_erc20_and_get_amount_delivered({
                token:      token,
                from:       msg.sender,
                to:         address(this),
                amount:     amount
            });
        }

        unchecked  // *GAS SAVING*  -  Safe bc `_accumulated_airdrops[token]` is uint256 and no token totalSupply can surpass it.
        {
            _accumulated_airdrops[ token ]  +=  amount_received;
        }

        // Graceful truncation if message exceeds MAX_MESSAGE_LENGTH bytes.
        if(  bytes(message).length > MAX_MESSAGE_LENGTH  )
        {
            assembly ("memory-safe") {  mstore( message, MAX_MESSAGE_LENGTH )  }
        }

        emit AirdropReceived( msg.sender, address(token), amount_received, message );
    }

    /**
     * @notice Notify BondRoute of tokens sent directly (for protocol airdrops)
     * @param amount Amount already sent to BondRoute before calling
     * @param message Optional identifier as `bytes32` - pass `bytes32(0)` for silent mode (no event)
     *
     * @dev Enables automatic micro-airdrops from protocol usage: small, per-call airdrops that would
     *      be prohibitively expensive via `airdrop()` (which requires approve + transferFrom overhead).
     *
     * @dev Pattern: mint directly to BondRoute, then notify.
     *
     * @dev No balance checks performed - caller is responsible for correct accounting.
     * @dev Notifying without actual amount minted/transferred is a caller bug affecting only airdrop claims on the caller token itself.
     *
     * @dev Returns silently if `amount` is zero (graceful no-op).
     *
     * @dev EMITTED EVENTS:
     *      - `AirdropCredited(msg.sender, amount, message)` if `message != bytes32(0)`
     */
    function notify_protocol_airdrop( uint256 amount, bytes32 message )
    external
    {
        // *SECURITY*  -  No balance checks or reentrancy locks. Malicious/buggy callers can only harm
        //                their own token's airdrop claims — not BondRoute or other tokens.

        if(  amount == 0  )  return;  // Graceful handling of 0 amount.

        unchecked  // *GAS SAVING*  -  Safe bc `_accumulated_airdrops[token]` is uint256 and no token totalSupply can surpass it.
        {
            _accumulated_airdrops[ IERC20(msg.sender) ]  +=  amount;
        }

        if(  message != bytes32(0)  )  emit AirdropCredited( msg.sender, amount, message );  // *GAS SAVING*  -  Skip event for empty message.
    }

    /**
     * @notice Get claimable airdrop amount for a token
     * @param token Token to check (`IERC20(address(0))` for native token)
     * @return amount Amount available to claim (excludes 1 wei dust kept for gas optimization)
     */
    function get_claimable_airdrop_amount( IERC20 token )
    external view returns ( uint256 amount )
    {
        uint accumulated  =  _accumulated_airdrops[ token ];
        unchecked {  amount  =  ( accumulated > 1 )  ?  accumulated - 1  :  0;  }  // *GAS SAVING*  -  Safe bc `accumulated > 1` checked.
    }

    /**
     * @notice Claim accumulated airdrops
     * @param tokens Array of tokens to claim airdrops for (`IERC20(address(0))` for native token)
     * @param recipient Address to receive
     *
     * @dev EMITTED EVENTS:
     *      - `AirdropClaimed(token, claimable, recipient)` for each token with claimable airdrops > 1 wei
     *
     * @dev ERROR CODES:
     *      - `Unauthorized(address caller, address expected)` if caller is not the collector
     *      - `Invalid(string field, uint256 value)` if `recipient` is zero address
     *      - `Invalid(string field, uint256 value)` if `tokens` array is empty
     *      - `TransferFailed(address from, address token, uint256 amount, address to)` if any transfer fails
     *      - `Reentrancy()` if reentering airdrop functions
     */
    function claim_airdrops( IERC20[] calldata tokens, address recipient )
    external  nonReentrant( LOCK_AIRDROP )
    {
        if(  msg.sender != _collector  )        revert Unauthorized( msg.sender, _collector );
        if(  recipient == address(0)  )         revert Invalid( "recipient", 0 );
        if(  tokens.length == 0  )              revert Invalid( "tokens.length", 0 );

        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by array length.
        {
            for(  uint i = 0  ;  i < tokens.length  ;  i++  )
            {
                IERC20 token  =  tokens[ i ];
                uint accumulated  =  _accumulated_airdrops[ token ];

                // *GAS SAVING*  -  Never clear slot to avoid more expensive zero-to-nonzero storage write.
                //                  Always leave 1 dust in the contract.
                if(  accumulated > 1  )
                {
                    uint claimable  =  accumulated - 1;
                    _accumulated_airdrops[ token ]  =  1;

                    TransferLib.transfer({ token: token, from: address(this), to: recipient, amount: claimable });

                    emit AirdropClaimed( address(token), claimable, recipient );
                }
            }
        }
    }

    /**
     * @notice Liquidate expired bonds and transfer stakes to recipient
     * @param commitment_hashes Array of commitment hashes from bond creation
     * @param stakes Array of stakes used during bond creation (must match commitment_hashes length)
     * @param recipient Address to receive the liquidated stakes
     *
     * @dev EMITTED EVENTS:
     *      - `BondLiquidated(commitment_hash, token, amount, recipient)` for each successfully liquidated bond
     *
     * @dev ERROR CODES:
     *      - `Unauthorized(address caller, address expected)` if caller is not the collector
     *      - `Invalid(string field, uint256 value)` if `recipient` is zero address
     *      - `Invalid(string field, uint256 value)` if array lengths don't match
     *      - `BondNotFound()` if any bond doesn't exist
     *      - `BondAlreadySettled(BondStatus status)` if any bond was already settled
     *      - `BondNotExpired(uint256 expiration_time)` if any bond has not exceeded `MAX_BOND_LIFETIME`
     *      - `TransferFailed(address from, address token, uint256 amount, address to)` if any transfer fails
     *      - `Reentrancy()` if called during active bond operation
     */
    function liquidate_expired_bonds( bytes32[] calldata commitment_hashes, TokenAmount[] calldata stakes, address recipient )
    external  nonReentrant( LOCK_LIQUIDATION )
    {
        // *SECURITY*  -  LOCK_LIQUIDATION (not LOCK_BONDS) is safe bc expired bonds can't execute and non-expired can't liquidate,
        //                time separates the state spaces.

        if(  msg.sender != _collector  )                        revert Unauthorized( msg.sender, _collector );
        if(  recipient == address(0)  )                         revert Invalid( "recipient", 0 );
        if(  commitment_hashes.length != stakes.length  )       revert Invalid( "array_length_mismatch", 0 );

        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by array length.
        {
            for(  uint i = 0  ;  i < commitment_hashes.length  ;  i++  )
            {
                _liquidate_bond( commitment_hashes[ i ], stakes[ i ], recipient );
            }
        }
    }


    // ━━━━  PRIVATE FUNCTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function _liquidate_bond( bytes32 commitment_hash, TokenAmount memory stake, address recipient ) private
    {
        ( BondInfo memory bond_info, bytes32 bond_key, uint256 packed_value )  =  _get_bond_info( commitment_hash, stake );  // Reverts if bond is not found.

        if(  bond_info.status != BondStatus.ACTIVE  )  revert BondAlreadySettled( bond_info.status );

        uint256 expiration_time;
        unchecked {  expiration_time = bond_info.creation_time + MAX_BOND_LIFETIME;  }  // *GAS SAVING*  -  Safe bc timestamp + constant won't overflow.
        if(  block.timestamp < expiration_time  )  revert BondNotExpired( expiration_time );

        _set_bond_status( bond_key, packed_value, BondStatus.LIQUIDATED );

        if(  address(stake.token) == address(NATIVE_TOKEN)  )
        {
            TransferLib.transfer_native({ to: recipient, amount: bond_info.stake_amount_received });
        }
        else
        {
            TransferLib.transfer_erc20({ token: stake.token, from: address(this), to: recipient, amount: bond_info.stake_amount_received });
        }

        emit BondLiquidated( commitment_hash, address(stake.token), bond_info.stake_amount_received, recipient );
    }
}
