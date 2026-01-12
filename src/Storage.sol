// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20, TokenAmount } from "./integrations/BondRouteProtected.sol";
import { ReentrancyLock } from "./utils/ReentrancyLock.sol";
import { HashLib } from "./HashLib.sol";
import { BondStatus } from "./Definitions.sol";
import "./Definitions.sol";

error BondNotFound( );
error BondAlreadyExists( );
error BondAlreadySettled( BondStatus status );
error UnsupportedStake( uint256 intended, uint256 received, uint256 max_delta_allowed );

/**
 * @title Storage
 * @notice Gas-optimized single-slot storage per bond with bit-packed state
 * @dev Stores bond state in one storage slot: execution flags, timestamps, and stake deltas
 */
abstract contract Storage is ReentrancyLock {

    struct BondInfo {
        uint56 creation_time;
        uint64 creation_block;
        uint256 stake_amount_received;
        BondStatus status;
    }

    // *GAS SAVING*  -  Single storage slot per bond. Key = `keccak256(commitment_hash || stake.token || stake.amount)`.
    //                  Bit packing (256 bits): status (8) || creation_time (56) || creation_block (64) || stake_received_delta (128).
    //                  Delta is signed: negative = fee taken, positive = bonus received.
    mapping( bytes32 => uint256 ) internal _bonds;

    address internal _collector;
    address internal _pending_collector;

    // Accumulated airdrops per token, claimable by collector via `claim_airdrops()`.
    // Key = token (`IERC20(address(0))` for native). Value = accumulated airdrop amount.
    mapping( IERC20 => uint256 ) internal _accumulated_airdrops;

    // Hash of current execution context. Set before protocol call, cleared after. Used by `transfer_funding()` to verify
    // the caller is the protocol being executed and the context matches. Zero when no execution is active.
    uint256 transient internal __transient__context_hash;

    // Tracks remaining stake held by BondRoute during execution. Starts at `actual_stake_received`,
    // decrements as stake is consumed via `transfer_funding()`. Read at cleanup to return unused portion.
    uint256 transient internal __transient__held_stake;

    // Tracks remaining native token from `msg.value` during execution. Starts at `msg.value`,
    // decrements as native is consumed via `transfer_funding()`. Read at cleanup to return unused portion.
    uint256 transient internal __transient__held_msg_value;


    function _create_bond_internal( bytes32 commitment_hash, TokenAmount memory stake, uint256 amount_received ) internal
    {
        // *SECURITY*  -  If we used `commitment_hash` directly as the slot key there would be a griefing vector in which attackers could
        //                frontrun the bond creation with any stake (like 0) to make the user's transaction fail with `BondAlreadyExists()`. 
        bytes32 bond_key  =  HashLib.calc_bond_key( commitment_hash, stake );

        if(  _bonds[ bond_key ] != 0  )  revert BondAlreadyExists( );

        // Calculate delta: negative = fee taken, positive = bonus received
        int128 stake_received_delta  =  0;

        // *GAS SAVING*  -  All arithmetic is safe: subtractions are guarded by conditionals, casts are bounds-checked.
        unchecked
        {
            if(  stake.amount > amount_received  )
            {
                // Fee case: received LESS than intended
                uint256 loss  =  stake.amount - amount_received;
                if(  loss > uint256(uint128(type(int128).max))  )  revert UnsupportedStake( stake.amount, amount_received, uint256(uint128(type(int128).max)) );
                stake_received_delta  =  -int128(uint128(loss));
            }
            else if(  amount_received > stake.amount  )
            {
                // Bonus case: received MORE than intended
                uint256 gain  =  amount_received - stake.amount;
                if(  gain > uint256(uint128(type(int128).max))  )  revert UnsupportedStake( stake.amount, amount_received, uint256(uint128(type(int128).max)) );
                stake_received_delta  =  int128(uint128(gain));
            }
        }

        // Pack: status (8 bits, bits 248-255) || creation_time (56 bits) || creation_block (64 bits) || stake_received_delta (128 bits)
        // Cast int128 → uint128 → uint256 to preserve bit pattern without sign extension.
        // *NOTE*  -  BondStatus.ACTIVE is 0, so status bits are implicitly clear at creation.
        uint256 packed_value  =  ( uint256(block.timestamp) << 192 ) | ( uint256(block.number) << 128 ) | uint256(uint128(stake_received_delta));

        _bonds[ bond_key ]  =  packed_value;
    }

    function _get_bond_info( bytes32 commitment_hash, TokenAmount memory stake )
    internal view returns ( BondInfo memory bond_info, bytes32 bond_key, uint256 packed_value )
    {
        bond_key        =  HashLib.calc_bond_key( commitment_hash, stake );
        packed_value    =  _bonds[ bond_key ];
        if(  packed_value == 0  )  revert BondNotFound( );

        // Unpack and calculate stake_amount_received in one go
        int128 stake_received_delta  =  int128( uint128( packed_value ) );
        uint256 stake_amount_received;
        unchecked {
            if(  stake_received_delta >= 0  )
            {
                stake_amount_received  =  stake.amount + uint128(stake_received_delta);
            }
            else
            {
                // Negate to convert negative int128 to positive before casting (can't cast negative to uint128).
                stake_amount_received  =  stake.amount - uint128(-stake_received_delta);
            }
        }

        return (
            BondInfo({
                creation_time: uint56( packed_value >> 192 ),
                creation_block: uint64( packed_value >> 128 ),
                stake_amount_received: stake_amount_received,
                status: BondStatus( uint8( packed_value >> 248 ) )
            }),
            bond_key,
            packed_value
        );
    }

    /**
     * @dev Assumes current status is ACTIVE (0). Caller MUST ensure `status == ACTIVE` before calling.
     * @param new_status The new terminal status (EXECUTED, FAILED, or LIQUIDATED)
     */
    function _set_bond_status( bytes32 bond_key, uint256 previous_packed_value, BondStatus new_status ) internal
    {
        _bonds[ bond_key ]  =  previous_packed_value | ( uint256(uint8(new_status)) << 248 );
    }

}
