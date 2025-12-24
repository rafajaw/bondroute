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

event NewSweeperAppointed( address indexed new_sweeper );
event NewSweeper( address indexed sweeper );
event BondLiquidated( bytes32 indexed commitment_hash, IERC20 token, uint256 amount, address indexed recipient );
event ThankYou( address indexed patron, IERC20 token, uint256 amount, string message );
event TipsClaimed( address indexed token, uint256 amount, address indexed recipient );


/**
 * @title Sweeper
 * @notice Sweeper functionality for expired bonds and accumulated tips
 * @dev The sweeper role can liquidate expired bonds and claim accumulated tips
 */
abstract contract Sweeper is Provider {

    /**
     * @notice Initialize Sweeper with sweeper address and EIP-1153 detector
     * @param sweeper Address that will manage expired bonds and accumulated tips
     * @param eip1153_detector Contract address to detect EIP-1153 support for gas optimization
     * @dev Reverts with `Invalid("sweeper", 0)` if sweeper is zero address
     * @dev Reverts with `"Bad eip1153_detector"` if eip1153_detector is invalid or doesn't implement the detection interface
     */
    constructor( address sweeper, address eip1153_detector )
    Provider( eip1153_detector )
    {
        if(  sweeper == address(0)  )  revert Invalid( "sweeper", 0 );

        _sweeper  =  sweeper;
    }

    /**
     * @notice Appoint a new sweeper (two-step process)
     * @param new_sweeper Address of the new sweeper
     *
     * @dev Emits `NewSweeperAppointed(new_sweeper)` upon successful appointment.
     *
     * @dev Reverts with `Unauthorized` if caller is not current sweeper.
     * @dev Reverts with `Invalid("new_sweeper", 0)` if new_sweeper is zero address.
     */
    function appoint_new_sweeper( address new_sweeper )
    external
    {
        if(  msg.sender != _sweeper  )      revert Unauthorized( msg.sender, _sweeper );
        if(  new_sweeper == address(0)  )   revert Invalid( "new_sweeper", 0 );

        _pending_sweeper  =  new_sweeper;

        emit NewSweeperAppointed( new_sweeper );
    }

    /**
     * @notice Claim the sweeper role (second step of two-step process)
     *
     * @dev Emits `NewSweeper(sweeper)` upon successful role claim.
     *
     * @dev Reverts with `Unauthorized` if caller is not the pending sweeper.
     */
    function claim_sweeper_role( )
    external
    {
        if(  msg.sender != _pending_sweeper  )  revert Unauthorized( msg.sender, _pending_sweeper );

        _sweeper  =  msg.sender;
        _pending_sweeper  =  address(0);

        emit NewSweeper( _sweeper );
    }

    /**
     * @notice Liquidate expired bonds and transfer stakes to recipient
     * @param commitment_hashes Array of commitment hashes from bond creation
     * @param stakes Array of stakes used during bond creation (must match commitment_hashes length)
     * @param recipient Address to receive the liquidated stakes
     *
     * @dev Emits `BondLiquidated(commitment_hash, token, amount, recipient)` for each successfully liquidated bond.
     *
     * @dev Reverts with `Unauthorized` if caller is not the sweeper.
     * @dev Reverts with `Invalid("recipient", 0)` if recipient is zero address.
     * @dev Reverts with `Invalid("array_length_mismatch", 0)` if array lengths don't match.
     * @dev Reverts with `BondNotFound` if any bond doesn't exist.
     * @dev Reverts with `BondAlreadySettled` if any bond was already settled (executed, failed, or liquidated).
     * @dev Reverts with `BondNotExpired` if any bond has not exceeded MAX_BOND_LIFETIME (111 days).
     * @dev Reverts with `TransferFailed` if any stake transfer fails.
     * @dev Reverts with `Reentrancy` if called during active bond operation.
     */
    function liquidate_expired_bonds( bytes32[] calldata commitment_hashes, TokenAmount[] calldata stakes, address recipient )
    external  nonReentrant( LOCK_BONDS )
    {
        if(  msg.sender != _sweeper  )                          revert Unauthorized( msg.sender, _sweeper );
        if(  recipient == address(0)  )                         revert Invalid( "recipient", 0 );
        if(  commitment_hashes.length != stakes.length  )       revert Invalid( "array_length_mismatch", 0 );

        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by array length.
        {
            for(  uint256 i = 0  ;  i < commitment_hashes.length  ;  i++  )
            {
                _liquidate_bond( commitment_hashes[ i ], stakes[ i ], recipient );
            }
        }
    }

    /**
     * @notice Liquidate a single expired bond
     * @param commitment_hash Commitment hash from bond creation
     * @param stake Stake used during bond creation
     * @param recipient Address to receive the liquidated stake
     */
    function _liquidate_bond( bytes32 commitment_hash, TokenAmount memory stake, address recipient )
    private
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

        emit BondLiquidated( commitment_hash, stake.token, bond_info.stake_amount_received, recipient );
    }

    /**
     * @notice Tip BondRoute sweeper with optional message
     * @param token Token to tip - `IERC20(address(0))` for native token
     * @param amount Amount to tip
     * @param message Optional message (max 280 characters, empty string for no message)
     *
     * @dev Emits `ThankYou(patron, token, amount_received, message)` upon successful tip.
     *
     * @dev RATIONALE:
     *      Protocols may set tip to 0 during bond execution to minimize gas costs for users.
     *      This function allows tipping separately - batching tips or tipping during off-peak times.
     *
     * @dev RECOMMENDED TIP AMOUNT:
     *      Protocols typically share 10% of their fee with BondRoute.
     *      Example: 1% protocol fee → 0.1% tip, or 0.1% fee → 0.01% tip.
     *      BondRoute protects against up to 5% MEV losses.
     *      Tips sustain SDKs and off-chain tooling protecting users from MEV.
     *
     * @dev NATIVE TOKEN: `amount` MUST equal `msg.value`.
     * @dev ERC20 TOKEN: Transfers from `msg.sender`, requires prior approval, measures actual received amount.
     *
     * @dev Reverts with `Invalid("amount", 0)` if `amount` is zero.
     * @dev Reverts with `Invalid("message.length", bytes(message).length)` if message exceeds 280 characters.
     * @dev Reverts with `NativeAmountMismatch` if native token and `msg.value` != `amount`.
     * @dev Reverts with `NativeAmountMismatch` if ERC20 token and `msg.value` > 0.
     * @dev Reverts with `TransferFailed` if ERC20 transfer fails.
     * @dev Reverts with `Reentrancy` if reentering tip functions.
     */
    function tip( IERC20 token, uint256 amount, string calldata message )
    external  payable  nonReentrant( LOCK_TIPPING )
    {
        if(  amount == 0  )  revert Invalid( "amount", 0 );
        if(  bytes(message).length > MAX_MESSAGE_LENGTH  )  revert Invalid( "message.length", bytes(message).length );

        uint256 amount_received;
        bool is_tip_in_native_token  =  ( address(token) == address(NATIVE_TOKEN) );
        if(  is_tip_in_native_token  )
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

        _accumulated_tips[ token ]  +=  amount_received;

        emit ThankYou( msg.sender, token, amount_received, message );
    }

    /**
     * @notice Get claimable tip amount for a token
     * @param token Token to check (`IERC20(address(0))` for native token)
     * @return claimable Amount available to claim (excludes 1 wei dust kept for gas optimization)
     */
    function get_claimable_tips( IERC20 token )
    external view returns ( uint256 claimable )
    {
        uint256 accumulated  =  _accumulated_tips[ token ];
        unchecked {  claimable  =  ( accumulated > 1 )  ?  accumulated - 1  :  0;  }  // *GAS SAVING*  -  Safe bc `accumulated > 1` checked.
    }

    /**
     * @notice Claim accumulated tips
     * @param tokens Array of tokens to claim tips for (`IERC20(address(0))` for native token)
     * @param recipient Address to receive the accumulated tips
     *
     * @dev Emits `TipsClaimed(token, claimable, recipient)` for each token with claimable tips > 1 wei.
     *
     * @dev Reverts with `Unauthorized` if caller is not the sweeper.
     * @dev Reverts with `Invalid("recipient", 0)` if recipient is zero address.
     * @dev Reverts with `Invalid("tokens.length", 0)` if tokens array is empty.
     * @dev Reverts with `TransferFailed` if any token transfer fails.
     * @dev Reverts with `Reentrancy` if reentering tip functions.
     */
    function claim_accumulated_tips( IERC20[] calldata tokens, address recipient )
    external  nonReentrant( LOCK_TIPPING )
    {
        if(  msg.sender != _sweeper  )          revert Unauthorized( msg.sender, _sweeper );
        if(  recipient == address(0)  )         revert Invalid( "recipient", 0 );
        if(  tokens.length == 0  )              revert Invalid( "tokens.length", 0 );

        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by array length.
        {
            for(  uint256 i = 0  ;  i < tokens.length  ;  i++  )
            {
                IERC20 token  =  tokens[ i ];
                uint256 accumulated  =  _accumulated_tips[ token ];

                // *GAS SAVING*  -  Never clear slot to avoid more expensive zero-to-nonzero storage write.
                //                  Always leave 1 dust in the contract.
                if(  accumulated > 1  )
                {
                    uint256 claimable  =  accumulated - 1;
                    _accumulated_tips[ token ]  =  1;

                    TransferLib.transfer({ token: token, from: address(this), to: recipient, amount: claimable });

                    emit TipsClaimed( address(token), claimable, recipient );
                }
            }
        }
    }
}
