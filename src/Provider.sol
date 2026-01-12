// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { User } from "./User.sol";
import { Invalid } from "./Core.sol";
import { IERC20, TokenAmount, BondContext, IBondRouteProtected, InsufficientFunding, NATIVE_TOKEN } from "@BondRouteProtected/BondRouteProtected.sol";
import { TransferLib } from "./utils/TransferLib.sol";
import { HashLib } from "./HashLib.sol";
import "./Definitions.sol";


// ━━━━  ERRORS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

error Forbidden( address caller, uint256 calculated_hash, uint256 current_hash );


// ━━━━  EVENTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

event ProtocolAnnounced( address indexed protocol, string name, string description );


/**
 * @title Provider
 * @notice Service layer providing functionality to BondRoute-protected contracts
 * @dev Provides transfer_funding() for fund management and announce_protocol() for discovery
 */
abstract contract Provider is User {

    /**
     * @notice Announce a protocol for on-chain discovery (free, log-only)
     * @param name Protocol name (1-64 chars)
     * @param description Short description (0-280 chars, optional)
     *
     * @dev Call from protocol constructor for automatic discovery.
     * @dev No spam protection - can't validate caller has protected selectors because
     *      protocols announce from constructor (before contract code is deployed).
     *
     * @dev EMITTED EVENTS:
     *      - `ProtocolAnnounced(protocol, name, description)` on success
     *
     * @dev ERROR CODES:
     *      - `Invalid(string field, uint256 value)` if `name` is empty or exceeds 64 bytes
     *      - `Invalid(string field, uint256 value)` if `description` exceeds 280 bytes
     */
    function announce_protocol( string calldata name, string calldata description )
    external
    {
        if(  bytes(name).length == 0  ||  bytes(name).length > MAX_NAME_LENGTH  )    revert Invalid( "name.length", bytes(name).length );
        if(  bytes(description).length > MAX_MESSAGE_LENGTH  )                       revert Invalid( "description.length", bytes(description).length );

        emit ProtocolAnnounced( msg.sender, name, description );
    }

    /**
     * @notice Transfer user funds during bond execution (ONLY callable by executing protocol)
     * @param to Recipient address
     * @param token Token to transfer (`address(0)` for native)
     * @param amount Amount to transfer
     * @param context Current execution context (must match active context)
     * @return updated_index Index of funding entry that was updated
     * @return new_available_amount Remaining amount available for this token
     *
     * @dev SMART STAKE CONSUMPTION (maximizes capital efficiency):
     *      Uses staked funds FIRST when funding token matches stake token.
     *      Example: 1,000 USDC swap with 10% stake (100 USDC staked) →
     *               BondRoute uses 100 USDC stake + pulls 900 USDC from user.
     *
     * @dev APPROVALS REQUIRED:
     *      - Fundings stay with user, pulled via `transferFrom()` during execution
     *      - Users must approve BondRoute for ALL funding tokens before executing
     *      - Only stake is held by BondRoute (transferred during `create_bond()`)
     *
     * @dev IMPORTANT: Must update `context.fundings[updated_index].amount` with returned value before calling again.
     * @dev WARNING: Fee-on-transfer/rebase fundings - recipient may receive less than `amount`.
     *
     * @dev ERROR CODES:
     *      - `Invalid(string field, uint256 value)` if `to` is BondRoute itself (use `airdrop()` instead)
     *      - `Forbidden(address caller, uint256 calculated_hash, uint256 current_hash)` if context hash mismatch
     *      - `InsufficientFunding(address token, uint256 provided, uint256 required)` if amount exceeds declared funding
     *      - `TransferFailed(address from, address token, uint256 amount, address to)` if transfer fails
     *      - `Reentrancy()` if reentering during active transfer
     */
    function transfer_funding( address to, IERC20 token, uint256 amount, BondContext memory context )
    external  nonReentrant( LOCK_TRANSFER_FUNDING )  returns ( uint256 updated_index, uint256 new_available_amount )
    {
        if(  to == address(this)  )  revert Invalid( "to", uint160(to) );

        // ━━━━  STEP 1: Access control  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        uint256 calculated_context_hash  =  HashLib.calc_context_hash( IBondRouteProtected(msg.sender), context );
        if(  calculated_context_hash != __transient__context_hash  )  revert Forbidden( msg.sender, calculated_context_hash, __transient__context_hash );

        // ━━━━  STEP 2: Find the funding entry for this token  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        uint index  =  _find_funding_index( context.fundings, token );
        if(  index == INDEX_NOT_FOUND  )  revert InsufficientFunding( address(token), 0, amount );

        uint declared_available  =  context.fundings[ index ].amount;
        if(  amount == 0  )  return ( index, declared_available );
        if(  amount > declared_available  )  revert InsufficientFunding( address(token), declared_available, amount );

        // ━━━━  STEP 3: Load held funds state (read slots once, only when relevant)  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        //  *GAS SAVING*  -  Only read slots that are relevant to this token.
        bool is_native_token            =  ( address(token) == address(NATIVE_TOKEN) );
        bool stake_matches_token        =  ( context.stake.token == token );

        uint held_from_stake      =  ( stake_matches_token )  ?  __transient__held_stake  :  0;
        uint held_from_msg_value  =  ( is_native_token )  ?  __transient__held_msg_value  :  0;

        // ━━━━  STEP 4: Transfer to recipient  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        //  Amount comes from held funds first.
        //  For ERC20: if held funds are insufficient, pull the rest from user.
        //  For native: MUST come entirely from held funds (can't pull native from user).

        ( held_from_stake, held_from_msg_value )  =  _transfer_using_held_and_pull({
            token: token,
            from: context.user,
            to: to,
            amount: amount,
            held_from_stake: held_from_stake,
            held_from_msg_value: held_from_msg_value
        });

        // ━━━━  STEP 5: Write held state and update context  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        //  *GAS SAVING*  -  Only write transient vars that are relevant to this token.
        if(  stake_matches_token  )  __transient__held_stake      =  held_from_stake;
        if(  is_native_token  )      __transient__held_msg_value  =  held_from_msg_value;

        unchecked {  new_available_amount  =  declared_available - amount;  }  // *GAS SAVING*  -  Safe bc `amount <= declared_available` validated above.
        context.fundings[ index ].amount  =  new_available_amount;
        updated_index  =  index;

        __transient__context_hash  =  HashLib.calc_context_hash( IBondRouteProtected(msg.sender), context );
    }


    // ━━━━  PRIVATE HELPERS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


    /**
     * @dev Transfer `amount` to `to` using held funds (`held_from_stake` + `held_from_msg_value`) first, then pull remainder from `from`.
     */
    function _transfer_using_held_and_pull( IERC20 token, address from, address to, uint256 amount, uint256 held_from_stake, uint256 held_from_msg_value )
    private returns ( uint256 new_held_from_stake, uint256 new_held_from_msg_value )
    {
        uint total_held;
        unchecked {  total_held  =  held_from_stake + held_from_msg_value;  }

        uint amount_from_held  =  _min( amount, total_held );
        uint amount_to_pull;
        unchecked {  amount_to_pull  =  amount - amount_from_held;  }  // *GAS SAVING*  -  Safe bc `amount_from_held = _min(amount, ...)`.

        if(  amount_from_held > 0  )
        {
            //  Consume from stake first, then from msg.value.
            uint from_stake  =  _min( amount_from_held, held_from_stake );
            uint from_msg_value;
            unchecked {  from_msg_value  =  amount_from_held - from_stake;  }  // *GAS SAVING*  -  Safe bc `from_stake = _min(amount_from_held, ...)`.

            //  Transfer from held funds to recipient.
            if(  from_stake > 0  )
            {
                TransferLib.transfer({ token: token, from: address(this), to: to, amount: from_stake });
            }

            if(  from_msg_value > 0  )
            {
                TransferLib.transfer_native({ to: to, amount: from_msg_value });
            }

            //  Update held amounts.
            unchecked   // *GAS SAVING*  -  Safe bc all values derived from `_min()` results.
            {
                held_from_stake      -=  from_stake;
                held_from_msg_value  -=  from_msg_value;
            }
        }

        if(  amount_to_pull > 0  )
        {
            //  *NOTE*  -  Native token can never reach here for destination transfers bc the available amount
            //             for native is capped by what's held (stake + msg.value). Enforced at `execute_bond()`.
            TransferLib.transfer_erc20({ token: token, from: from, to: to, amount: amount_to_pull });
        }

        return ( held_from_stake, held_from_msg_value );
    }

    uint256 private constant INDEX_NOT_FOUND  =  type(uint256).max;

    /**
     * @dev Returns index of `token` in `fundings` array, or `INDEX_NOT_FOUND` if not found.
     */
    function _find_funding_index( TokenAmount[] memory fundings, IERC20 token ) private pure returns ( uint256 index )
    {
        unchecked   // *GAS SAVING*  -  Safe bc `index++` is bounded by array length.
        {
            for(  index = 0  ;  index < fundings.length  ;  index++  )
            {
                if(  fundings[ index ].token == token  )  return index;
            }
        }
        return INDEX_NOT_FOUND;
    }

    function _min( uint256 a, uint256 b ) private pure returns ( uint256 )
    {
        return  ( a < b )  ?  a  :  b;
    }
}
