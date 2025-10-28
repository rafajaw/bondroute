// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20 } from "@OpenZeppelin/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@OpenZeppelin/token/ERC20/utils/SafeERC20.sol";
import { SmartReentrancyGuard } from "../utils/SmartReentrancyGuard.sol";
import { TokenSearch } from "../utils/TokenSearch.sol";
import { Config } from "../Config.sol";
import { Bond, ExecutionData } from "../user/IUser.sol";
import { InsufficientFunds, TokenTransferFailed, PushedFundsOverflow } from "../provider/IProvider.sol";
import { Invalid } from "../user/IUser.sol";
import { TokenAmount, IBondRouteProtected } from "../integrations/IBondRouteProtected.sol";
import "../IBondRoute.sol";


abstract contract Storage is SmartReentrancyGuard {

    using TokenSearch for TokenAmount[];

    constructor( address eip1153_detector ) SmartReentrancyGuard( eip1153_detector ) { }

    
    // ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
    //                              REENTRANCY LOCKS
    // ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
    //
    bytes20 constant BONDS_LOCK         =   bytes20(uint160(uint256(keccak256( "BondRoute.BONDS.lock" ))));
    bytes20 constant FUNDS_LOCK         =   bytes20(uint160(uint256(keccak256( "BondRoute.FUNDS.lock" ))));
    //

    // ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
    //                      STORAGE SLOT CALCULATIONS & ENCODING
    // ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════
    //
    // This contract uses XOR-based storage mapping for gas-efficient data manipulation.
    // Each base slot is derived from keccak256 hash and then XORed with token addresses
    // to create unique storage locations for each token.
    // 
    // STORAGE ISOLATION:
    // - All storage slots maintain at least a unique 64-bit prefix, creating hard boundaries that
    //   prevent any collision with other contract-wide storage.
    //
    // DEBUGGING AND AUDITING MASKS:
    // - Base slots are masked to make actual values and offsets visible for easier debugging and auditing.
    //
    // ═════════════════════════════════════════════════════════════════════════════════════════════════════════════════════════

    // Collision-safe prefix bitmask for all storage slots.
    // Preserves 64-bit prefix to prevent storage collisions, clears remaining 192 bits for dynamic use.
    //   FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    // ├─────── 8 bytes ────────┤────────────────────────── 24 bytes cleared ──────────────────────────────┤
    //  (64 bits preserved)                           (192 bits available for keys/indices)
    uint256 private constant COLLISION_SAFE_PREFIX_BITMASK  =  0xFFFFFFFFFFFFFFFF000000000000000000000000000000000000000000000000;

    // ┌─────────────────────────────────────────────────────────────────────────────────┐
    // │                     ARRAY OF AVAILABLE TOKEN ADDRESSES                          │
    // └─────────────────────────────────────────────────────────────────────────────────┘
    //
    // ENCODING LAYOUT:
    // ┌─────────┬─────────┬─────────┬─────────┐
    // │ slot+0  │ slot+1  │ slot+2  │ slot+3  │
    // ├─────────┼─────────┼─────────┼─────────┤
    // │ length  │ token1  │ token2  │ token3  │
    // │(256bit) │(160bit) │(160bit) │(160bit) │
    // └─────────┴─────────┴─────────┴─────────┘
    //
    // For an array with 2 tokens it looks like this:
    // slot+0: 0x0000000000000000000000000000000000000000000000000000000000000002 (length=2)
    // slot+1: 0x000000000000000000000000A0b86991c431e47f5d4c4c5775C6C6E4D2A4b5c2 (USDC address)
    // slot+2: 0x000000000000000000000000C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 (WETH address)
    //
    uint256 private constant _AVAILABLE_TOKENS__BASE_SLOT  =  uint256(keccak256( "BondRoute.available_tokens.base_slot" )) & COLLISION_SAFE_PREFIX_BITMASK;
    // Final masked slot: 0x52d2dc7902adcfe0000000000000000000000000000000000000000000000000

    // ┌─────────────────────────────────────────────────────────────────────────────────┐
    // │                      PER-TOKEN FUNDING SOURCES ARRAYS                           │
    // └─────────────────────────────────────────────────────────────────────────────────┘
    // XOR Usage: _FUNDING_SOURCES_BASE_SLOT ^ (uint256(uint160(token)) << 32)
    // 32-bit left shift creates space for funding entries.
    // Because each funding entry occupies two slots (source and amount) we can store over
    // 2 billion funding entries theoretically, and even if an attacker manages to do it,
    // overflowing it would start colliding only with the least significant bit of the token
    // address.
    //
    // ENCODING LAYOUT:
    // ┌─────────┬─────────┬─────────┬─────────┬─────────┬─────────┐
    // │ slot+0  │ slot+1  │ slot+2  │ slot+3  │ slot+4  │ slot+5  │
    // ├─────────┼─────────┼─────────┼─────────┼─────────┼─────────┤
    // │seen_flag│ source1 │ amount1 │ source2 │ amount2 │   ...   │
    // │+ length │(160bit) │(256bit) │(160bit) │(256bit) │         │
    // └─────────┴─────────┴─────────┴─────────┴─────────┴─────────┘
    //
    // For an array with 2 entries it looks like this:
    // slot+0: 0x8000000000000000000000000000000000000000000000000000000000000002   (seen_flag | length=2)
    // slot+1: 0x000000000000000000000000A1B2C3D4E5F6...                            (source1 address)
    // slot+2: 0x0000000000000000000000000000000000000000000000000de0b6b3a7640000   (amount1 = 1000 tokens)
    // slot+3: 0x000000000000000000000000F6E5D4C3B2A1...                            (source2 address)  
    // slot+4: 0x0000000000000000000000000000000000000000000000001bc16d674ec80000   (amount2 = 2000 tokens)
    //
    // The `seen_flag` tells us whether the token was already added to the array of available tokens or not.
    uint256 private constant _SEEN_FLAG_BITMASK                 =  ( 1 << 255 );        // Most significant bit marks token as seen
    uint256 private constant _LENGTH_EXTRACTION_MASK            =  ~_SEEN_FLAG_BITMASK; // Extract length without seen flag
    uint256 private constant _FUNDING_SOURCES__BASE_SLOT        =  uint256(keccak256( "BondRoute.funding_sources.base_slot" )) & COLLISION_SAFE_PREFIX_BITMASK;
    // Final masked slot: 0x5c64fc62a17083f4000000000000000000000000000000000000000000000000

    // ┌─────────────────────────────────────────────────────────────────────────────────┐
    // │                        PER-TOKEN TOTAL AMOUNTS                                  │
    // └─────────────────────────────────────────────────────────────────────────────────┘
    // XOR Usage: _TOTAL_TOKEN_AMOUNT_BASE_SLOT ^ uint256(uint160(token))
    // 160-bit space reserved for token addresses (20 bytes) at the end
    //
    // ENCODING LAYOUT:
    // ┌─────────┐
    // │ slot+0  │
    // ├─────────┤
    // │ total   │
    // │(256bit) │
    // └─────────┘
    //
    // For a token with 5000 total amount:
    // slot+0: 0x0000000000000000000000000000000000000000000000010f0cf064dd59200000 (5000 tokens)
    //
    uint256 private constant _TOKEN_TOTAL_AMOUNT__SLOT  =  uint256(keccak256( "BondRoute.token_total_amount.slot" )) & COLLISION_SAFE_PREFIX_BITMASK;
    // Final masked slot: 0x036ec257254e6a68000000000000000000000000000000000000000000000000

    // ┌─────────────────────────────────────────────────────────────────────────────────┐
    // │                    PER-TOKEN ACCUMULATED FEES OWED                              │
    // └─────────────────────────────────────────────────────────────────────────────────┘
    // XOR Usage: _TOKEN_ACCUMULATED_FEES__SLOT ^ uint256(uint160(token))
    // Tracks the total fees accumulated from all pull_funds/send_funds operations for each token
    // Each pull_funds/send_funds call adds 0.01% of the pulled/sent amount to this accumulator
    //
    // ENCODING LAYOUT:
    // ┌─────────┐
    // │ slot+0  │
    // ├─────────┤
    // │acc_fees │
    // │(256bit) │
    // └─────────┘
    //
    // For a token with 8000 tokens total pushed (accumulated fees = 8000 * 0.01% = 0.8):
    // slot+0: 0x0000000000000000000000000000000000000000000000000B1A2BC2EC500000 (0.8 tokens)
    //
    uint256 private constant _TOKEN_ACCUMULATED_FEES__SLOT  =  uint256(keccak256( "BondRoute.token_accumulated_fees.slot" )) & COLLISION_SAFE_PREFIX_BITMASK;
    // Final masked slot: 0x654cdccc6cc1d333000000000000000000000000000000000000000000000000
    
    // ┌─────────────────────────────────────────────────────────────────────────────────┐
    // │                           CURRENT CALLED CONTRACT                               │
    // └─────────────────────────────────────────────────────────────────────────────────┘
    // Stores the contract address that is currently being called by BondRoute
    //
    // ENCODING LAYOUT (1 slot):
    // slot+0:   00 00 00 00 00 00 00 00 00 00 00 00 FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
    //         ├────────────── unused ──────────────┤────────────────── current_contract ─────────────────────────┤
    //                  (96 bits / 12 bytes)                           (160 bits / 20 bytes)
    //
    uint256 private constant _CURRENT_CALLED_CONTRACT__SLOT  =  uint256(keccak256( "BondRoute.current_called_contract.slot" )) & COLLISION_SAFE_PREFIX_BITMASK;
    // Final masked slot: 0xa8e10a3560dfa657000000000000000000000000000000000000000000000000


    // Bond storage
    uint64 internal _last_bond_id;
    mapping( uint64 => Bond ) internal _bonds;
    mapping( uint64 => mapping( uint8 => IERC20 ) ) internal _bonds_stake_index_to_token;
    mapping( uint64 => mapping( IERC20 => uint256 ) ) internal _bonds_stake_token_to_amount;

    // Protocol treasury storage
    address internal _protocol_treasury;

    // Admin storage
    address internal _admin;
    address internal _pending_new_admin;


    function _load_bond_stakes( uint64 bond_id, uint8 count_of_staked_tokens ) internal view returns ( TokenAmount[] memory stakes )
    {
        stakes  =  new TokenAmount[]( count_of_staked_tokens );
        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by count_of_staked_tokens.
        {
            for(  uint8 i = 0  ;  i < count_of_staked_tokens  ;  i++  )
            {
                IERC20 staked_token   =  _bonds_stake_index_to_token[ bond_id ][ i ];
                uint256 staked_amount  =  _bonds_stake_token_to_amount[ bond_id ][ staked_token ];
                
                stakes[ i ]  =  TokenAmount({
                    token:   staked_token,
                    amount:  staked_amount
                });
            }
        }
    }

    /**
     * @dev  Pushes `execution_data.fundings` to escrow but deducting the amounts already staked in this bond.
     *       Example: Bond created with 30 USDC staked -> User fundings is 100 USDC -> Pushes 70 USDC from user into escrow -> Pushes 30 USDC from BondRoute into escrow.
     * 
     *       *NOTE*  -  Modifies the `stakes` array. Decreases the `amount` field of each item in the array by the amount pushed into escrow - essentially, the returned array 
     *                  contains the staked tokens and amounts which are left (not pushed into escrow).
     */
    function _smart_push_of_fundings_and_stakes_to_escrow( address user, TokenAmount[] memory stakes, ExecutionData calldata execution_data ) internal
    {
        uint256[] memory stakes_to_push  =  new uint256[]( stakes.length );  // Track first to push later to make stakes consumed first when pulled (LIFO).

        for(  uint256 i = 0  ;  i < execution_data.fundings.length  ;  i++  )
        {
            TokenAmount calldata funding  =  execution_data.fundings[ i ];

            uint256 remaining_stake  =  0;
            uint k  =  stakes.index_of( funding.token );
            if(  k != TokenSearch.INDEX_NOT_FOUND  )   remaining_stake  =  stakes[ k ].amount;
            
            uint256 user_must_provide;
            
            if(  remaining_stake > 0  )
            {
                // Deduct stake from what user needs to provide.
                user_must_provide  =  ( funding.amount > remaining_stake )  ?  funding.amount - remaining_stake  :  0;
            }
            else
            {
                user_must_provide  =  funding.amount;
            }
            
            // Push user portion.
            if(  user_must_provide > 0  )
            {
                _push_funds_internal({
                    token:      funding.token,
                    amount:     user_must_provide,
                    source:     user
                });
            }
            
            // Track stake portion.
            if(  remaining_stake > 0  )
            {
                uint256 stake_to_use  =  ( funding.amount > remaining_stake )  ?  remaining_stake  :  funding.amount;

                stakes_to_push[ k ]  =  stakes_to_push[ k ] + stake_to_use;

                // Update available stake amount.
                stakes[ k ].amount  =  stakes[ k ].amount - stake_to_use;
            }
        }

        // Push stakes at last to be pulled first (LIFO).
        for(  uint i = 0  ;  i < stakes_to_push.length  ;  i++  )
        {
            uint amount_to_push  =  stakes_to_push[ i ];
            if(  amount_to_push > 0  )
            {
                _push_funds_internal({
                    token:      stakes[ i ].token,
                    amount:     amount_to_push,
                    source:     address(this)       // Stakes are held by the BondRoute contract.
                });
            }
        }
    }

    function _send_escrow_funds_to_user_and_clear_context( address user ) internal  nonReentrant( FUNDS_LOCK )
    {
        uint256 available_tokens_length  =  _read_smart_var( _AVAILABLE_TOKENS__BASE_SLOT );
        if(  available_tokens_length > 0  )
        {
            // Iterate over all available tokens.
            address protocol_treasury  =  _protocol_treasury;

            unchecked  // *GAS SAVING*  -  Safe bc outer loop checks `i > 0`, inner loop checks `j < funding_sources_length`, and subtractions are protected by min() logic.
            {
                for(  uint256 i = available_tokens_length  ;  i > 0  ;  i--  )
                {
                    address token                           =   address(uint160(_read_smart_var( _AVAILABLE_TOKENS__BASE_SLOT + i )));
                    uint256 token_total_amount_slot         =   _TOKEN_TOTAL_AMOUNT__SLOT ^ uint256(uint160(token));
                    uint256 accumulated_fees_slot           =   _TOKEN_ACCUMULATED_FEES__SLOT ^ uint256(uint160(token));
                    
                    uint256 remaining_fee_to_collect        =   _read_smart_var( accumulated_fees_slot );
                    
                    uint256 funding_sources_base            =   _FUNDING_SOURCES__BASE_SLOT ^ (uint256(uint160(token)) << 32);
                    uint256 packed_seen_flag_and_length     =   _read_smart_var( funding_sources_base );
                    uint256 funding_sources_length          =   packed_seen_flag_and_length & _LENGTH_EXTRACTION_MASK;
                    
                    // Transfer from each funding source - first collect protocol fees, then send remainder to beneficiary.
                    for(  uint256 j = 0  ;  j < funding_sources_length  ;  j++  )
                    {
                        uint256 entry_index     =   j * 2;
                        address entry_source    =   address(uint160(_read_smart_var( funding_sources_base + entry_index + 1 )));
                        uint256 entry_amount    =   _read_smart_var( funding_sources_base + entry_index + 2 );
                        if(  entry_amount == 0  )  continue;  // Continue on next funding source.
                        
                        if(  remaining_fee_to_collect > 0  )
                        {
                            // Take up to what is available on this source.
                            uint256 fee_from_this_source  =  ( entry_amount > remaining_fee_to_collect )  ?  remaining_fee_to_collect  :  entry_amount;
                            _safe_transfer_from({
                                token:      IERC20(token),
                                from:       entry_source,
                                to:         protocol_treasury,
                                amount:     fee_from_this_source
                            });
                            
                            remaining_fee_to_collect  =  remaining_fee_to_collect - fee_from_this_source;
                            entry_amount  =  entry_amount - fee_from_this_source;
                            if(  entry_amount == 0  )  continue;  // Continue on next funding source.
                        }
                        
                        // Transfer remaining amount to user.
                        _safe_transfer_from({
                            token:      IERC20(token),
                            from:       entry_source,
                            to:         user,
                            amount:     entry_amount
                        });
                    }
                    
                    // *SECURITY*  -  Clear token-specific vars bc:
                    //                1) Resets state for multiple bond executions if on a multicall.
                    //                2) State would persist if no transient storage (EIP-1153) support on this chain.
                    _write_smart_var( funding_sources_base, 0 );              // Reset token-specific `packed_seen_flag_and_length`.
                    _write_smart_var( token_total_amount_slot, 0 );           // Reset token-specific total amount.
                    _write_smart_var( accumulated_fees_slot, 0 );             // Reset token-specific accumulated fees.
                }
            }
            
            // *SECURITY*  -  Clear var for same reasons as above.
            _write_smart_var( _AVAILABLE_TOKENS__BASE_SLOT, 0 );
        }
    }

    function _get_available_funds_internal( ) internal view returns ( TokenAmount[] memory )
    {
        uint256 available_tokens_length  =  _read_smart_var( _AVAILABLE_TOKENS__BASE_SLOT );
        if(  available_tokens_length == 0  )  return new TokenAmount[]( 0 );

        // Create array large enough to hold all available tokens (including the ones that might have no available funds - 0 amount).
        TokenAmount[] memory available_funds  =  new TokenAmount[]( available_tokens_length );

        // Fill array only with tokens that have non-zero amounts.
        uint k  =  0;  // Iterator for all token entries in which the amount is greater than zero.
        for(  uint256 i = 1  ;  i <= available_tokens_length  ;  i++  )  // Start at 1 bc 0 is array length.
        {
            IERC20 token                =   IERC20(address(uint160(_read_smart_var( _AVAILABLE_TOKENS__BASE_SLOT + i ))));
            uint256 available_amount    =   _get_available_amount_for_token_internal( token );
            
            if(  available_amount > 0  )
            {
                available_funds[ k++ ]  =  TokenAmount({
                    token:      token,
                    amount:     available_amount
                });
            }
        }

        // Trim down the array by setting its length to the first `k` entries.
        assembly ("memory-safe") {
            mstore( available_funds, k )
        }

        return available_funds;
    }

    function _get_available_amount_for_token_internal( IERC20 token ) internal view returns ( uint256 )
    {
        unchecked   // *GAS SAVING*  -  Safe bc we check `gross_amount > fees_owed`.
        {
            uint256 gross_amount        =  _read_smart_var( _TOKEN_TOTAL_AMOUNT__SLOT ^ uint256(uint160(address(token))) );
            uint256 fees_owed           =  _read_smart_var( _TOKEN_ACCUMULATED_FEES__SLOT ^ uint256(uint160(address(token))) );
            
            // Return net available amount (gross minus fees already owed from pulls/sends)
            return  ( gross_amount > fees_owed )  ?  gross_amount - fees_owed  :  0;
        }
    }

    function _push_funds_internal( IERC20 token, uint256 amount, address source ) internal  nonReentrant( FUNDS_LOCK )
    {
        if(  address(token) == address(0)  )  revert Invalid( "token", 0 );
        if(  amount == 0  )  return;

        uint256 funding_sources_base            =  _FUNDING_SOURCES__BASE_SLOT ^ (uint256(uint160(address(token))) << 32);
        uint256 token_total_amount_slot         =  _TOKEN_TOTAL_AMOUNT__SLOT ^ uint256(uint160(address(token)));
        uint256 packed_seen_flag_and_length     =  _read_smart_var( funding_sources_base );
        
        unchecked  // *GAS SAVING*  -  Safe bc all math well within range and we are checking for integer overflow when summing amount to total below.
        {
            bool is_token_first_time_seen  =  ( packed_seen_flag_and_length == 0 );
            if(  is_token_first_time_seen  )
            {
                uint256 available_tokens_count  =  _read_smart_var( _AVAILABLE_TOKENS__BASE_SLOT );
                
                // Add token to available tokens array.
                _write_smart_var( _AVAILABLE_TOKENS__BASE_SLOT + available_tokens_count + 1, uint256(uint160(address(token))) );   //  Add new token.
                _write_smart_var( _AVAILABLE_TOKENS__BASE_SLOT, available_tokens_count + 1 );       // Set new available tokens array length.
                
                // Initialize funding sources array with the new entry.
                _write_smart_var( funding_sources_base, _SEEN_FLAG_BITMASK | 1 );                   // Set packed "seen flag" + array length (1)
                _write_smart_var( funding_sources_base + 1, uint256(uint160(source)) );             // source
                _write_smart_var( funding_sources_base + 2, amount );                               // gross amount (fees charged on pull/send)
                
                // Set total amount available for this token the same as the new entry.
                _write_smart_var( token_total_amount_slot, amount );
            }
            else
            {
                // Add new funding entry to existing array.
                uint current_length     =   packed_seen_flag_and_length & _LENGTH_EXTRACTION_MASK;
                uint entry_index        =   current_length * 2;
                _write_smart_var( funding_sources_base, packed_seen_flag_and_length + 1 );              // Increment length while keeping seen flag
                _write_smart_var( funding_sources_base + entry_index + 1, uint256(uint160(source)) );   // set source
                _write_smart_var( funding_sources_base + entry_index + 2, amount );                     // set gross amount (fees charged on pull/send)
            
                // Add new funding entry amount to existing total.
                uint current_total  =   _read_smart_var( token_total_amount_slot );
                uint new_total      =   current_total + amount;
                if(  new_total < current_total  )   // *SECURITY*  -  Check for integer overflow when summing up the pushed amount to the current total.
                {
                    revert PushedFundsOverflow({
                        token:                  address(token),
                        msg_sender:             msg.sender,
                        source:                 source,
                        tried_to_push_amount:   amount
                    });
                }

                _write_smart_var( token_total_amount_slot, new_total );
            }
        }
    }

    function _send_funds_internal( IERC20 token, uint256 amount, address beneficiary ) internal  nonReentrant( FUNDS_LOCK )  returns ( uint256 net_amount )
    {
        if(  address(token) == address(0)  )  revert Invalid( "token", 0 );
        if(  amount == 0  )  return 0;

        uint256 funding_sources_base        =   _FUNDING_SOURCES__BASE_SLOT ^ (uint256(uint160(address(token))) << 32);
        uint256 token_total_amount_slot     =   _TOKEN_TOTAL_AMOUNT__SLOT ^ uint256(uint160(address(token)));
        uint256 accumulated_fees_slot       =   _TOKEN_ACCUMULATED_FEES__SLOT ^ uint256(uint160(address(token)));

        // Check if requested gross amount is available (accounting for fees already owed).
        uint256 gross_total                 =   _read_smart_var( token_total_amount_slot );
        uint256 current_accumulated_fees    =   _read_smart_var( accumulated_fees_slot );
        uint256 total_available             =   gross_total - current_accumulated_fees;


        if(  amount > total_available  )
        {
            revert InsufficientFunds({
                requester:  msg.sender,
                token:      address(token),
                requested:  amount,
                available:  total_available
            });
        }
        
        // Calculate fee and net amount (after availability check passes)
        uint256 fee_amount  =   amount / Config.BONDROUTE_FEE_DIVISOR;  // *NOTE*  -  BondRoute is fine with 0 fees if this rounds to 0.
        net_amount          =   amount - fee_amount;
        
        // Accumulate fee debt for later collection
        _write_smart_var( accumulated_fees_slot, current_accumulated_fees + fee_amount );
        
        // Update the new total amount for this token upfront as a good defensive practice.
        _write_smart_var( token_total_amount_slot, gross_total - amount );
        
        // Get current token `packed_seen_flag_and_length` and extract length.
        uint256 packed_seen_flag_and_length     =  _read_smart_var( funding_sources_base );
        uint256 funding_sources_length          =  packed_seen_flag_and_length & _LENGTH_EXTRACTION_MASK;
        uint256 remaining_to_send               =  net_amount;  // Transfer only net amount to beneficiary
        
        unchecked   // *GAS SAVING*  -  Safe bc for-loop checks `i > 0` and `( i - 1 ) * 2` overflows at 5e76+.
        {
            // Pull from end of array (LIFO) - iterate backwards
            for(  uint256 i = funding_sources_length  ;  i > 0 && remaining_to_send > 0  ;  i--  )
            {
                uint256 entry_index   =  ( i - 1 ) * 2;
                address entry_source  =  address(uint160(_read_smart_var( funding_sources_base + entry_index + 1 )));
                uint256 entry_amount  =  _read_smart_var( funding_sources_base + entry_index + 2 );
                
                // Take up to what is available on this source.
                uint256 amount_to_take  =  ( entry_amount > remaining_to_send )  ?  remaining_to_send  :  entry_amount;
                
                // If this source is fully consumed, decrement the length pointer, otherwise update with the new amount.
                if(  entry_amount == amount_to_take  )
                {
                    packed_seen_flag_and_length  =  packed_seen_flag_and_length - 1;
                    _write_smart_var( funding_sources_base, packed_seen_flag_and_length );  // *NOTE*  -  The seen flag persists.
                }
                else
                {
                    _write_smart_var( funding_sources_base + entry_index + 2, entry_amount - amount_to_take );
                }
                
                _safe_transfer_from({
                    token:      token,
                    from:       entry_source,
                    to:         beneficiary,
                    amount:     amount_to_take
                });
                
                remaining_to_send  =  remaining_to_send - amount_to_take;
            }
        }
        
        return net_amount;
    }

    function _set_current_called_contract( IBondRouteProtected called_contract ) internal
    {
        _write_smart_var( _CURRENT_CALLED_CONTRACT__SLOT, uint256(uint160(address(called_contract))) );
    }

    function _get_current_called_contract( ) internal view returns ( IBondRouteProtected )
    {
        return IBondRouteProtected(address(uint160(_read_smart_var( _CURRENT_CALLED_CONTRACT__SLOT ))));
    }

    function _safe_transfer_from( IERC20 token, address from, address to, uint256 amount ) internal
    {
        if(  from == to  )  return;
        
        bool did_transfer_succeed;
        if(  from == address(this)  )
        {
            did_transfer_succeed  =  SafeERC20.trySafeTransfer( token, to, amount );
        }
        else
        {
            did_transfer_succeed  =  SafeERC20.trySafeTransferFrom( token, from, to, amount );
        }
        
        if(  did_transfer_succeed == false  )  revert TokenTransferFailed( address(token), from, to, amount );
    }

    function _read_smart_var( uint256 slot ) private view returns ( uint256 value )
    {
        bool use_transient  =  _has_transient_storage_support( );
        
        assembly ("memory-safe") {
            switch use_transient
            case 1 {  value  :=  tload( slot )  }
            default { value  :=  sload( slot ) }
        }
    }

    function _write_smart_var( uint256 slot, uint256 value ) private
    {
        bool use_transient  =  _has_transient_storage_support( );
        
        assembly ("memory-safe") {
            switch use_transient
            case 1 { tstore( slot, value ) }
            default { sstore( slot, value ) }
        }
    }
}
