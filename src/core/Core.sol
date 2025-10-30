// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20 } from "@OpenZeppelin/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@OpenZeppelin/token/ERC20/utils/SafeERC20.sol";
import { EIP712 } from "@OpenZeppelin/utils/cryptography/EIP712.sol";
import { Storage } from "./Storage.sol";
import { TokenSearch } from "../utils/TokenSearch.sol";
import { SignatureValidator } from "../utils/SignatureValidator.sol";
import { Config } from "../Config.sol";
import { TokenTransferFailed, IProvider } from "../provider/IProvider.sol";
import { TokenAmount, IBondRouteProtected, PossiblyBondPicking, BONDROUTEPROTECTED_MAGIC_SIGNATURE } from "../integrations/IBondRouteProtected.sol";
import "../user/IUser.sol";



struct CommitmentProofData {    // *TYPE SAFETY*  -  Ensures consistent commitment proof generation.
    uint256 chain_id;           // Prevents cross-chain replay attacks.
    address bondroute;          // Prevents cross-contract replay attacks.
    address user;               // Binds the user address to the commitment.
    TokenAmount[] fundings;    // User approved ERC20 tokens to be pulled or sent by the called contracts.
    CallEntry[] calls;          // Array of calls to execute sequentially.
    bytes32 secret;             // Prevents preimage attacks.
}



abstract contract Core is Storage, EIP712 {

    using TokenSearch for TokenAmount[];
    
    // *SECURITY*  -  Define a max contract address to prevent a potential precompiled contract exploitation.
    //             -  Ethereum mainnet has precompiled contracts 0x01-0x09, but other chains may have higher numbers.
    //             -  Using 1000 as safe threshold - no valid contract address exists within this range. Even if someone 
    //                manages to craft one, it would only prevent that specific contract from signature validation (fail-safe).
    uint160 private constant _MAX_PRECOMPILED_CONTRACT_ADDRESS  =  1_000;

    constructor( address eip1153_detector ) Storage( eip1153_detector ) EIP712( Config.EIP712_DOMAIN_NAME, Config.EIP712_DOMAIN_VERSION ) { }
    

    function _get_bond_internal( uint64 bond_id ) internal view returns ( Bond memory bond )
    {
        bond  =  _bonds[ bond_id ];
        if(  bond.commitment_proof == 0  )  revert BondNotFound( bond_id );
    }

    function _create_bond_internal( bytes21 commitment_proof, TokenAmount[] memory stakes ) internal
    {
        unchecked { _last_bond_id  =  _last_bond_id + 1; }  // *GAS SAVING*  -  Safe bc `uint64` overflows at 1.8e19+.

        uint64 bond_id  =  _last_bond_id;

        _bonds[ bond_id ]  =  Bond({
            commitment_proof:           commitment_proof,
            created_at_timestamp:       uint40(block.timestamp),
            created_at_block_number:    uint40(block.number),
            count_of_staked_tokens:     uint8(stakes.length)
        });
        
        IERC20[] memory seen_tokens  =  new IERC20[]( stakes.length );  // *GAS SAVING*  -  Track seen tokens in memory to prevent duplicate entries for the same token.
        uint256 count_of_seen_tokens  =  0;

        for(  uint8 i = 0  ;  i < stakes.length  ;  i  =  i + 1  )
        {
            TokenAmount memory stake  =  stakes[ i ];

            if(  stake.amount == 0  )  revert Invalid( STAKE_AMOUNT, 0 );

            // *SECURITY*  -  Revert on duplicate entries for the same token for easier bond execution later and to prevent front-end bugs when creating the bond.
            for(  uint256 k = 0  ;  k < count_of_seen_tokens  ;  k++  )
            {
                if(  seen_tokens[ k ] == stake.token  )  revert Invalid( DUPLICATE_STAKE_TOKEN, uint256(uint160(address(stake.token))) );
            }
            seen_tokens[ count_of_seen_tokens ]  =  stake.token;
            count_of_seen_tokens  =  count_of_seen_tokens + 1;

            uint actual_amount_staked  =  _transfer_from_and_get_actual_amount_delivered({
                token:              stake.token,
                from:               msg.sender,
                to:                 address(this),          // Staked funds are sent and locked onto this very contract.
                amount:             stake.amount
            });

            _bonds_stake_index_to_token[ bond_id ][ i ]             =   stake.token;
            _bonds_stake_token_to_amount[ bond_id ][ stake.token ]  =   actual_amount_staked;
        }
        
        emit BondCreated( bond_id, commitment_proof, stakes.length );
    }

    function _execute_bond_internal( uint64 bond_id, address user, ExecutionData calldata execution_data ) internal
    {
        Bond memory bond  =  _get_bond_internal( bond_id );

        _revert_if_bond_validation_fails( user, bond_id, bond, execution_data );

        TokenAmount[] memory stakes  =  _load_bond_stakes( bond_id, bond.count_of_staked_tokens );
        
        ( bool are_stakes_sufficient, IERC20 failing_token )  =  _does_bond_stakes_cover_all_individual_calls_stakes( stakes, execution_data.calls );
        if(  are_stakes_sufficient == false  )
        {
            // *NOTE*  -  This is a malformed bond from the start (likely a calculation bug or a fee-on-transfer token). Since there is no possibility of a malicious 
            //            attack here, we better just settle this bond returning the stakes to the user.
            emit BondExecutionInsufficientStake({
                bond_id:            bond_id,
                failing_token:      address(failing_token)
            });
        }
        else
        {
            // *NOTE*  -  Modifies the `stakes` array. Decreases the `amount` field of each item in the array by the amount pushed into escrow - essentially, the returned array 
            //            contains the staked tokens and amounts which are left (not pushed into escrow) which we will have to return to the user at the end.
            _smart_push_of_fundings_and_stakes_to_escrow( user, stakes, execution_data );

            _execute_calls( bond_id, user, bond, execution_data );

            _send_escrow_funds_to_user_and_clear_context( user );

            emit BondExecuted( bond_id, user );
        }

        // *NOTE*  -  `stakes` contains all the stakes which we must return to the user.
        _transfer_stakes_to_user_and_delete_bond( bond_id, user, stakes );  // *GAS SAVING*  -  Delete bond for gas refunding and state unbloat.
    }

    function _revert_if_bond_validation_fails( address user, uint64 bond_id, Bond memory bond, ExecutionData calldata execution_data ) internal view
    {
        if(  bond.created_at_block_number == block.number  )            revert SameBlockExecute( bond_id );

        uint execution_deadline  =  bond.created_at_timestamp + Config.HARD_CAP_EXECUTION_WINDOW;
        if(  block.timestamp > execution_deadline  )                    revert BondExpired( bond_id, execution_deadline );

        bytes21 calculated_commitment_proof  =  _calculate_commitment_proof( user, execution_data );
        if(  calculated_commitment_proof != bond.commitment_proof  )    revert CommitmentProofMismatch( bond_id, bond.commitment_proof, calculated_commitment_proof );
    }

    function _does_bond_stakes_cover_all_individual_calls_stakes( TokenAmount[] memory stakes, CallEntry[] calldata calls ) private pure returns ( bool are_stakes_sufficient, IERC20 failing_token )
    {
        uint256[] memory sums  =  new uint256[]( stakes.length );

        unchecked  // *GAS SAVING*  -  Safe bc `i` is bound by `calls.length` and we are checking overflow prior to summing up below.
        {
            for(  uint i = 0  ;  i < calls.length  ;  i++  )
            {
                CallEntry calldata _call  =  calls[ i ];
                if(  _call.stake.amount > 0  )
                {
                    uint k  =  stakes.index_of( _call.stake.token );
                    if(  k == TokenSearch.INDEX_NOT_FOUND  )  return ( false, _call.stake.token );

                    // *SECURITY*  -  Check for overflow in the summing up.
                    uint256 new_sum  =  sums[ k ] + _call.stake.amount;
                    if(  new_sum < sums[ k ]  )  return( false, _call.stake.token );

                    // Check if sums of individual calls exceed what was staked.
                    if(  new_sum > stakes[ k ].amount  )  return ( false, _call.stake.token );
                    
                    sums[ k ]  =  new_sum;
                }
            }
        }

        return  ( true, IERC20(address(0)) );
    }

    function _execute_calls( uint64 bond_id, address user, Bond memory bond, ExecutionData calldata execution_data ) internal
    {
        // *NOTE*  -  We will call `BondRoute_entry_point` on each contract within the `calls` array of `execution_data`, passing in the original user intended 
        //            calldata appended with `packed_user_and_commit_info` and the staked `token` and `amount` relative to the call, which gets fully reconstructed 
        //            on the target as a `BondRouteContext`.

        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by array length.
        {
            for(  uint256 i = 0  ;  i < execution_data.calls.length  ;  i++  )
            {
                CallEntry calldata call_entry  =  execution_data.calls[ i ];

                // *NOTE*  -  Allow user to call `send_funds` on BondRoute itself directly from the `calls` array.
                if(  _process_internally_if_call_to_BondRoute_send_funds( call_entry )  )   continue;  // If processed then continue on next call.
                
                _validate_bond_execution_call( bond_id, i, call_entry );  // Checks if contract implements `BondRoute_is_BondRouteProtected`.
                
                _set_current_called_contract( call_entry._contract );  // Only this contract will be able to manage funds during its call.
                
                bytes memory calldata_with_context  =  _craft_calldata_with_appended_context( call_entry, user, bond );
                try call_entry._contract.BondRoute_entry_point( calldata_with_context ) { }
                catch( bytes memory call_output )
                {
                    // *AUDITABILITY*  -  Emit event to identify exact call that failed and its full output.
                    emit BondExecutionCallFailed({
                        bond_id:     bond_id,
                        call_index:  i,
                        call_output: call_output
                    });
                    
                    _revert_if_possibly_bond_picking( call_output );
                }
            }
            
            _set_current_called_contract( IBondRouteProtected(address(0)) );  // *SECURITY*  -  Forbids out of context calls to funds managing functions.
        }
    }

    function _process_internally_if_call_to_BondRoute_send_funds( CallEntry calldata call_entry ) private returns ( bool did_process )
    {
        bool is_call_to_BondRoute_send_funds  =  (  address(call_entry._contract) == address(this)  &&  bytes4(call_entry._calldata) == IProvider.send_funds.selector  );
        if(  is_call_to_BondRoute_send_funds  )
        {
            _set_current_called_contract( IBondRouteProtected(address(0)) );  // *SECURITY*  -  Probably not required but still solid defensive measure.

            ( address token, uint256 amount, address beneficiary )  =  abi.decode( call_entry._calldata[ 4: ], (address, uint256, address) );
            _send_funds_internal( IERC20(token), amount, beneficiary );

            did_process  =  true;
        }
    }

    function _validate_bond_execution_call( uint64 bond_id, uint256 call_index, CallEntry calldata call_entry ) internal pure
    {
        // *SECURITY*  -  Block precompiled contract addresses to prevent potential exploitation.
        if(  uint160(address(call_entry._contract)) <= _MAX_PRECOMPILED_CONTRACT_ADDRESS  )
        {
            revert BondExecutionForbiddenCall({
                bond_id:        bond_id,
                call_index:     call_index,
                reason:         INVALID_CONTRACT_ADDRESS
            });
        }

        // *SECURITY*  -  Prevent calls from looping over `BondRoute_entry_point` as that could be manipulated to obfuscate user transaction signing.
        if(  call_entry._calldata.length >= 4  )
        {
            bytes4 selector  =  bytes4(call_entry._calldata);
            if(  selector == IBondRouteProtected.BondRoute_entry_point.selector  )
            {
                revert BondExecutionForbiddenCall({
                    bond_id:        bond_id,
                    call_index:     call_index,
                    reason:         CANT_CALL_ENTRY_POINT
                });
            }
        }

        // *SECURITY*  -  We would be susceptible to an edge case vulnerability allowing attackers to steal other users' staked funds if the staked token was 
        //                an ERC20 contract that happened to have a valid function in which its selector collided with the 4-bytes selector of `BondRoute_entry_point`.
        //             -  An attacker could then craft a call with specific calldata that upon `BondRoute_entry_point` call would trigger the legitimate contract function 
        //                with attacker supplied calldata, running in the context of BondRoute itself, potentially affecting all users' staked funds for this specific
        //                contract.
        //             -  To prevent that, we confirm that the target contract is aware of `BondRoute_entry_point` by checking it returns a magic signature when probed
        //                at `BondRoute_is_BondRouteProtected`.
        //             -  Note that to prevent bond-picking (creating multiple bonds and executing only profitable ones), we must revert if the contract fails this check, 
        //                otherwise an attacker could insert a controlled contract in the calls array and selectively change the output of `BondRoute_is_BondRouteProtected` 
        //                (or perform an OOG attack) to manage recovering the stakes from abandoned bonds.
        //             -  Also note that BondRoute supports calls to contracts which are both ERC20 and BondRouteProtected and that there is no risk of selector collision
        //                bc the compiler should (solidity will) forbid exposing two functions with the same selector.
        try call_entry._contract.BondRoute_is_BondRouteProtected( ) returns ( bytes32 returned_code )
        {
            if(  returned_code == BONDROUTEPROTECTED_MAGIC_SIGNATURE  )  return;
        }
        catch { }
        revert PossiblyBondPicking( OUT_OF_GAS_OR_NOT_BONDROUTEPROTECTED );
    }

    function _revert_if_possibly_bond_picking( bytes memory call_output ) internal pure
    {
        // Check for empty call output (OOG or low-level failure).
        // *SECURITY*  -  This catches OOG attacks at ANY depth: if a protected contract calls another contract
        //                and that call OOGs, the failure propagates up through all call levels. If not caught
        //                by intermediate contracts with try/catch, it reaches here as empty call_output.
        //                This prevents attackers from using gas manipulation at any call depth to selectively
        //                fail bond executions and potentially recover stakes.
        if(  call_output.length == 0  )
        {
            revert PossiblyBondPicking( OUT_OF_GAS_OR_UNSPECIFIED_FAILURE );
        }

        // Check for `PossiblyBondPicking` error from protected contract.
        if(  call_output.length >= 4  )
        {
            // forge-lint: disable-next-line(unsafe-typecast)  -  Safe bc checked length is >= 4.
            bytes4 error_selector  =  bytes4(call_output);
            if(  error_selector == PossiblyBondPicking.selector  )
            {
                // Propagate the original error unchanged.
                assembly ("memory-safe") {
                    revert( add( call_output, 0x20 ), mload( call_output ) )
                }
            }
        }
    }

    function _craft_calldata_with_appended_context( CallEntry calldata call_entry, address user, Bond memory bond ) private pure returns ( bytes memory )
    {
        // *GAS SAVING*  -  Pack the user address with commit info on a single word.
        uint256 packed_user_and_commit_info     =   ( uint256(uint160(user)) << 80 ) | ( uint256(bond.created_at_timestamp) << 40 ) | uint256(bond.created_at_block_number);

        bytes calldata _calldata    =  call_entry._calldata;
        uint256 calldata_size       =  call_entry._calldata.length;
        bytes memory calldata_with_context;

        IERC20 staked_token         =  call_entry.stake.token;
        uint256 staked_amount       =  call_entry.stake.amount;
        
        assembly ("memory-safe") {
            let total_size  :=  add( calldata_size, 96 )    // 96 is the context size (3 * 32 bytes).
            calldata_with_context  :=  mload( 0x40 )        // Load free-memory pointer.
            mstore( calldata_with_context, total_size )     // Set memory size.
            
            // Copy original calldata.
            calldatacopy(                                   // Copy from calldata
                add( calldata_with_context, 0x20 ),         // to (our new memory location - just past the size slot)
                _calldata.offset,                           // from
                calldata_size                               // size
            )
            
            // Append context at end.
            let ctx_ptr  :=  add( add( calldata_with_context, 0x20 ), calldata_size )
            mstore( ctx_ptr, packed_user_and_commit_info )
            mstore( add( ctx_ptr, 0x20 ), staked_token )
            mstore( add( ctx_ptr, 0x40 ), staked_amount )
            
            // Update free memory pointer.
            mstore( 0x40, add( ctx_ptr, 0x60 ) )
        }

        return calldata_with_context;
    }

    function _transfer_stakes_to_user_and_delete_bond( uint64 bond_id, address user, TokenAmount[] memory stakes ) internal
    {
        for(  uint8 i = 0  ;  i < stakes.length  ;  i++  )
        {
            TokenAmount memory stake  =  stakes[ i ];

            if(  stake.amount > 0  )
            {
                _safe_transfer_from({
                    token:      stake.token,
                    from:       address(this),
                    to:         user,
                    amount:     stake.amount
                });
            }

            // Clear stake storage.
            delete _bonds_stake_index_to_token[ bond_id ][ i ];
            delete _bonds_stake_token_to_amount[ bond_id ][ stake.token ];
        }

        // Clear bond storage.
        delete _bonds[ bond_id ];
    }

    function _calculate_commitment_proof( address user, ExecutionData calldata execution_data ) internal view returns ( bytes21 )
    {
        CommitmentProofData memory commitment_data  =  CommitmentProofData({
            chain_id:       block.chainid,
            bondroute:      address(this),
            user:           user,
            fundings:       execution_data.fundings,
            calls:          execution_data.calls,
            secret:         execution_data.secret
        });

        /// forge-lint: disable-next-line(asm-keccak256)  -  Can't optimize due to dynamic types.
        return bytes21(keccak256( abi.encode( commitment_data ) ));  // *SECURITY*  -  Use `abi.encode` as the packed version would enable parameter boundary drifting.
    }

    function _is_valid_signature_for_bond_execution( uint64 bond_id, ExecutionData calldata execution_data, address user, bytes calldata signature, bool is_eip1271 ) internal view returns ( bool )
    {
        // Create the expected authorization message.
        /// forge-lint: disable-start(asm-keccak256) - EIP-712 compatibility requires abi.encode format.
        bytes32 typed_data_hash  =  _hashTypedDataV4( keccak256( abi.encode(
            Config.EXECUTE_BOND_ON_BEHALF_OF_USER_TYPEHASH,
            bond_id,
            _hash_fundings( execution_data.fundings ),
            _hash_calls( execution_data.calls ),
            execution_data.secret
        )));
        /// forge-lint: disable-end(asm-keccak256)
        
        // Delegate to signature validation library
        return SignatureValidator.is_valid_signature( user, typed_data_hash, signature, is_eip1271 );
    }
    
    function _hash_calls( CallEntry[] calldata calls ) internal pure returns ( bytes32 )
    {
        bytes32[] memory hashes  =  new bytes32[]( calls.length );

        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by array length.
        {
            for(  uint256 i = 0  ;  i < calls.length  ;  i++  )
            {
                hashes[ i ]  =  keccak256( abi.encode(
                    Config.CALL_ENTRY_TYPEHASH,
                    calls[ i ]._contract,
                    keccak256( calls[ i ]._calldata ),
                    keccak256( abi.encode(
                        Config.TOKEN_AMOUNT_TYPEHASH,
                        calls[ i ].stake.token,
                        calls[ i ].stake.amount
                    ))
                ));
            }
        }

        return keccak256( abi.encode( hashes ) );  /// forge-lint: disable-line(asm-keccak256)  -  Array encoding must match EIP-712 format.
    }
    
    function _hash_fundings( TokenAmount[] calldata fundings ) internal pure returns ( bytes32 )
    {
        bytes32[] memory hashes  =  new bytes32[]( fundings.length );

        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by array length.
        {
            for(  uint256 i = 0  ;  i < fundings.length  ;  i++  )
            {
                hashes[ i ]  =  keccak256( abi.encode(
                    Config.TOKEN_AMOUNT_TYPEHASH,
                    fundings[ i ].token,
                    fundings[ i ].amount
                ));
            }
        }

        return keccak256( abi.encode( hashes ) );  /// forge-lint: disable-line(asm-keccak256)  -  Array encoding must match EIP-712 format.
    }

    function _transfer_from_and_get_actual_amount_delivered( IERC20 token, address from, address to, uint256 amount ) internal returns ( uint256 )
    {
        uint old_balance            =  token.balanceOf( to );  // *SECURITY*  -  It may revert failed `balanceOf`.
        bool did_transfer_succeed   =  SafeERC20.trySafeTransferFrom( token, from, to, amount );
        if(  did_transfer_succeed == false  )  revert TokenTransferFailed( address(token), from, to, amount );

        return  token.balanceOf( to ) - old_balance;  // *SECURITY*  -  It may revert on underflow (for exotic tokens) or failed `balanceOf`.
    }

}

