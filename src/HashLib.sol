// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { TokenAmount, BondContext, IBondRouteProtected } from "./integrations/BondRouteProtected.sol";
import { ExecutionData } from "./Core.sol";
import { TYPE_HASH_TOKEN_AMOUNT } from "./Definitions.sol";

library HashLib {

    function calc_commitment_hash( address user, address bondroute, ExecutionData memory execution_data )
    internal view returns ( bytes32 )
    {
        return keccak256( abi.encode(
            block.chainid,              // *SECURITY*  -  Binds the bond to one specific chain.
            bondroute,                  // *SECURITY*  -  Binds to the canonical BondRoute address.
            user,                       // *SECURITY*  -  Binds the user's address.
            execution_data              // *SECURITY*  -  Binds the exact call, fundings, stake and salt.
        ));
    }

    function calc_bond_key( bytes32 commitment_hash, TokenAmount memory stake )
    internal pure returns ( bytes32 )
    {
        return keccak256( abi.encode(
            commitment_hash,            // *SECURITY*  -  Must hash in the `commitment_hash` with the stake or we
            stake.token,                //                would be vulnerable to griefing if an attacker would 
            stake.amount                //                frontrun the bond creation with a bogus stake, causing
        ));                             //                the legit user to fail with `error BondAlreadyExists()`.
    }

    function calc_context_hash( IBondRouteProtected called_contract, BondContext memory context )
    internal pure returns ( uint256 )
    {
        return uint256(keccak256(
            abi.encode(                 // *SECURITY*  -  Used to validate that `transfer_funding()` calls made 
                called_contract,        //                during bond execution come from the authorized `protocol`
                context.user,           //                and are passed the exact correct context (user, stake,
                context.stake,          //                up-to-date available fundings) in order to ensure only
                context.fundings        //                authorized and limited funding access.
            )
        ));
    }

    // *EIP-712*  -  Used for signature validation in `execute_bond_as`.
    //               Must follow EIP-712 spec: each array element is individually hashed with its typehash then concatenated.
    function hash_fundings( TokenAmount[] memory fundings )
    internal pure returns ( bytes32 result )
    {
        bytes32[] memory hashes  =  new bytes32[]( fundings.length );

        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by array length.
        {
            for(  uint256 i = 0  ;  i < fundings.length  ;  i++  )
            {
                hashes[ i ]  =  keccak256( abi.encode(
                    TYPE_HASH_TOKEN_AMOUNT,
                    fundings[ i ].token,
                    fundings[ i ].amount
                ));
            }
        }

        assembly ("memory-safe")  // *GAS SAVING*  -  Use assembly to hash array elements directly.
        {
            let array_length  :=  mload( hashes )
            result  :=  keccak256(
                add( hashes, 32 ),        // Sets the pointer to the hashes values (past the array length).
                mul( array_length, 32 )   // Sets the size in bytes. Each entry is 32 bytes.
            )
        }
    }
}
