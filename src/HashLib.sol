// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { TokenAmount, BondContext, IBondRouteProtected } from "./integrations/BondRouteProtected.sol";
import { ExecutionData } from "./Core.sol";
import { TYPE_HASH_TOKEN_AMOUNT } from "./Definitions.sol";

library HashLib {

    /// @dev *WARNING* Writes 0x120 bytes at free memory pointer without updating or clearing it.
    ///      If uninitialized memory must be zero, uncomment the calldatacopy line at end of assembly block.
    function calc_commitment_hash( address user, address bondroute, ExecutionData memory execution_data ) internal view returns ( bytes32 result )
    {
        bytes32 fundings_hash   =  hash_fundings( execution_data.fundings );
        bytes32 call_hash       =  keccak256( execution_data.call );  // forge-lint: disable-line(asm-keccak256)
        address stake_token     =  address(execution_data.stake.token);
        uint256 stake_amount    =  execution_data.stake.amount;
        uint256 salt            =  execution_data.salt;
        address protocol        =  address(execution_data.protocol);

        // *SECURITY*  -  Binds: chain, BondRoute address, user, fundings, stake, salt, protocol, call.
        //                All dynamic data is pre-hashed to fixed 32-byte values, preventing field drift.
        assembly ("memory-safe")  // *GAS SAVING*  -  Avoids abi.encode overhead for struct with dynamic fields.
        {
            let ptr  :=  mload( 0x40 )
            mstore( ptr,              chainid() )
            mstore( add(ptr, 0x20),   bondroute )
            mstore( add(ptr, 0x40),   user )
            mstore( add(ptr, 0x60),   fundings_hash )
            mstore( add(ptr, 0x80),   stake_token )
            mstore( add(ptr, 0xa0),   stake_amount )
            mstore( add(ptr, 0xc0),   salt )
            mstore( add(ptr, 0xe0),   protocol )
            mstore( add(ptr, 0x100),  call_hash )
            result  :=  keccak256( ptr, 0x120 )
            // calldatacopy( ptr, calldatasize(), 0x120 )  // Clears memory; reading past calldata returns 0 per EVM spec.
        }
    }

    /// @dev *WARNING* Writes length*0x40 bytes at free memory pointer without updating or clearing it.
    ///      If uninitialized memory must be zero, uncomment the calldatacopy line at end of assembly block.
    function hash_fundings( TokenAmount[] memory fundings ) internal pure returns ( bytes32 result )
    {
        uint length  =  fundings.length;
        if(  length == 0  )  return bytes32(0);

        // *NOTE*  -  Assembly pointer math validated against Solidity reference in "test/HashLib/HashLib.t.sol".

        assembly ("memory-safe")  // *GAS SAVING*  -  Assembly avoids abi.encode overhead.
        {
            let ptr  :=  mload( 0x40 )
            for { let i := 0 } lt( i, length ) { i := add(i, 1) }
            {
                let funding_ptr  :=  mload( add( add(fundings, 0x20), mul(i, 0x20) ) )
                let token   :=  mload( funding_ptr )
                let amount  :=  mload( add(funding_ptr, 0x20) )
                mstore( add(ptr, mul(i, 0x40)),            token )
                mstore( add(ptr, add(mul(i, 0x40), 0x20)), amount )
            }
            result  :=  keccak256( ptr, mul(length, 0x40) )
            // calldatacopy( ptr, calldatasize(), mul(length, 0x40) )  // Clears memory; reading past calldata returns 0 per EVM spec.
        }
    }

    function calc_bond_key( bytes32 commitment_hash, TokenAmount memory stake ) internal pure returns ( bytes32 result )
    {
        // *SECURITY*  -  Must hash in the `commitment_hash` with the stake or we would be vulnerable to griefing
        //                if an attacker would frontrun the bond creation with a bogus stake, causing the legit
        //                user to fail with `error BondAlreadyExists()`.
        address token   =  address(stake.token);
        uint256 amount  =  stake.amount;
        assembly ("memory-safe")  // *GAS SAVING*  -  Assembly avoids abi.encode overhead (~230 gas saved per call).
        {
            let free_ptr  :=  mload( 0x40 )
            mstore( 0x00, commitment_hash )
            mstore( 0x20, token )
            mstore( 0x40, amount )
            result  :=  keccak256( 0x00, 0x60 )
            mstore( 0x40, free_ptr )
        }
    }

    /// @dev *WARNING* Writes 0xa0 bytes at free memory pointer without updating or clearing it.
    ///      If uninitialized memory must be zero, uncomment the calldatacopy line at end of assembly block.
    function calc_context_hash( IBondRouteProtected called_contract, BondContext memory context ) internal pure returns ( uint256 result )
    {
        bytes32 fundings_hash  =  hash_fundings( context.fundings );
        address protocol       =  address(called_contract);
        address user           =  context.user;
        address stake_token    =  address(context.stake.token);
        uint256 stake_amount   =  context.stake.amount;

        // *SECURITY*  -  Used to validate that `transfer_funding()` calls made during bond execution
        //                come from the authorized `protocol` and are passed the exact correct context
        //                (user, stake, up-to-date available fundings) to ensure only authorized and
        //                limited funding access.
        assembly ("memory-safe")  // *GAS SAVING*  -  Avoids abi.encode overhead for struct with dynamic field.
        {
            let ptr  :=  mload( 0x40 )
            mstore( ptr,              protocol )
            mstore( add(ptr, 0x20),   user )
            mstore( add(ptr, 0x40),   stake_token )
            mstore( add(ptr, 0x60),   stake_amount )
            mstore( add(ptr, 0x80),   fundings_hash )
            result  :=  keccak256( ptr, 0xa0 )
            // calldatacopy( ptr, calldatasize(), 0xa0 )  // Clears memory; reading past calldata returns 0 per EVM spec.
        }
    }

    // *EIP-712*  -  Used for signature validation in `execute_bond_as`.
    //               Hashes a single TokenAmount with its type hash per EIP-712 spec.
    function hash_stake_for_eip712( TokenAmount memory stake ) internal pure returns ( bytes32 result )
    {
        bytes32 type_hash  =  TYPE_HASH_TOKEN_AMOUNT;
        address token      =  address(stake.token);
        uint256 amount     =  stake.amount;
        assembly ("memory-safe")  // *GAS SAVING*  -  Assembly avoids abi.encode overhead (~200 gas saved).
        {
            let free_ptr  :=  mload( 0x40 )
            mstore( 0x00, type_hash )
            mstore( 0x20, token )
            mstore( 0x40, amount )
            result  :=  keccak256( 0x00, 0x60 )
            mstore( 0x40, free_ptr )
        }
    }

    // *EIP-712*  -  Used for signature validation in `execute_bond_as`.
    //               Must follow EIP-712 spec: each array element is individually hashed with its typehash then concatenated.
    function hash_fundings_for_eip712( TokenAmount[] memory fundings ) internal pure returns ( bytes32 result )
    {
        bytes32[] memory hashes  =  new bytes32[]( fundings.length );
        bytes32 type_hash  =  TYPE_HASH_TOKEN_AMOUNT;

        unchecked   // *GAS SAVING*  -  Safe bc `i++` is bounded by array length.
        {
            for(  uint i = 0  ;  i < fundings.length  ;  i++  )
            {
                address token   =  address(fundings[ i ].token);
                uint256 amount  =  fundings[ i ].amount;
                bytes32 hash;
                assembly ("memory-safe")  // *GAS SAVING*  -  Assembly avoids abi.encode overhead (~200 gas saved per funding).
                {
                    let free_ptr  :=  mload( 0x40 )
                    mstore( 0x00, type_hash )
                    mstore( 0x20, token )
                    mstore( 0x40, amount )
                    hash  :=  keccak256( 0x00, 0x60 )
                    mstore( 0x40, free_ptr )
                }
                hashes[ i ]  =  hash;
            }
        }

        assembly ("memory-safe")  // *GAS SAVING*  -  Hash array elements directly without Solidity overhead.
        {
            let array_length  :=  mload( hashes )
            result  :=  keccak256(
                add( hashes, 32 ),        // Sets the pointer to the hashes values (past the array length).
                mul( array_length, 32 )   // Sets the size in bytes. Each entry is 32 bytes.
            )
        }
    }
}
