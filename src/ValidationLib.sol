// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20, TokenAmount, IBondRouteProtected, PossiblyBondFarming } from "./integrations/BondRouteProtected.sol";
import { ExecutionData } from "./Core.sol";
import { TransferFailed } from "./utils/TransferLib.sol";
import { Reentrancy } from "./utils/ReentrancyLock.sol";
import "./Definitions.sol";

error InvalidTypedString( );

library ValidationLib {

    // *SECURITY*  -  Minimum address for valid contracts - addresses below this are reserved for EVM precompiles.
    //             -  Standard EVM precompiles are 0x01-0x09, but some chains (L2s, alt-L1s) use higher ranges.
    //             -  Using 0x10000 (65536) as a conservative threshold to cover current and future precompiles.
    uint160 private constant _MIN_ADDRESS_FOR_VALID_CONTRACT  =  0x10000;

    function is_valid_execution( ExecutionData memory execution_data ) internal view returns ( bool is_valid, string memory invalid_reason )
    {
        // *SECURITY*  -  Reject precompile addresses as protocol targets.
        if(  uint160(address(execution_data.protocol)) < _MIN_ADDRESS_FOR_VALID_CONTRACT  )  return ( false, INVALID_PROTOCOL_OR_CALL );

        bytes4 target_selector  =  bytes4(execution_data.call);
        bool _does_contract_support_bondroute_and_selector  =  _does_support_bondroute_and_selector( execution_data.protocol, target_selector );
        if(  _does_contract_support_bondroute_and_selector == false  )  return ( false, INVALID_PROTOCOL_OR_CALL );

        ( is_valid, invalid_reason )  =  is_valid_fundings( execution_data.fundings );
    }

    function is_valid_fundings( TokenAmount[] memory fundings ) internal pure returns ( bool is_valid, string memory invalid_reason )
    {
        bool is_within_fundings_limit  =  ( fundings.length <= MAX_FUNDINGS_PER_BOND );
        if(  is_within_fundings_limit == false  )  return ( false, INVALID_TOO_MANY_FUNDINGS );

        // *GAS SAVING*  -  Safe bc `i++` and `j++` are bounded by `fundings.length` (max of `MAX_FUNDINGS_PER_BOND`).
        unchecked
        {
            // Check for:
            //      1) `amount` must not be 0.
            //      2) no duplicate `token`.
            for(  uint i = 0  ;  i < fundings.length  ;  i++  )
            {
                IERC20 current_token    =   fundings[ i ].token;
                uint256 current_amount  =   fundings[ i ].amount;

                if(  current_amount == 0  )  return ( false, INVALID_ZERO_AMOUNT );

                // Check for duplicates by comparing with all previous tokens.
                for(  uint j = 0  ;  j < i  ;  j++  )
                {
                    if(  current_token == fundings[ j ].token  )  return ( false, INVALID_DUPLICATE_FUNDING_TOKEN );
                }
            }
        }

        return ( true, "" );
    }

    function _does_support_bondroute_and_selector( IBondRouteProtected target_contract, bytes4 target_selector ) internal view returns ( bool )
    {
        // *SECURITY*  -  Prevent OOG bond farming attacks. Attacker could craft a transaction with minimal gas making 
        //                the staticcall to `BondRoute_get_protected_selectors()` revert due to out-of-gas, causing 
        //                validation to fail and triggering graceful bond settlement with stake refund.
        //             -  By requiring minimum gas, we ensure the query succeeds for any reasonable protocol.
        if(  gasleft() < MIN_GAS_FOR_SELECTOR_QUERY  )  revert PossiblyBondFarming( OUT_OF_GAS_OR_UNSPECIFIED_FAILURE, 0 );

        // *NOTE*  -  Use low-level `staticcall` to safely handle unexpected return data.
        //            High-level try-catch with typed returns would ABI-decode OUTSIDE the try scope,
        //            allowing malformed data (e.g., gas bomb, bogus array length from fallback/selector collision)
        //            to panic and revert the entire transaction instead of gracefully returning false.
        bytes memory call_data  =  abi.encodeWithSelector( IBondRouteProtected.BondRoute_get_protected_selectors.selector );
        ( bool success, bytes memory returndata )  =  address(target_contract).staticcall{ gas: MIN_GAS_FOR_SELECTOR_QUERY }( call_data );

        // *NOTE*  -  A `staticcall` to an address without code results in `success = true` but `returndata.length = 0`.
        if(  success == false  ||  returndata.length < 96  )  return false;

        // ABI encoding of `bytes4[]` return in `bytes memory returndata`:
        //
        // Memory layout (returndata is a `bytes memory`, so first 32 bytes = length):
        //   returndata+0x00..0x1F  ->  length of returndata bytes array
        //   returndata+0x20..0x3F  ->  offset to array data (must be 0x20)
        //   returndata+0x40..0x5F  ->  array length N
        //   returndata+0x60..0x7F  ->  first array element (bytes4 right-padded to 32 bytes)
        //   returndata+0x80..      ->  subsequent elements
        //
        // Minimum valid response: 96 bytes total (offset + length + at least one selector).

        uint offset;
        uint length;
        assembly ("memory-safe")
        {
            offset  :=  mload( add( returndata, 0x20 ) )
            length  :=  mload( add( returndata, 0x40 ) )
        }

        // *GAS SAVING*  -  No need to explicitly check `length == 0` bc the `returndata.length != expected_size` check below would catch it.
        uint expected_size;
        unchecked {  expected_size  =  64 + ( length * 32 );  }  // Allow overflow - mismatch below returns false gracefully.
        if(  offset != 32  ||  returndata.length != expected_size  )  return false;

        unchecked
        {
            uint ptr;
            uint end;
            assembly ("memory-safe")
            {
                ptr  :=  add( returndata, 0x60 )
                end  :=  add( ptr, mul( length, 32 ) )
            }

            for(  ; ptr < end ; ptr += 32  )
            {
                bytes4 selector;
                assembly ("memory-safe") {  selector  :=  mload( ptr )  }

                if(  selector == target_selector  )  return true;
            }
        }

        return false;
    }

    function revert_if_possibly_bond_farming( bytes memory call_output ) internal pure
    {
        // Check for empty call output (OOG or low-level failure).
        // *SECURITY*  -  This catches OOG attacks at ANY depth: if a protected contract calls another contract
        //                and that call OOGs, the failure propagates up through all call levels. If not caught
        //                by intermediate contracts with try/catch, it reaches here as empty call_output.
        //                This prevents attackers from using gas manipulation at any call depth to selectively
        //                fail bond executions and potentially recover stakes.
        if(  call_output.length == 0  )
        {
            revert PossiblyBondFarming( OUT_OF_GAS_OR_UNSPECIFIED_FAILURE, 0 );
        }

        // Check for bond farming error selectors.
        if(  call_output.length >= 4  )
        {
            bytes4 error_selector  =  bytes4(call_output);

            // *SECURITY*  -  `TransferFailed` is user-controllable (revoke allowance, transfer tokens away).
            //                Must trigger `PossiblyBondFarming` to prevent selective bond failure attacks.
            if(  error_selector == TransferFailed.selector  )
            {
                /*
                 * Error signature:  `error TransferFailed( address from, address token, uint256 amount, address to )`
                 *
                 * Memory layout of `call_output` (bytes memory):
                 *   0x00-0x1F (32 bytes): length prefix (bytes memory header)
                 *   0x20-0x23 (4 bytes):  selector
                 *   0x24-0x43 (32 bytes): from address (1st param)
                 *   0x44-0x63 (32 bytes): token address (2nd param)
                 *   0x64-0x83 (32 bytes): amount (3rd param)
                 *   0x84-0xA3 (32 bytes): to address (4th param)
                 */
                address token;
                assembly {
                    token  :=  mload(  add( call_output, 0x44 )  )  // Load:  0x44-0x63 (32 bytes): token address
                }
                revert PossiblyBondFarming( "Transfer failed", bytes32(uint256(uint160(token))) );
            }

            // *SECURITY*  -  `Reentrancy` should never occur legitimately. Users could trigger it via malicious
            //                token callbacks to selectively fail bonds. Treat as bond farming attempt.
            if(  error_selector == Reentrancy.selector  )
            {
                revert PossiblyBondFarming( "Reentrancy", 0 );
            }

            // Propagate `PossiblyBondFarming` from protected contract unchanged.
            if(  error_selector == PossiblyBondFarming.selector  )
            {
                assembly ("memory-safe") {
                    revert( add( call_output, 0x20 ), mload( call_output ) )
                }
            }
        }
    }

    /**
     * @notice Validate ExecuteBondAs type string prefix
     * @param typed_string The complete EIP-712 type string
     * @dev Validates string starts with: "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,"
     */
    function validate_typed_string_prefix( string memory typed_string ) internal pure
    {
        // *SECURITY*  -  Validates string starts with: "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,"
        //                Prevents malicious integrators from passing arbitrary type structures.

        bytes memory typed_bytes  =  bytes(typed_string);

        if(  typed_bytes.length < 96  )  revert InvalidTypedString( );

        bytes32 word1;
        bytes32 word2;
        bytes32 word3;

        assembly ("memory-safe")
        {
            word1  :=  mload( add( typed_bytes, 32 ) )
            word2  :=  mload( add( typed_bytes, 64 ) )
            word3  :=  mload( add( typed_bytes, 96 ) )
        }

        if(  word1 != bytes32("ExecuteBondAs(TokenAmount[] fund")  )  revert InvalidTypedString( );
        if(  word2 != bytes32("ings,TokenAmount stake,uint256 s")  )  revert InvalidTypedString( );

        bytes32 mask3  =  0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000000000000000000000;  // Mask first 21 bytes.
        if(  (word3 & mask3) != (bytes32("alt,address protocol,") & mask3)  )  revert InvalidTypedString( );
    }

    /**
     * @notice Validate TokenAmount type definition in EIP-712 type string
     * @param typed_string The complete EIP-712 type string
     * @param TokenAmount_offset Byte offset where "TokenAmount(address token,uint256 amount)" starts
     * @dev Validates ")TokenAmount(address token,uint256 amount)" at the specified offset - 1
     * @dev The ')' prefix prevents integrators from defining malicious "TokenAmount(bool,bool)" and pointing
     *      to a different "dummyTokenAmount(address token,uint256 amount)" to bypass validation
     */
    function validate_TokenAmount_definition( string memory typed_string, uint256 TokenAmount_offset ) internal pure
    {
        // *SECURITY*  -  Validates ")TokenAmount(address token,uint256 amount)" at the specified offset - 1.
        //                The ')' prefix prevents integrators from defining malicious "TokenAmount(bool,bool)" and pointing
        //                to a different "dummyTokenAmount(address token,uint256 amount)" to bypass validation.

        bytes memory typed_bytes  =  bytes(typed_string);
        uint min_length  =  TokenAmount_offset + 41;  // "TokenAmount(address token,uint256 amount)" is 41 chars.

        if(  typed_bytes.length < min_length  )  revert InvalidTypedString( );
        if(  TokenAmount_offset == 0  )  revert InvalidTypedString( );

        // Load and validate ")TokenAmount(address token,uint256 amount)".
        bytes32 word1;
        bytes32 word2;

        assembly ("memory-safe")
        {
            // Load from (32 + TokenAmount_offset - 1) to include the ')' before TokenAmount.
            let ptr :=  add( add( typed_bytes, 31 ), TokenAmount_offset )
            word1   :=  mload( ptr )
            word2   :=  mload( add( ptr, 32 ) )
        }

        // Expected: ")TokenAmount(address token,uint2"
        if(  word1 != bytes32(")TokenAmount(address token,uint2")  )  revert InvalidTypedString( );

        // Expected: "56 amount)" (first 10 bytes).
        if(  bytes10(word2) != bytes10("56 amount)")  )  revert InvalidTypedString( );
    }
}
