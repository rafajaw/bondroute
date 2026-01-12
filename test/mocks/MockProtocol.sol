// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20, IBondRouteProtected, BondContext, TokenAmount, BondConstraints, IBondRoute, Range } from "@BondRouteProtected/BondRouteProtected.sol";

struct FundingTransfer {
    address to;
    IERC20 token;
    uint256 amount;
}

/**
 * @title MockProtocol
 * @notice Mock BondRoute-protected protocol for testing bond execution
 */
contract MockProtocol is IBondRouteProtected {

    string private constant DEFAULT_REVERT_MESSAGE  =  "MockProtocol: intentional revert";

    bool public should_revert;
    bytes public revert_data;
    bool public should_return_custom_signing_info;
    string public custom_typed_string;
    bytes32 public custom_struct_hash;
    uint256 public custom_TokenAmount_offset;
    bytes public return_data;

    FundingTransfer[] public funding_transfers;

    function set_should_revert( bool _should_revert ) external
    {
        should_revert   =  _should_revert;
        revert_data     =  abi.encodeWithSignature( "Error(string)", DEFAULT_REVERT_MESSAGE );
    }

    function set_should_revert( bool _should_revert, bytes memory _revert_data ) external
    {
        should_revert   =  _should_revert;
        revert_data     =  _revert_data;
    }

    function get_revert_data( ) external view returns ( bytes memory )
    {
        return revert_data;
    }

    function set_return_data( bytes memory _return_data ) external
    {
        return_data  =  _return_data;
    }

    function set_custom_signing_info( string memory typed_string, bytes32 struct_hash, uint256 TokenAmount_offset ) external
    {
        should_return_custom_signing_info  =  true;
        custom_typed_string                =  typed_string;
        custom_struct_hash                 =  struct_hash;
        custom_TokenAmount_offset          =  TokenAmount_offset;
    }

    function set_funding_transfers( FundingTransfer[] memory transfers ) external
    {
        delete funding_transfers;
        unchecked
        {
            for(  uint256 i = 0  ;  i < transfers.length  ;  i++  )
            {
                funding_transfers.push( transfers[ i ] );
            }
        }
    }

    function clear_funding_transfers( ) external
    {
        delete funding_transfers;
    }

    function BondRoute_entry_point( bytes calldata /* call */, BondContext memory context ) external override returns ( bytes memory output )
    {
        if(  should_revert  )
        {
            bytes memory data  =  revert_data;
            assembly {
                revert( add(data, 0x20), mload(data) )
            }
        }

        unchecked
        {
            for(  uint256 i = 0  ;  i < funding_transfers.length  ;  i++  )
            {
                FundingTransfer memory transfer  =  funding_transfers[ i ];
                ( uint256 updated_index, uint256 new_available )  =  IBondRoute(msg.sender).transfer_funding( transfer.to, transfer.token, transfer.amount, context );
                context.fundings[ updated_index ].amount  =  new_available;
            }
        }

        // Return raw bytes
        output  =  return_data;
        assembly ("memory-safe")
        {
            return( add( output, 0x20 ), mload( output ) )
        }
    }

    function BondRoute_quote_call( bytes calldata /* call */, IERC20 /* preferred_stake_token */, TokenAmount[] memory /* preferred_fundings */ ) external pure override returns ( BondConstraints memory )
    {
        return BondConstraints({
            min_stake: TokenAmount({ token: IERC20(address(0)), amount: 0 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        });
    }

    function BondRoute_get_protected_selectors( ) external pure override returns ( bytes4[] memory selectors )
    {
        selectors  =  new bytes4[](1);
        selectors[ 0 ]  =  bytes4(keccak256( "test()" ));
    }

    function BondRoute_get_signing_info( bytes calldata /* call */ ) external view override returns ( string memory typed_string, bytes32 struct_hash, uint256 TokenAmount_offset )
    {
        if(  should_return_custom_signing_info  )
        {
            return ( custom_typed_string, custom_struct_hash, custom_TokenAmount_offset );
        }
        return ( "", bytes32(0), 0 );
    }
}
