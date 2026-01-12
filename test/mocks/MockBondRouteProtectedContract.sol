// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20, BondRouteProtected, BondContext, BondConstraints, TokenAmount, FundingsLib } from "@BondRouteProtected/BondRouteProtected.sol";

/**
 * @title MockBondRouteProtectedContract
 * @notice Mock protocol that inherits BondRouteProtected for testing the integration library
 * @dev Configurable constraints and behaviors for comprehensive testing
 */
contract MockBondRouteProtectedContract is BondRouteProtected {

    using FundingsLib for BondContext;

    BondConstraints public configured_constraints;
    bool public should_revert_on_validate;
    bool public should_revert_on_protected_function;
    bool public was_protected_function_called;
    address public last_caller;
    BondContext private _last_context;
    bytes public entry_point_return_data;

    function last_context( ) external view returns ( BondContext memory )
    {
        return _last_context;
    }

    constructor( string memory name, string memory description ) BondRouteProtected( name, description ) {}

    function configure_constraints( BondConstraints memory constraints ) external
    {
        configured_constraints  =  constraints;
    }

    function set_should_revert_on_validate( bool should_revert ) external
    {
        should_revert_on_validate  =  should_revert;
    }

    function set_should_revert_on_protected_function( bool should_revert ) external
    {
        should_revert_on_protected_function  =  should_revert;
    }

    function reset_call_tracking( ) external
    {
        was_protected_function_called  =  false;
        last_caller                    =  address(0);
        delete _last_context;
    }

    function set_entry_point_return_data( bytes memory return_data ) external
    {
        entry_point_return_data  =  return_data;
    }

    function protected_swap( uint256 amount ) external returns ( bytes memory )
    {
        BondContext memory ctx  =  BondRoute_initialize( );

        was_protected_function_called  =  true;
        last_caller                    =  msg.sender;
        _last_context                  =  ctx;

        if(  should_revert_on_protected_function  )  revert( "MockProtocol: intentional revert" );

        // Pull funds from first funding token if available.
        if(  ctx.fundings.length > 0  )
        {
            ctx.pull( ctx.fundings[ 0 ].token, amount );
        }

        return entry_point_return_data;
    }

    function protected_add_liquidity( uint256 amount_a, uint256 amount_b ) external
    {
        BondContext memory ctx  =  BondRoute_initialize( );

        was_protected_function_called  =  true;
        last_caller                    =  msg.sender;
        _last_context                  =  ctx;

        if(  should_revert_on_protected_function  )  revert( "MockProtocol: intentional revert" );

        // Pull both tokens simulating real liquidity addition.
        // Assumes fundings[0] is token A and fundings[1] is token B.
        if(  ctx.fundings.length >= 2  )
        {
            ctx.pull( ctx.fundings[ 0 ].token, amount_a );
            ctx.pull( ctx.fundings[ 1 ].token, amount_b );
        }
    }

    function protected_calc_minus_one( uint256 input ) external returns ( uint256 )
    {
        BondContext memory ctx  =  BondRoute_initialize( );

        was_protected_function_called  =  true;
        last_caller                    =  msg.sender;
        _last_context                  =  ctx;

        if(  should_revert_on_protected_function  )  revert( "MockProtocol: intentional revert" );

        return input - 1;
    }

    function unprotected_function( ) external
    {
        last_caller  =  msg.sender;
    }

    function BondRoute_get_protected_selectors( ) public pure override returns ( bytes4[] memory selectors )
    {
        selectors  =  new bytes4[](3);
        selectors[ 0 ]  =  this.protected_swap.selector;
        selectors[ 1 ]  =  this.protected_add_liquidity.selector;
        selectors[ 2 ]  =  this.protected_calc_minus_one.selector;
    }

    function BondRoute_quote_call( bytes calldata call, IERC20 /* preferred_stake_token */, TokenAmount[] memory /* preferred_fundings */ ) public view override returns ( BondConstraints memory )
    {
        bytes4 selector  =  bytes4(call);

        if(  selector == this.protected_swap.selector  )
        {
            return configured_constraints;
        }

        if(  selector == this.protected_add_liquidity.selector  )
        {
            return configured_constraints;
        }

        if(  selector == this.protected_calc_minus_one.selector  )
        {
            return configured_constraints;
        }

        revert( "Unknown function selector" );
    }

    function BondRoute_validate( BondContext memory context, bytes calldata call ) internal view override
    {
        if(  should_revert_on_validate  )  revert( "MockProtocol: validation failed" );

        super.BondRoute_validate( context, call );
    }

    // ─── Exposed BondRoute_airdrop for Testing ───────────────────────────────────

    function exposed_BondRoute_airdrop( IERC20 token, uint256 amount, string memory message ) external payable
    {
        BondRoute_airdrop( token, amount, message );
    }

    receive() external payable {}
}
