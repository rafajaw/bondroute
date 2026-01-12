// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { IERC20 } from "@BondRouteProtected/BondRouteProtected.sol";
import { Reentrancy } from "@BondRoute/utils/ReentrancyLock.sol";

/**
 * @title MockERC20
 * @notice Mock ERC20 for testing - can simulate fee-on-transfer and bonus-on-transfer behavior
 */
contract MockERC20 is IERC20, Test {

    string public name;
    string public symbol;
    uint8 public decimals  =  18;

    mapping( address => uint256 ) public override balanceOf;
    mapping( address => mapping( address => uint256 ) ) public override allowance;
    uint256 public override totalSupply;

    // Simulates fee-on-transfer or bonus-on-transfer behavior.
    // If set, transferFrom will deliver this amount instead of the requested amount.
    mapping( address => uint256 ) private _delivered_amount_override;

    // Reentrancy attack configuration.
    address private _reentrancy_target;
    bytes private _reentrancy_call;
    bool private _reentrancy_enabled;
    bool private _did_reentrancy_succeed;

    constructor( string memory _name, string memory _symbol )
    {
        name     =  _name;
        symbol   =  _symbol;
    }

    function mint( address to, uint256 amount ) external
    {
        balanceOf[ to ]  =  balanceOf[ to ] + amount;
        totalSupply      =  totalSupply + amount;

        emit Transfer( address(0), to, amount );
    }

    function approve( address spender, uint256 amount ) external override returns ( bool )
    {
        allowance[ msg.sender ][ spender ]  =  amount;

        emit Approval( msg.sender, spender, amount );

        return true;
    }

    function transfer( address to, uint256 amount ) external virtual override returns ( bool )
    {
        if(  _reentrancy_enabled  )  // *ATTACK*  -  Execute reentrancy attack if configured.
        {
            _execute_reentrancy_attack( );
        }

        balanceOf[ msg.sender ]  =  balanceOf[ msg.sender ] - amount;
        balanceOf[ to ]          =  balanceOf[ to ] + amount;

        emit Transfer( msg.sender, to, amount );

        return true;
    }

    function transferFrom( address from, address to, uint256 amount ) external virtual override returns ( bool )
    {
        if(  _reentrancy_enabled  )  // *ATTACK*  -  Execute reentrancy attack if configured.
        {
            _execute_reentrancy_attack( );
        }

        if(  allowance[ from ][ msg.sender ] != type(uint256).max  )
        {
            allowance[ from ][ msg.sender ]  =  allowance[ from ][ msg.sender ] - amount;
        }

        balanceOf[ from ]  =  balanceOf[ from ] - amount;

        // Check if we should deliver a different amount (for fee-on-transfer/bonus testing).
        uint256 delivered_amount  =  ( _delivered_amount_override[ to ] > 0 )  ?  _delivered_amount_override[ to ]  :  amount;

        balanceOf[ to ]  =  balanceOf[ to ] + delivered_amount;

        emit Transfer( from, to, delivered_amount );

        // Clear override after use.
        if(  _delivered_amount_override[ to ] > 0  )
        {
            _delivered_amount_override[ to ]  =  0;
        }

        return true;
    }

    /**
     * @notice Set the delivered amount for the next transferFrom to a specific recipient
     * @param recipient The recipient address
     * @param delivered_amount The amount that will actually be delivered (can be less for fee-on-transfer or more for bonus)
     * @dev Used for testing fee-on-transfer and bonus-on-transfer scenarios
     */
    function set_delivered_amount( address recipient, uint256 delivered_amount ) external
    {
        _delivered_amount_override[ recipient ]  =  delivered_amount;
    }

    /**
     * @notice Configure reentrancy attack that executes during next transferFrom
     * @param target Address to call during reentrancy
     * @param call Calldata to execute
     * @dev Attack fires during transferFrom after balance updates but before return
     * @dev Attack fires once then automatically disables
     * @dev Use this to test reentrancy guards across all BondRoute modules
     */
    function set_reentrancy_call( address target, bytes calldata call ) external
    {
        _reentrancy_target   =  target;
        _reentrancy_call     =  call;
        _reentrancy_enabled  =  true;
        _did_reentrancy_succeed  =  false;
    }

    function did_reentrancy_succeed( ) external view returns ( bool )
    {
        return _did_reentrancy_succeed;
    }

    /**
     * @notice Clear reentrancy attack configuration
     */
    function clear_reentrancy( ) external
    {
        _reentrancy_target   =  address(0);
        _reentrancy_call     =  "";
        _reentrancy_enabled  =  false;
        _did_reentrancy_succeed  =  false;
    }

    /**
     * @notice Execute configured reentrancy attack and disable
     * @dev Disables before calling to prevent infinite loops
     * @dev Propagates revert from reentrancy guard
     */
    function _execute_reentrancy_attack( ) private
    {
        _reentrancy_enabled  =  false;

        ( bool success, bytes memory revertdata )  =  _reentrancy_target.call( _reentrancy_call );
        if(  success == true  ||  bytes4(revertdata) != Reentrancy.selector  )
        {
            _did_reentrancy_succeed  =  true;
        }
    }
}
