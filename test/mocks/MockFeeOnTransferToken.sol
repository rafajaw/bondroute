// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { MockERC20 } from "./MockERC20.sol";

contract MockFeeOnTransferToken is MockERC20 {

    uint256 public fee_percentage;

    constructor( string memory name_, string memory symbol_ ) MockERC20( name_, symbol_ ) {}

    function set_fee_percentage( uint256 percentage ) external
    {
        require( percentage <= 100, "Fee cannot exceed 100%" );
        fee_percentage  =  percentage;
    }

    function transfer( address to, uint256 amount ) external override returns ( bool )
    {
        uint256 fee  =  ( amount * fee_percentage ) / 100;
        uint256 amount_after_fee  =  amount - fee;

        balanceOf[ msg.sender ]  =  balanceOf[ msg.sender ] - amount;
        balanceOf[ to ]          =  balanceOf[ to ] + amount_after_fee;
        totalSupply              =  totalSupply - fee;

        emit Transfer( msg.sender, to, amount_after_fee );

        return true;
    }

    function transferFrom( address from, address to, uint256 amount ) external override returns ( bool )
    {
        if(  allowance[ from ][ msg.sender ] != type(uint256).max  )
        {
            allowance[ from ][ msg.sender ]  =  allowance[ from ][ msg.sender ] - amount;
        }

        uint256 fee  =  ( amount * fee_percentage ) / 100;
        uint256 amount_after_fee  =  amount - fee;

        balanceOf[ from ]  =  balanceOf[ from ] - amount;
        balanceOf[ to ]    =  balanceOf[ to ] + amount_after_fee;
        totalSupply        =  totalSupply - fee;

        emit Transfer( from, to, amount_after_fee );

        return true;
    }
}
