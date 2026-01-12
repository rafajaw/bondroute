// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20 } from "@BondRouteProtected/BondRouteProtected.sol";
import { Reentrancy } from "@BondRoute/utils/ReentrancyLock.sol";

interface ICollector {
    function notify_protocol_airdrop( uint256 amount, bytes32 message ) external;
}

/**
 * @title MockProtocolToken
 * @notice Mock protocol token that can call `notify_protocol_airdrop()` on BondRoute
 * @dev Used for testing `notify_protocol_airdrop()` where caller must be the token contract
 */
contract MockProtocolToken is IERC20 {

    string public name;
    string public symbol;
    uint8 public decimals  =  18;

    mapping( address => uint256 ) public override balanceOf;
    mapping( address => mapping( address => uint256 ) ) public override allowance;
    uint256 public override totalSupply;

    address public collector_address;

    // Reentrancy attack configuration.
    address private _reentrancy_target;
    bytes private _reentrancy_call;
    bool private _reentrancy_enabled;
    bool private _did_reentrancy_succeed;

    constructor( string memory _name, string memory _symbol )
    {
        name    =  _name;
        symbol  =  _symbol;
    }

    function set_collector( address _collector ) external
    {
        collector_address  =  _collector;
    }

    function mint( address to, uint256 amount ) external
    {
        balanceOf[ to ]  +=  amount;
        totalSupply      +=  amount;

        emit Transfer( address(0), to, amount );
    }

    function approve( address spender, uint256 amount ) external override returns ( bool )
    {
        allowance[ msg.sender ][ spender ]  =  amount;

        emit Approval( msg.sender, spender, amount );

        return true;
    }

    function transfer( address to, uint256 amount ) external override returns ( bool )
    {
        balanceOf[ msg.sender ]  -=  amount;
        balanceOf[ to ]          +=  amount;

        emit Transfer( msg.sender, to, amount );

        return true;
    }

    function transferFrom( address from, address to, uint256 amount ) external override returns ( bool )
    {
        if(  allowance[ from ][ msg.sender ] != type(uint256).max  )
        {
            allowance[ from ][ msg.sender ]  -=  amount;
        }

        balanceOf[ from ]  -=  amount;
        balanceOf[ to ]    +=  amount;

        emit Transfer( from, to, amount );

        return true;
    }

    /**
     * @notice Mint tokens directly to collector and notify the airdrop
     * @param amount Amount to airdrop
     * @param message Optional 32-byte message
     */
    function mint_and_notify_airdrop( uint256 amount, bytes32 message ) external
    {
        if(  _reentrancy_enabled  )
        {
            _execute_reentrancy_attack();
        }

        balanceOf[ collector_address ]  +=  amount;
        totalSupply                     +=  amount;

        emit Transfer( address(0), collector_address, amount );

        ICollector( collector_address ).notify_protocol_airdrop( amount, message );
    }

    /**
     * @notice Notify airdrop without minting (for testing trust-based accounting)
     * @param amount Amount to notify (may not match actual balance)
     * @param message Optional 32-byte message
     */
    function notify_airdrop_without_mint( uint256 amount, bytes32 message ) external
    {
        ICollector( collector_address ).notify_protocol_airdrop( amount, message );
    }

    /**
     * @notice Configure reentrancy attack that executes during next mint_and_notify_airdrop
     */
    function set_reentrancy_call( address target, bytes calldata call ) external
    {
        _reentrancy_target       =  target;
        _reentrancy_call         =  call;
        _reentrancy_enabled      =  true;
        _did_reentrancy_succeed  =  false;
    }

    function did_reentrancy_succeed() external view returns ( bool )
    {
        return _did_reentrancy_succeed;
    }

    function _execute_reentrancy_attack() private
    {
        _reentrancy_enabled  =  false;

        ( bool success, bytes memory revertdata )  =  _reentrancy_target.call( _reentrancy_call );
        if(  success == true  ||  bytes4(revertdata) != Reentrancy.selector  )
        {
            _did_reentrancy_succeed  =  true;
        }
    }
}
