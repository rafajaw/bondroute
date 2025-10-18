// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20 } from "@OpenZeppelin/token/ERC20/IERC20.sol";
import { Admin } from "../admin/Admin.sol";
import "./IProvider.sol";


abstract contract Provider is IProvider, Admin {

    constructor( address initial_admin, address eip1153_detector ) Admin( initial_admin, eip1153_detector ) { }

    modifier onlyCurrentCalledContract( )
    {
        _onlyCurrentCalledContract( );
        _;
    }

    function _onlyCurrentCalledContract( ) private view
    {
        if(  msg.sender != address(_get_current_called_contract( ))  )  revert Unauthorized( msg.sender );
    }


    function get_available_funds( ) external  onlyCurrentCalledContract  view returns ( TokenAmount[] memory )
    {
        return _get_available_funds_internal( );
    }

    function get_available_amount_for_token( IERC20 token ) external  onlyCurrentCalledContract  view returns ( uint256 amount )
    {
        return _get_available_amount_for_token_internal( token );
    }

    function push_funds( IERC20 token, uint256 amount ) external  onlyCurrentCalledContract
    {
        _push_funds_internal( token, amount, msg.sender );
    }

    function pull_funds( IERC20 token, uint256 amount ) external  onlyCurrentCalledContract  returns ( uint256 net_amount )
    {
        return _send_funds_internal( token, amount, msg.sender );
    }

    function send_funds( IERC20 token, uint256 amount, address beneficiary ) external  onlyCurrentCalledContract  returns ( uint256 net_amount )
    {
        return _send_funds_internal( token, amount, beneficiary );
    }

}