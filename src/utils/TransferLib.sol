// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20, NATIVE_TOKEN } from "@BondRouteProtected/BondRouteProtected.sol";
import { IERC20 as IERC20_OZ } from "@OpenZeppelin/token/ERC20/IERC20.sol";
import { SafeERC20 } from "@OpenZeppelin/token/ERC20/utils/SafeERC20.sol";

error TransferFailed( address from, address token, uint256 amount, address to );

library TransferLib {

    /**
     * @notice Transfer native token (ETH) to an address
     * @param to Destination address
     * @param amount Amount to transfer (no-op if zero)
     * @dev Reverts with `TransferFailed` if the native transfer fails.
     */
    function transfer_native( address to, uint256 amount ) internal
    {
        if(  amount == 0  )  return;

        ( bool did_succeed, )  =  to.call{ value: amount }( "" );
        if(  did_succeed == false  )  revert TransferFailed( address(this), address(NATIVE_TOKEN), amount, to );
    }

    /**
     * @notice Transfer ERC20 tokens from one address to another
     * @param token ERC20 token to transfer
     * @param from Source address - use address(this) for tokens held by this contract
     * @param to Destination address
     * @param amount Amount to transfer (no-op if zero)
     * @dev Reverts with `TransferFailed` if the token transfer fails.
     */
    function transfer_erc20( IERC20 token, address from, address to, uint256 amount ) internal
    {
        if(  amount == 0  )  return;

        bool did_succeed  =  ( from == address(this) )
                            ?   SafeERC20.trySafeTransfer( IERC20_OZ(address(token)), to, amount )
                            :   SafeERC20.trySafeTransferFrom( IERC20_OZ(address(token)), from, to, amount );

        if(  did_succeed == false  )  revert TransferFailed( from, address(token), amount, to );
    }

    /**
     * @notice Transfer ERC20 tokens and measure actual amount delivered (for fee-on-transfer tokens)
     * @param from Source address - use address(this) for tokens held by this contract
     * @param token ERC20 token to transfer
     * @param amount Amount to transfer (returns 0 if zero)
     * @param to Destination address
     * @return amount_delivered Actual amount received by destination (may differ for fee-on-transfer or bonus-on-transfer tokens)
     * @dev Reverts with `TransferFailed` if the token transfer fails.
     */
    function transfer_erc20_and_get_amount_delivered( address from, IERC20 token, uint256 amount, address to ) internal returns ( uint256 amount_delivered )
    {
        if(  amount == 0  )  return 0;

        uint balance_before  =  token.balanceOf( to );

        bool did_succeed    =   ( from == address(this) )
                                ?   SafeERC20.trySafeTransfer( IERC20_OZ(address(token)), to, amount )
                                :   SafeERC20.trySafeTransferFrom( IERC20_OZ(address(token)), from, to, amount );

        if(  did_succeed == false  )  revert TransferFailed( from, address(token), amount, to );

        uint balance_after  =  token.balanceOf( to );

        amount_delivered  =  balance_after - balance_before;  // *SECURITY*  -  Reverts on underflow if recipient balance decreased (should never happen).
    }

    /**
     * @notice Unified transfer function that handles both native and ERC20 tokens
     * @param token Token to transfer - address(0) for native token
     * @param from Source address - address(this) for tokens held by this contract
     * @param to Destination address
     * @param amount Amount to transfer (no-op if zero)
     * @dev Reverts with `TransferFailed` if the transfer fails.
     */
    function transfer( IERC20 token, address from, address to, uint256 amount ) internal
    {
        if(  address(token) == address(NATIVE_TOKEN)  )
        {
            transfer_native({ to: to, amount: amount });
        }
        else
        {
            transfer_erc20({ token: token, from: from, to: to, amount: amount });
        }
    }
}