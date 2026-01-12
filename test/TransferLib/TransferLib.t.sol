// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { IERC20, NATIVE_TOKEN } from "@BondRouteProtected/BondRouteProtected.sol";
import { TransferLib, TransferFailed } from "@BondRoute/utils/TransferLib.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";

/**
 * @title TransferLibHarness
 * @notice Exposes TransferLib internal functions for testing
 */
contract TransferLibHarness {

    using TransferLib for *;

    function exposed_transfer_native( address to, uint256 amount ) external
    {
        TransferLib.transfer_native( to, amount );
    }

    function exposed_transfer_erc20( IERC20 token, address from, address to, uint256 amount ) external
    {
        TransferLib.transfer_erc20( token, from, to, amount );
    }

    function exposed_transfer_erc20_and_get_amount_delivered( address from, IERC20 token, uint256 amount, address to ) external returns ( uint256 )
    {
        return TransferLib.transfer_erc20_and_get_amount_delivered( from, token, amount, to );
    }

    function exposed_transfer( IERC20 token, address from, address to, uint256 amount ) external
    {
        TransferLib.transfer( token, from, to, amount );
    }

    receive() external payable {}
}

/**
 * @title MockRevertingReceiver
 * @notice Contract that reverts on receiving native tokens
 */
contract MockRevertingReceiver {
    receive() external payable {
        revert( "I reject your ETH" );
    }
}

/**
 * @title TransferLibTest
 * @notice Tests for TransferLib utility library
 * @dev Implements ITransferLibTests from TestManifest.sol
 */
contract TransferLibTest is Test {

    TransferLibHarness public harness;
    MockERC20 public token;
    MockRevertingReceiver public reverting_receiver;

    address public alice  =  makeAddr( "alice" );
    address public bob    =  makeAddr( "bob" );

    function setUp() public
    {
        harness            =  new TransferLibHarness();
        token              =  new MockERC20( "Test Token", "TEST" );
        reverting_receiver =  new MockRevertingReceiver();

        // Fund harness with native and tokens.
        vm.deal( address(harness), 100 ether );
        token.mint( address(harness), 1000e18 );

        // Fund alice with tokens and approve harness.
        token.mint( alice, 1000e18 );
        vm.prank( alice );
        token.approve( address(harness), type(uint256).max );
    }


    // ━━━━  transfer_native() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_native_zero_amount_no_op() public
    {
        uint256 balance_before  =  bob.balance;

        harness.exposed_transfer_native( bob, 0 );

        assertEq( bob.balance, balance_before, "Zero transfer should be no-op" );
    }

    function test_transfer_native_success() public
    {
        uint256 amount  =  1 ether;

        harness.exposed_transfer_native( bob, amount );

        assertEq( bob.balance, amount, "Bob should receive native tokens" );
    }

    function test_transfer_native_reverts_on_failed_transfer() public
    {
        vm.expectRevert( abi.encodeWithSelector( TransferFailed.selector, address(harness), address(NATIVE_TOKEN), 1 ether, address(reverting_receiver) ) );
        harness.exposed_transfer_native( address(reverting_receiver), 1 ether );
    }


    // ━━━━  transfer_erc20() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_erc20_zero_amount_no_op() public
    {
        uint256 balance_before  =  token.balanceOf( bob );

        harness.exposed_transfer_erc20( IERC20(address(token)), alice, bob, 0 );

        assertEq( token.balanceOf( bob ), balance_before, "Zero transfer should be no-op" );
    }

    function test_transfer_erc20_from_self() public
    {
        uint256 amount  =  100e18;

        harness.exposed_transfer_erc20( IERC20(address(token)), address(harness), bob, amount );

        assertEq( token.balanceOf( bob ), amount, "Bob should receive tokens from harness" );
    }

    function test_transfer_erc20_from_external() public
    {
        uint256 amount  =  100e18;

        harness.exposed_transfer_erc20( IERC20(address(token)), alice, bob, amount );

        assertEq( token.balanceOf( bob ), amount, "Bob should receive tokens from alice" );
    }

    function test_transfer_erc20_reverts_on_failed_transfer() public
    {
        // Bob has no tokens and no approval.
        vm.expectRevert( abi.encodeWithSelector( TransferFailed.selector, bob, address(token), 100e18, alice ) );
        harness.exposed_transfer_erc20( IERC20(address(token)), bob, alice, 100e18 );
    }


    // ━━━━  transfer_erc20_and_get_amount_delivered() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_erc20_and_get_amount_delivered_zero_returns_zero() public
    {
        uint256 delivered  =  harness.exposed_transfer_erc20_and_get_amount_delivered( alice, IERC20(address(token)), 0, bob );

        assertEq( delivered, 0, "Zero transfer should return zero" );
    }

    function test_transfer_erc20_and_get_amount_delivered_from_self() public
    {
        uint256 amount  =  100e18;

        uint256 delivered  =  harness.exposed_transfer_erc20_and_get_amount_delivered( address(harness), IERC20(address(token)), amount, bob );

        assertEq( delivered, amount, "Should return delivered amount" );
        assertEq( token.balanceOf( bob ), amount, "Bob should receive tokens" );
    }

    function test_transfer_erc20_and_get_amount_delivered_from_external() public
    {
        uint256 amount  =  100e18;

        uint256 delivered  =  harness.exposed_transfer_erc20_and_get_amount_delivered( alice, IERC20(address(token)), amount, bob );

        assertEq( delivered, amount, "Should return delivered amount" );
        assertEq( token.balanceOf( bob ), amount, "Bob should receive tokens" );
    }

    function test_transfer_erc20_and_get_amount_delivered_reverts_on_failed_transfer() public
    {
        vm.expectRevert( abi.encodeWithSelector( TransferFailed.selector, bob, address(token), 100e18, alice ) );
        harness.exposed_transfer_erc20_and_get_amount_delivered( bob, IERC20(address(token)), 100e18, alice );
    }


    // ━━━━  transfer() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_routes_native_token() public
    {
        uint256 amount  =  1 ether;

        harness.exposed_transfer( NATIVE_TOKEN, address(harness), bob, amount );

        assertEq( bob.balance, amount, "Bob should receive native tokens via transfer()" );
    }

    function test_transfer_routes_erc20_token() public
    {
        uint256 amount  =  100e18;

        harness.exposed_transfer( IERC20(address(token)), address(harness), bob, amount );

        assertEq( token.balanceOf( bob ), amount, "Bob should receive ERC20 tokens via transfer()" );
    }
}
