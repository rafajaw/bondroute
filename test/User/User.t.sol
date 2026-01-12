// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { User, NativeAmountMismatch, InvalidSignature, EIP712Domain } from "@BondRoute/User.sol";
import { Invalid, BondCreated, ExecutionData } from "@BondRoute/Core.sol";
import { BondStatus } from "@BondRoute/Storage.sol";
import { IERC20, TokenAmount, IBondRouteProtected } from "@BondRouteProtected/BondRouteProtected.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockFeeOnTransferToken } from "@test/mocks/MockFeeOnTransferToken.sol";
import { MockProtocol } from "@test/mocks/MockProtocol.sol";
import { MockEIP1271Wallet } from "@test/mocks/MockEIP1271Wallet.sol";
import "@BondRoute/Definitions.sol";

/**
 * @title UserHarness
 * @notice Test harness exposing User's functions for testing
 */
contract UserHarness is User {

    constructor() {}

    function exposed_get_bond_info( bytes32 commitment_hash, TokenAmount memory stake ) external view returns ( BondInfo memory bond_info, bytes32 bond_key, uint256 packed_value )
    {
        return _get_bond_info( commitment_hash, stake );
    }
}

/**
 * @title UserTest
 * @notice Tests for User contract (user-facing bond operations)
 * @dev Implements IUserTests from TestManifest.sol
 */
contract UserTest is Test {

    UserHarness public user_harness;
    MockProtocol public mock_protocol;
    MockERC20 public usdc;
    MockERC20 public dai;
    MockFeeOnTransferToken public fee_token;
    MockEIP1271Wallet public eip1271_wallet;

    address public constant USER     =  address(0x1111);
    address public constant RELAYER  =  address(0x2222);
    uint256 public constant USER_PRIVATE_KEY  =  0xA11CE;

    function setUp() public
    {
        user_harness      =  new UserHarness();
        mock_protocol     =  new MockProtocol();
        usdc              =  new MockERC20( "USDC", "USDC" );
        dai               =  new MockERC20( "DAI", "DAI" );
        fee_token         =  new MockFeeOnTransferToken( "FEE", "FEE" );

        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );
        eip1271_wallet    =  new MockEIP1271Wallet( user_from_key );

        usdc.mint( USER, 1000e6 );
        usdc.mint( RELAYER, 1000e6 );
        dai.mint( USER, 1000e18 );
        fee_token.mint( USER, 1000e18 );

        vm.deal( USER, 100 ether );
        vm.deal( RELAYER, 100 ether );
        vm.deal( address(eip1271_wallet), 100 ether );

        vm.prank( USER );
        usdc.approve( address(user_harness), type(uint256).max );

        vm.prank( USER );
        dai.approve( address(user_harness), type(uint256).max );

        vm.prank( USER );
        fee_token.approve( address(user_harness), type(uint256).max );

        vm.prank( RELAYER );
        usdc.approve( address(user_harness), type(uint256).max );
    }


    // ━━━━  HELPER FUNCTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function _create_test_execution_data( TokenAmount memory stake, uint256 salt ) internal view returns ( ExecutionData memory )
    {
        return ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: salt,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });
    }


    // ━━━━  CREATE_BOND() TESTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_create_bond_with_erc20_stake() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 1 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        uint256 balance_before  =  usdc.balanceOf( USER );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        uint256 balance_after  =  usdc.balanceOf( USER );

        assertEq( balance_before - balance_after, 100e6, "Should transfer stake from user" );

        ( UserHarness.BondInfo memory bond_info, , )  =  user_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.ACTIVE), "Bond should be active" );
    }

    function test_create_bond_with_native_stake() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 2 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        uint256 balance_before  =  USER.balance;

        vm.prank( USER );
        user_harness.create_bond{ value: 1 ether }( commitment_hash, stake );

        uint256 balance_after  =  USER.balance;

        assertEq( balance_before - balance_after, 1 ether, "Should transfer native stake from user" );

        ( UserHarness.BondInfo memory bond_info, , )  =  user_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.ACTIVE), "Bond should be active" );
    }

    function test_create_bond_emits_correct_event() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 3 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.expectEmit( true, false, false, true );
        emit BondCreated( commitment_hash, address(usdc), 100e6 );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );
    }

    function test_create_bond_stores_correct_data() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 4 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        ( UserHarness.BondInfo memory bond_info, bytes32 bond_key, )  =  user_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( uint8(bond_info.status), uint8(BondStatus.ACTIVE), "Bond should be active" );
        assertEq( bond_info.creation_time, block.timestamp, "Creation time should match" );
        assertEq( bond_info.creation_block, block.number, "Creation block should match" );
        assertTrue( bond_key != bytes32(0), "Bond key should be generated" );
    }

    function test_create_bond_transfers_stake_from_user() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 5 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        uint256 user_balance_before  =  usdc.balanceOf( USER );
        uint256 contract_balance_before  =  usdc.balanceOf( address(user_harness) );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        uint256 user_balance_after  =  usdc.balanceOf( USER );
        uint256 contract_balance_after  =  usdc.balanceOf( address(user_harness) );

        assertEq( user_balance_before - user_balance_after, 100e6, "User should lose stake amount" );
        assertEq( contract_balance_after - contract_balance_before, 100e6, "Contract should gain stake amount" );
    }

    function test_create_bond_handles_fee_on_transfer_tokens() public
    {
        fee_token.set_fee_percentage( 5 );

        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(fee_token)), amount: 100e18 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 6 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        ( UserHarness.BondInfo memory bond_info, , )  =  user_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.stake_amount_received, 95e18, "Should store actual received amount after fee" );
    }

    function test_create_bond_reverts_on_zero_commitment_hash() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "commitment_hash", 0 ) );

        vm.prank( USER );
        user_harness.create_bond( bytes32(0), stake );
    }

    function test_create_bond_reverts_on_native_amount_mismatch() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 8 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.expectRevert( abi.encodeWithSelector( NativeAmountMismatch.selector, 0.5 ether, 1 ether ) );

        vm.prank( USER );
        user_harness.create_bond{ value: 0.5 ether }( commitment_hash, stake );
    }

    function test_create_bond_reverts_on_zero_erc20_stake() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 0 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 9 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "stake.amount", 0 ) );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );
    }

    function test_create_bond_reverts_on_native_sent_with_erc20_stake() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 50 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.expectRevert( abi.encodeWithSelector( NativeAmountMismatch.selector, 1 ether, 0 ) );

        vm.prank( USER );
        user_harness.create_bond{ value: 1 ether }( commitment_hash, stake );
    }

    function test_create_bond_reverts_on_reentrancy() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 10 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        // *ATTACK*  -  Configure token to re-enter create_bond during transfer.
        bytes memory reentrancy_call  =  abi.encodeCall(
            user_harness.create_bond,
            ( commitment_hash, stake )
        );
        usdc.set_reentrancy_call( address(user_harness), reentrancy_call );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        assertFalse( usdc.did_reentrancy_succeed(), "Reentrancy attack should fail - missing reentrancy guard!" );
    }


    // ━━━━  EXECUTE_BOND() TESTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_execute_bond_success_path() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 11 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, ) = user_harness.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );
    }

    function test_execute_bond_with_msg_value() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: stake,
            salt: 12,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, ) = user_harness.execute_bond{ value: 1 ether }( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed with msg.value" );
    }

    function test_execute_bond_delegates_to_internal() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 13 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, ) = user_harness.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should delegate to _execute_bond_internal" );

        ( UserHarness.BondInfo memory bond_info, , )  =  user_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.EXECUTED), "Bond should be marked as EXECUTED" );
    }

    function test_execute_bond_reverts_on_reentrancy() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 14 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        bytes memory reentrancy_call  =  abi.encodeCall(
            user_harness.execute_bond,
            ( execution_data )
        );
        usdc.set_reentrancy_call( address(user_harness), reentrancy_call );

        vm.prank( USER );
        user_harness.execute_bond( execution_data );

        assertFalse( usdc.did_reentrancy_succeed(), "Reentrancy attack should fail - missing reentrancy guard!" );
    }


    // ━━━━  EXECUTE_BOND_AS() TESTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_execute_bond_as_with_valid_signature() public
    {
        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );

        usdc.mint( user_from_key, 1000e6 );
        vm.prank( user_from_key );
        usdc.approve( address(user_harness), type(uint256).max );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 15 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( user_from_key, execution_data );

        vm.prank( user_from_key );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        vm.prank( RELAYER );
        ( BondStatus status, ) = user_harness.execute_bond_as( execution_data, user_from_key, signature, false );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed with valid signature" );
    }

    function test_execute_bond_as_with_eip1271_signature() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 16 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( address(eip1271_wallet), execution_data );

        usdc.mint( address(eip1271_wallet), 1000e6 );
        vm.prank( address(eip1271_wallet) );
        usdc.approve( address(user_harness), type(uint256).max );

        vm.prank( address(eip1271_wallet) );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        vm.prank( RELAYER );
        ( BondStatus status, ) = user_harness.execute_bond_as( execution_data, address(eip1271_wallet), signature, true );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed with EIP-1271 signature" );
    }

    function test_execute_bond_as_refunds_to_user_not_relayer() public
    {
        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );

        usdc.mint( user_from_key, 1000e6 );
        vm.prank( user_from_key );
        usdc.approve( address(user_harness), type(uint256).max );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 17 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( user_from_key, execution_data );

        vm.prank( user_from_key );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        uint256 user_balance_before  =  usdc.balanceOf( user_from_key );
        uint256 relayer_balance_before  =  usdc.balanceOf( RELAYER );

        vm.prank( RELAYER );
        user_harness.execute_bond_as( execution_data, user_from_key, signature, false );

        uint256 user_balance_after  =  usdc.balanceOf( user_from_key );
        uint256 relayer_balance_after  =  usdc.balanceOf( RELAYER );

        assertEq( user_balance_after, user_balance_before + 100e6, "User should receive stake refund" );
        assertEq( relayer_balance_after, relayer_balance_before, "Relayer should not receive refund" );
    }

    function test_execute_bond_as_relayer_fronts_stake() public
    {
        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 18 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( user_from_key, execution_data );

        usdc.mint( user_from_key, 100e6 );
        vm.prank( user_from_key );
        usdc.approve( address(user_harness), type(uint256).max );

        vm.prank( user_from_key );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        uint256 user_balance_before  =  usdc.balanceOf( user_from_key );

        vm.prank( RELAYER );
        ( BondStatus status, ) = user_harness.execute_bond_as( execution_data, user_from_key, signature, false );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );

        uint256 user_balance_after  =  usdc.balanceOf( user_from_key );
        assertEq( user_balance_after, user_balance_before + 100e6, "User should receive stake refund" );
    }

    function test_execute_bond_as_relayer_fronts_native_funding() public
    {
        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );

        usdc.mint( user_from_key, 1000e6 );
        vm.prank( user_from_key );
        usdc.approve( address(user_harness), type(uint256).max );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: stake,
            salt: 19,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( user_from_key, execution_data );

        vm.prank( user_from_key );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        vm.prank( RELAYER );
        ( BondStatus status, ) = user_harness.execute_bond_as{ value: 1 ether }( execution_data, user_from_key, signature, false );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed with relayer fronting native funding" );
    }

    function test_execute_bond_as_reverts_on_invalid_signature() public
    {
        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );

        usdc.mint( user_from_key, 1000e6 );
        vm.prank( user_from_key );
        usdc.approve( address(user_harness), type(uint256).max );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 20 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( user_from_key, execution_data );

        vm.prank( user_from_key );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        bytes memory invalid_signature  =  abi.encodePacked( bytes32(0), bytes32(0), uint8(27) );

        vm.expectRevert( InvalidSignature.selector );

        vm.prank( RELAYER );
        user_harness.execute_bond_as( execution_data, user_from_key, invalid_signature, false );
    }

    function test_execute_bond_as_reverts_on_wrong_signer() public
    {
        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );
        uint256 wrong_private_key  =  0xBAD;

        usdc.mint( user_from_key, 1000e6 );
        vm.prank( user_from_key );
        usdc.approve( address(user_harness), type(uint256).max );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 21 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( user_from_key, execution_data );

        vm.prank( user_from_key );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( wrong_private_key, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        vm.expectRevert( InvalidSignature.selector );

        vm.prank( RELAYER );
        user_harness.execute_bond_as( execution_data, user_from_key, signature, false );
    }

    function test_execute_bond_as_reverts_on_reentrancy() public
    {
        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );

        usdc.mint( user_from_key, 1000e6 );
        vm.prank( user_from_key );
        usdc.approve( address(user_harness), type(uint256).max );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 22 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( user_from_key, execution_data );

        vm.prank( user_from_key );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        bytes memory reentrancy_call  =  abi.encodeCall(
            user_harness.execute_bond_as,
            ( execution_data, user_from_key, signature, false )
        );
        usdc.set_reentrancy_call( address(user_harness), reentrancy_call );

        vm.prank( RELAYER );
        user_harness.execute_bond_as( execution_data, user_from_key, signature, false );

        assertFalse( usdc.did_reentrancy_succeed(), "Reentrancy attack should fail - missing reentrancy guard!" );
    }


    // ━━━━  OFF-CHAIN HELPER FUNCTION TESTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_calc_commitment_hash_deterministic() public view
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 23 );

        bytes32 hash1  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
        bytes32 hash2  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        assertEq( hash1, hash2, "Should return deterministic hash" );
    }

    function test_calc_commitment_hash_different_users_different_hash() public view
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 24 );

        bytes32 hash_user1  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
        bytes32 hash_user2  =  user_harness.__OFF_CHAIN__calc_commitment_hash( RELAYER, execution_data );

        assertTrue( hash_user1 != hash_user2, "Different users should produce different hashes" );
    }

    function test_calc_commitment_hash_different_salt_different_hash() public view
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data1  =  _create_test_execution_data( stake, 25 );
        ExecutionData memory execution_data2  =  _create_test_execution_data( stake, 26 );

        bytes32 hash1  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data1 );
        bytes32 hash2  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data2 );

        assertTrue( hash1 != hash2, "Different salts should produce different hashes" );
    }

    function test_calc_commitment_hash_reverts_on_zero_user() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 51 );

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "user", 0 ) );
        user_harness.__OFF_CHAIN__calc_commitment_hash( address(0), execution_data );
    }

    function test_calc_commitment_hash_reverts_on_invalid_execution() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 52 );

        // Set protocol to precompile address (invalid).
        execution_data.protocol  =  IBondRouteProtected(address(1));

        vm.expectRevert( "Invalid protocol or call" );
        user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
    }

    function test_get_bond_info_helper_matches_internal() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 27 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        UserHarness.BondInfo memory bond_info_helper  =  user_harness.__OFF_CHAIN__get_bond_info( commitment_hash, stake );
        ( UserHarness.BondInfo memory bond_info_internal, , )  =  user_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info_helper.creation_time, bond_info_internal.creation_time, "Creation times should match" );
        assertEq( bond_info_helper.creation_block, bond_info_internal.creation_block, "Creation blocks should match" );
        assertEq( bond_info_helper.stake_amount_received, bond_info_internal.stake_amount_received, "Stake amounts should match" );
        assertEq( uint8(bond_info_helper.status), uint8(bond_info_internal.status), "Statuses should match" );
    }

    function test_get_signing_info_returns_complete_data() public view
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 28 );

        ( bytes32 digest, bytes32 type_hash, string memory type_string, EIP712Domain memory domain )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );

        assertTrue( digest != bytes32(0), "Digest should not be zero" );
        assertTrue( type_hash != bytes32(0), "Type hash should not be zero" );
        assertTrue( bytes(type_string).length > 0, "Type string should not be empty" );
        assertTrue( bytes(domain.name).length > 0, "Domain name should not be empty" );
        assertTrue( bytes(domain.version).length > 0, "Domain version should not be empty" );
        assertTrue( domain.chainId != 0, "Chain ID should not be zero" );
        assertTrue( domain.verifyingContract != address(0), "Verifying contract should not be zero" );
    }

    function test_get_signing_info_domain_matches_deployed() public view
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 29 );

        ( , , , EIP712Domain memory domain )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );

        assertEq( domain.verifyingContract, address(user_harness), "Verifying contract should be deployed harness address" );
        assertEq( domain.chainId, block.chainid, "Chain ID should match current chain" );
    }


    // ━━━━  EXECUTE_BOND() RETURN VALUES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_execute_bond_returns_status_and_output() public
    {
        bytes memory expected_output  =  abi.encode( uint256(123), address(0xBEEF) );
        mock_protocol.set_return_data( expected_output );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 30 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, bytes memory output ) = user_harness.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should return EXECUTED status" );
        assertEq( output, expected_output, "Should return protocol output" );
    }

    function test_execute_bond_output_matches_protocol_return() public
    {
        uint256 expected_value  =  999;
        bool expected_flag  =  true;
        bytes memory protocol_return  =  abi.encode( expected_value, expected_flag );
        mock_protocol.set_return_data( protocol_return );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 31 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, bytes memory output ) = user_harness.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed" );

        ( uint256 decoded_value, bool decoded_flag )  =  abi.decode( output, (uint256, bool) );
        assertEq( decoded_value, expected_value, "Decoded value should match protocol return" );
        assertEq( decoded_flag, expected_flag, "Decoded flag should match protocol return" );
    }


    // ━━━━  EXECUTE_BOND_AS() RETURN VALUES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_execute_bond_as_returns_status_and_output() public
    {
        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );

        bytes memory expected_output  =  abi.encode( uint256(777), bytes32(uint256(0xDEADBEEF)) );
        mock_protocol.set_return_data( expected_output );

        usdc.mint( user_from_key, 1000e6 );
        vm.prank( user_from_key );
        usdc.approve( address(user_harness), type(uint256).max );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 32 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( user_from_key, execution_data );

        vm.prank( user_from_key );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        vm.prank( RELAYER );
        ( BondStatus status, bytes memory output ) = user_harness.execute_bond_as( execution_data, user_from_key, signature, false );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should return EXECUTED status" );
        assertEq( output, expected_output, "Should return protocol output" );
    }

    function test_execute_bond_as_output_composable_for_smart_wallets() public
    {
        address user_from_key  =  vm.addr( USER_PRIVATE_KEY );

        address[] memory tokens  =  new address[](3);
        tokens[ 0 ]  =  address(usdc);
        tokens[ 1 ]  =  address(dai);
        tokens[ 2 ]  =  address(0xCAFE);

        uint256[] memory amounts  =  new uint256[](3);
        amounts[ 0 ]  =  1000e6;
        amounts[ 1 ]  =  500e18;
        amounts[ 2 ]  =  250e18;

        bytes memory smart_wallet_return  =  abi.encode( tokens, amounts, true );
        mock_protocol.set_return_data( smart_wallet_return );

        usdc.mint( user_from_key, 1000e6 );
        vm.prank( user_from_key );
        usdc.approve( address(user_harness), type(uint256).max );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  _create_test_execution_data( stake, 33 );

        bytes32 commitment_hash  =  user_harness.__OFF_CHAIN__calc_commitment_hash( user_from_key, execution_data );

        vm.prank( user_from_key );
        user_harness.create_bond( commitment_hash, stake );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  user_harness.__OFF_CHAIN__get_signing_info( execution_data );
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        vm.prank( RELAYER );
        ( BondStatus status, bytes memory output ) = user_harness.execute_bond_as( execution_data, user_from_key, signature, false );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed" );

        ( address[] memory decoded_tokens, uint256[] memory decoded_amounts, bool decoded_success )  =  abi.decode( output, (address[], uint256[], bool) );

        assertEq( decoded_tokens.length, 3, "Should decode token array" );
        assertEq( decoded_tokens[ 0 ], address(usdc), "Token 0 should match" );
        assertEq( decoded_tokens[ 1 ], address(dai), "Token 1 should match" );
        assertEq( decoded_tokens[ 2 ], address(0xCAFE), "Token 2 should match" );

        assertEq( decoded_amounts.length, 3, "Should decode amounts array" );
        assertEq( decoded_amounts[ 0 ], 1000e6, "Amount 0 should match" );
        assertEq( decoded_amounts[ 1 ], 500e18, "Amount 1 should match" );
        assertEq( decoded_amounts[ 2 ], 250e18, "Amount 2 should match" );

        assertEq( decoded_success, true, "Success flag should match" );
    }
}
