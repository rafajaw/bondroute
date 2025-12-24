// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import { Sweeper, NewSweeperAppointed, NewSweeper, BondLiquidated, ThankYou, TipsClaimed, BondNotExpired } from "@BondRoute/Sweeper.sol";
import { BondAlreadySettled, BondStatus } from "@BondRoute/Storage.sol";
import { Invalid } from "@BondRoute/Core.sol";
import { Unauthorized } from "@BondRouteProtected/BondRouteProtected.sol";
import { NativeAmountMismatch } from "@BondRoute/User.sol";
import { IERC20, TokenAmount } from "@BondRouteProtected/BondRouteProtected.sol";
import { EIP1153Detector } from "@EIP1153Detector/EIP1153Detector.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockFeeOnTransferToken } from "@test/mocks/MockFeeOnTransferToken.sol";
import "@BondRoute/Definitions.sol";

/**
 * @title SweeperHarness
 * @notice Test harness exposing Sweeper's internal functions for testing
 */
contract SweeperHarness is Sweeper {

    constructor( address sweeper, address eip1153_detector ) Sweeper( sweeper, eip1153_detector ) {}

    function exposed_create_bond_internal( bytes32 commitment_hash, TokenAmount memory stake, uint256 amount_received ) external
    {
        _create_bond_internal( commitment_hash, stake, amount_received );
    }

    function exposed_set_bond_status( bytes32 bond_key, uint256 previous_packed_value, BondStatus new_status ) external
    {
        _set_bond_status( bond_key, previous_packed_value, new_status );
    }

    function exposed_get_bond_info( bytes32 commitment_hash, TokenAmount memory stake ) external view returns ( BondInfo memory bond_info, bytes32 bond_key, uint256 packed_value )
    {
        return _get_bond_info( commitment_hash, stake );
    }

    function exposed_get_sweeper() external view returns ( address )
    {
        return _sweeper;
    }

    function exposed_get_pending_sweeper() external view returns ( address )
    {
        return _pending_sweeper;
    }

    function exposed_get_accumulated_tips( IERC20 token ) external view returns ( uint256 )
    {
        return _accumulated_tips[ token ];
    }
}

/**
 * @title SweeperTest
 * @notice Tests for Sweeper contract (expired bond liquidation and tip management)
 * @dev Implements ISweeperTests from TestManifest.sol
 */
contract SweeperTest is Test {

    SweeperHarness public sweeper_harness;
    EIP1153Detector public eip1153_detector;
    MockERC20 public usdc;
    MockERC20 public dai;
    MockFeeOnTransferToken public fee_token;

    address public constant SWEEPER      =  address(0x5555);
    address public constant NEW_SWEEPER  =  address(0x6666);
    address public constant RECIPIENT  =  address(0x7777);
    address public constant USER         =  address(0x1111);

    function setUp() public
    {
        eip1153_detector  =  new EIP1153Detector();
        sweeper_harness   =  new SweeperHarness( SWEEPER, address(eip1153_detector) );
        usdc              =  new MockERC20( "USDC", "USDC" );
        dai               =  new MockERC20( "DAI", "DAI" );
        fee_token         =  new MockFeeOnTransferToken( "FeeToken", "FEE" );
        fee_token.set_fee_percentage( 1 );

        usdc.mint( USER, 10000e6 );
        usdc.mint( address(sweeper_harness), 10000e6 );
        dai.mint( USER, 10000e18 );
        dai.mint( address(sweeper_harness), 10000e18 );
        fee_token.mint( USER, 10000e18 );
        fee_token.mint( address(sweeper_harness), 10000e18 );

        vm.deal( USER, 100 ether );
        vm.deal( address(sweeper_harness), 100 ether );
        vm.deal( SWEEPER, 10 ether );
        vm.deal( RECIPIENT, 1 ether );
    }


    // ━━━━  HELPER FUNCTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function _create_expired_bond( TokenAmount memory stake, uint256 amount_received ) internal returns ( bytes32 commitment_hash )
    {
        commitment_hash  =  keccak256( abi.encodePacked( "test_commitment", block.timestamp ) );
        sweeper_harness.exposed_create_bond_internal( commitment_hash, stake, amount_received );

        vm.warp( block.timestamp + MAX_BOND_LIFETIME + 1 );
    }

    function _create_not_yet_expired_bond( TokenAmount memory stake, uint256 amount_received ) internal returns ( bytes32 commitment_hash )
    {
        commitment_hash  =  keccak256( abi.encodePacked( "test_commitment", block.timestamp ) );
        sweeper_harness.exposed_create_bond_internal( commitment_hash, stake, amount_received );
    }


    // ━━━━  SWEEPER ROLE MANAGEMENT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_constructor_sets_initial_sweeper() public view
    {
        address initial_sweeper  =  sweeper_harness.exposed_get_sweeper();
        assertEq( initial_sweeper, SWEEPER, "Constructor should set initial sweeper" );
    }

    function test_constructor_reverts_on_zero_sweeper() public
    {
        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "sweeper", 0 ) );
        new SweeperHarness( address(0), address(eip1153_detector) );
    }

    function test_appoint_new_sweeper_success() public
    {
        vm.prank( SWEEPER );
        sweeper_harness.appoint_new_sweeper( NEW_SWEEPER );

        address pending  =  sweeper_harness.exposed_get_pending_sweeper();
        assertEq( pending, NEW_SWEEPER, "Should set pending sweeper" );
    }

    function test_appoint_new_sweeper_emits_event() public
    {
        vm.expectEmit( true, false, false, false );
        emit NewSweeperAppointed( NEW_SWEEPER );

        vm.prank( SWEEPER );
        sweeper_harness.appoint_new_sweeper( NEW_SWEEPER );
    }

    function test_appoint_new_sweeper_reverts_if_not_sweeper() public
    {
        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, SWEEPER ) );

        vm.prank( USER );
        sweeper_harness.appoint_new_sweeper( NEW_SWEEPER );
    }

    function test_appoint_new_sweeper_reverts_on_zero_address() public
    {
        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "new_sweeper", 0 ) );

        vm.prank( SWEEPER );
        sweeper_harness.appoint_new_sweeper( address(0) );
    }

    function test_claim_sweeper_role_success() public
    {
        vm.prank( SWEEPER );
        sweeper_harness.appoint_new_sweeper( NEW_SWEEPER );

        vm.prank( NEW_SWEEPER );
        sweeper_harness.claim_sweeper_role();

        address current_sweeper  =  sweeper_harness.exposed_get_sweeper();
        assertEq( current_sweeper, NEW_SWEEPER, "Should update current sweeper" );
    }

    function test_claim_sweeper_role_emits_event() public
    {
        vm.prank( SWEEPER );
        sweeper_harness.appoint_new_sweeper( NEW_SWEEPER );

        vm.expectEmit( true, false, false, false );
        emit NewSweeper( NEW_SWEEPER );

        vm.prank( NEW_SWEEPER );
        sweeper_harness.claim_sweeper_role();
    }

    function test_claim_sweeper_role_reverts_if_not_pending() public
    {
        vm.prank( SWEEPER );
        sweeper_harness.appoint_new_sweeper( NEW_SWEEPER );

        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, NEW_SWEEPER ) );

        vm.prank( USER );
        sweeper_harness.claim_sweeper_role();
    }

    function test_claim_sweeper_role_clears_pending() public
    {
        vm.prank( SWEEPER );
        sweeper_harness.appoint_new_sweeper( NEW_SWEEPER );

        vm.prank( NEW_SWEEPER );
        sweeper_harness.claim_sweeper_role();

        address pending  =  sweeper_harness.exposed_get_pending_sweeper();
        assertEq( pending, address(0), "Should clear pending sweeper" );
    }


    // ━━━━  LIQUIDATE EXPIRED BONDS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_liquidate_expired_bonds_single_bond() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        uint256 recipient_balance_before  =  usdc.balanceOf( RECIPIENT );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        uint256 recipient_balance_after  =  usdc.balanceOf( RECIPIENT );
        assertEq( recipient_balance_after, recipient_balance_before + 100e6, "Recipient should receive stake" );
    }

    function test_liquidate_expired_bonds_with_native_stake() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 1 ether );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        uint256 recipient_balance_before  =  RECIPIENT.balance;

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        uint256 recipient_balance_after  =  RECIPIENT.balance;
        assertEq( recipient_balance_after, recipient_balance_before + 1 ether, "Recipient should receive native stake" );

        ( SweeperHarness.BondInfo memory bond_info, , )  =  sweeper_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.LIQUIDATED), "Bond should be marked as liquidated" );
    }

    function test_liquidate_expired_bonds_multiple_bonds() public
    {
        TokenAmount memory stake1  =  TokenAmount({ token: usdc, amount: 100e6 });
        TokenAmount memory stake2  =  TokenAmount({ token: dai, amount: 200e18 });

        bytes32 commitment_hash1  =  _create_expired_bond( stake1, 100e6 );

        vm.warp( block.timestamp + 10 );

        bytes32 commitment_hash2  =  _create_expired_bond( stake2, 200e18 );

        bytes32[] memory commitment_hashes  =  new bytes32[](2);
        commitment_hashes[ 0 ]  =  commitment_hash1;
        commitment_hashes[ 1 ]  =  commitment_hash2;

        TokenAmount[] memory stakes  =  new TokenAmount[](2);
        stakes[ 0 ]  =  stake1;
        stakes[ 1 ]  =  stake2;

        uint256 usdc_balance_before  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_before   =  dai.balanceOf( RECIPIENT );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        uint256 usdc_balance_after  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_after   =  dai.balanceOf( RECIPIENT );

        assertEq( usdc_balance_after, usdc_balance_before + 100e6, "Recipient should receive USDC stake" );
        assertEq( dai_balance_after, dai_balance_before + 200e18, "Recipient should receive DAI stake" );
    }

    function test_liquidate_expired_bonds_emits_events() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.expectEmit( true, true, true, true );
        emit BondLiquidated( commitment_hash, usdc, 100e6, RECIPIENT );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
    }

    function test_liquidate_expired_bonds_transfers_stakes() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        uint256 contract_balance_before   =  usdc.balanceOf( address(sweeper_harness) );
        uint256 recipient_balance_before  =  usdc.balanceOf( RECIPIENT );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        uint256 contract_balance_after   =  usdc.balanceOf( address(sweeper_harness) );
        uint256 recipient_balance_after  =  usdc.balanceOf( RECIPIENT );

        assertEq( contract_balance_after, contract_balance_before - 100e6, "Contract should lose stake" );
        assertEq( recipient_balance_after, recipient_balance_before + 100e6, "Recipient should gain stake" );
    }

    function test_liquidate_expired_bonds_marks_as_liquidated() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        ( SweeperHarness.BondInfo memory bond_info, , )  =  sweeper_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.LIQUIDATED), "Bond should be marked as liquidated" );
    }

    function test_liquidate_expired_bonds_reverts_if_not_sweeper() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, SWEEPER ) );

        vm.prank( USER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
    }

    function test_liquidate_expired_bonds_reverts_on_zero_recipient() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "recipient", 0 ) );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, address(0) );
    }

    function test_liquidate_expired_bonds_reverts_on_array_mismatch() public
    {
        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  keccak256( "test" );

        TokenAmount[] memory stakes  =  new TokenAmount[](2);
        stakes[ 0 ]  =  TokenAmount({ token: usdc, amount: 100e6 });
        stakes[ 1 ]  =  TokenAmount({ token: dai, amount: 200e18 });

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "array_length_mismatch", 0 ) );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
    }

    function test_liquidate_expired_bonds_reverts_if_not_expired() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_not_yet_expired_bond( stake, 100e6 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        uint256 expected_expiration  =  block.timestamp + MAX_BOND_LIFETIME;

        vm.expectRevert( abi.encodeWithSelector( BondNotExpired.selector, expected_expiration ) );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
    }

    function test_liquidate_expired_bonds_reverts_if_already_executed() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        ( , bytes32 bond_key, uint256 packed_value )  =  sweeper_harness.exposed_get_bond_info( commitment_hash, stake );
        sweeper_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.EXECUTED );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.expectRevert( abi.encodeWithSelector( BondAlreadySettled.selector, BondStatus.EXECUTED ) );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
    }

    function test_liquidate_expired_bonds_reverts_if_already_liquidated() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        ( , bytes32 bond_key, uint256 packed_value )  =  sweeper_harness.exposed_get_bond_info( commitment_hash, stake );
        sweeper_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.LIQUIDATED );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.expectRevert( abi.encodeWithSelector( BondAlreadySettled.selector, BondStatus.LIQUIDATED ) );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
    }

    function test_liquidate_expired_bonds_reverts_on_reentrancy() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        bytes32[] memory hashes  =  new bytes32[](1);
        hashes[ 0 ]  =  commitment_hash;

        bytes memory reentrancy_call  =  abi.encodeCall(
            sweeper_harness.liquidate_expired_bonds,
            ( hashes, stakes, RECIPIENT )
        );
        usdc.set_reentrancy_call( address(sweeper_harness), reentrancy_call );

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( hashes, stakes, RECIPIENT );

        assertFalse( usdc.did_reentrancy_succeed(), "Reentrancy attack should fail - missing reentrancy guard!" );
    }

    function test_liquidate_expired_bonds_exactly_at_expiration() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_not_yet_expired_bond( stake, 100e6 );

        vm.warp( block.timestamp + MAX_BOND_LIFETIME );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        ( SweeperHarness.BondInfo memory bond_info, , )  =  sweeper_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.LIQUIDATED), "Should liquidate at exact expiration" );
    }

    function test_liquidate_expired_bonds_one_second_after_expiration() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_not_yet_expired_bond( stake, 100e6 );

        vm.warp( block.timestamp + MAX_BOND_LIFETIME + 1 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.prank( SWEEPER );
        sweeper_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        ( SweeperHarness.BondInfo memory bond_info, , )  =  sweeper_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.LIQUIDATED), "Should liquidate one second after expiration" );
    }


    // ━━━━  TIP()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_tip_with_erc20() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        uint256 accumulated  =  sweeper_harness.exposed_get_accumulated_tips( usdc );
        assertEq( accumulated, 100e6, "Should accumulate ERC20 tip" );
    }

    function test_tip_with_native() public
    {
        vm.prank( USER );
        sweeper_harness.tip{ value: 1 ether }( IERC20(address(0)), 1 ether, "" );

        uint256 accumulated  =  sweeper_harness.exposed_get_accumulated_tips( IERC20(address(0)) );
        assertEq( accumulated, 1 ether, "Should accumulate native tip" );
    }

    function test_tip_with_message() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.expectEmit( true, true, false, true );
        emit ThankYou( USER, usdc, 100e6, "Thank you!" );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "Thank you!" );
    }

    function test_tip_without_message() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.expectEmit( true, true, false, true );
        emit ThankYou( USER, usdc, 100e6, "" );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );
    }

    function test_tip_emits_event() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.expectEmit( true, true, false, true );
        emit ThankYou( USER, usdc, 100e6, "Great work!" );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "Great work!" );
    }

    function test_tip_accumulates_correctly() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 300e6 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 200e6, "" );

        uint256 accumulated  =  sweeper_harness.exposed_get_accumulated_tips( usdc );
        assertEq( accumulated, 300e6, "Should accumulate multiple tips" );
    }

    function test_tip_handles_fee_on_transfer() public
    {
        vm.prank( USER );
        fee_token.approve( address(sweeper_harness), 1000e18 );

        vm.prank( USER );
        sweeper_harness.tip( IERC20(address(fee_token)), 1000e18, "" );

        uint256 accumulated  =  sweeper_harness.exposed_get_accumulated_tips( IERC20(address(fee_token)) );
        assertEq( accumulated, 990e18, "Should accumulate actual received amount after fee" );
    }

    function test_tip_reverts_on_zero_amount() public
    {
        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "amount", 0 ) );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 0, "" );
    }

    function test_tip_reverts_on_message_too_long() public
    {
        string memory long_message  =  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "message.length", bytes(long_message).length ) );

        vm.prank( USER );
        sweeper_harness.tip{ value: 1 ether }( IERC20(address(0)), 1 ether, long_message );
    }

    function test_tip_reverts_on_native_amount_mismatch() public
    {
        vm.expectRevert( abi.encodeWithSelector( NativeAmountMismatch.selector, 0.5 ether, 1 ether ) );

        vm.prank( USER );
        sweeper_harness.tip{ value: 0.5 ether }( IERC20(address(0)), 1 ether, "" );
    }

    function test_tip_reverts_on_reentrancy() public
    {
        bytes memory reentrancy_call  =  abi.encodeCall(
            sweeper_harness.tip,
            ( IERC20(address(usdc)), 100e6, "Reentrancy attack!" )
        );
        usdc.set_reentrancy_call( address(sweeper_harness), reentrancy_call );

        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        sweeper_harness.tip( IERC20(address(usdc)), 100e6, "Initial tip" );

        assertFalse( usdc.did_reentrancy_succeed(), "Reentrancy attack should fail - missing reentrancy guard!" );
    }


    // ━━━━  GET_CLAIMABLE_TIPS()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_get_claimable_tips_returns_zero_when_none() public view
    {
        uint256 claimable  =  sweeper_harness.get_claimable_tips( usdc );
        assertEq( claimable, 0, "Should return zero when no tips" );
    }

    function test_get_claimable_tips_returns_zero_when_only_dust() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 1 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 1, "" );

        uint256 claimable  =  sweeper_harness.get_claimable_tips( usdc );
        assertEq( claimable, 0, "Should return zero when only 1 wei (dust)" );
    }

    function test_get_claimable_tips_excludes_dust() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        uint256 claimable  =  sweeper_harness.get_claimable_tips( usdc );
        assertEq( claimable, 100e6 - 1, "Should exclude 1 wei dust" );
    }

    function test_get_claimable_tips_multiple_tokens() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        dai.approve( address(sweeper_harness), 200e18 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        vm.prank( USER );
        sweeper_harness.tip( dai, 200e18, "" );

        uint256 usdc_claimable  =  sweeper_harness.get_claimable_tips( usdc );
        uint256 dai_claimable   =  sweeper_harness.get_claimable_tips( dai );

        assertEq( usdc_claimable, 100e6 - 1, "Should return USDC claimable" );
        assertEq( dai_claimable, 200e18 - 1, "Should return DAI claimable" );
    }


    // ━━━━  CLAIM_ACCUMULATED_TIPS()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_claim_accumulated_tips_single_token() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        uint256 recipient_balance_before  =  usdc.balanceOf( RECIPIENT );

        vm.prank( SWEEPER );
        sweeper_harness.claim_accumulated_tips( tokens, RECIPIENT );

        uint256 recipient_balance_after  =  usdc.balanceOf( RECIPIENT );
        assertEq( recipient_balance_after, recipient_balance_before + 100e6 - 1, "Recipient should receive tips minus dust" );
    }

    function test_claim_accumulated_tips_multiple_tokens() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        dai.approve( address(sweeper_harness), 200e18 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        vm.prank( USER );
        sweeper_harness.tip( dai, 200e18, "" );

        IERC20[] memory tokens  =  new IERC20[](2);
        tokens[ 0 ]  =  usdc;
        tokens[ 1 ]  =  dai;

        uint256 usdc_balance_before  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_before   =  dai.balanceOf( RECIPIENT );

        vm.prank( SWEEPER );
        sweeper_harness.claim_accumulated_tips( tokens, RECIPIENT );

        uint256 usdc_balance_after  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_after   =  dai.balanceOf( RECIPIENT );

        assertEq( usdc_balance_after, usdc_balance_before + 100e6 - 1, "Recipient should receive USDC tips" );
        assertEq( dai_balance_after, dai_balance_before + 200e18 - 1, "Recipient should receive DAI tips" );
    }

    function test_claim_accumulated_tips_leaves_dust() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        vm.prank( SWEEPER );
        sweeper_harness.claim_accumulated_tips( tokens, RECIPIENT );

        uint256 accumulated  =  sweeper_harness.exposed_get_accumulated_tips( usdc );
        assertEq( accumulated, 1, "Should leave 1 wei dust" );
    }

    function test_claim_accumulated_tips_emits_events() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        vm.expectEmit( true, false, true, true );
        emit TipsClaimed( address(usdc), 100e6 - 1, RECIPIENT );

        vm.prank( SWEEPER );
        sweeper_harness.claim_accumulated_tips( tokens, RECIPIENT );
    }

    function test_claim_accumulated_tips_transfers_correctly() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        uint256 contract_balance_before  =  usdc.balanceOf( address(sweeper_harness) );
        uint256 recipient_balance_before  =  usdc.balanceOf( RECIPIENT );

        vm.prank( SWEEPER );
        sweeper_harness.claim_accumulated_tips( tokens, RECIPIENT );

        uint256 contract_balance_after  =  usdc.balanceOf( address(sweeper_harness) );
        uint256 recipient_balance_after  =  usdc.balanceOf( RECIPIENT );

        assertEq( contract_balance_after, contract_balance_before - (100e6 - 1), "Contract should lose tips" );
        assertEq( recipient_balance_after, recipient_balance_before + (100e6 - 1), "Recipient should gain tips" );
    }

    function test_claim_accumulated_tips_reverts_if_not_sweeper() public
    {
        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, SWEEPER ) );

        vm.prank( USER );
        sweeper_harness.claim_accumulated_tips( tokens, RECIPIENT );
    }

    function test_claim_accumulated_tips_reverts_on_zero_recipient() public
    {
        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "recipient", 0 ) );

        vm.prank( SWEEPER );
        sweeper_harness.claim_accumulated_tips( tokens, address(0) );
    }

    function test_claim_accumulated_tips_reverts_on_empty_array() public
    {
        IERC20[] memory tokens  =  new IERC20[](0);

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "tokens.length", 0 ) );

        vm.prank( SWEEPER );
        sweeper_harness.claim_accumulated_tips( tokens, RECIPIENT );
    }

    function test_claim_accumulated_tips_reverts_on_reentrancy() public
    {
        // Setup: Accumulate some tips.
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 1000e6 );

        vm.prank( USER );
        sweeper_harness.tip( IERC20(address(usdc)), 1000e6, "Setup tip" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        bytes memory reentrancy_call  =  abi.encodeCall(
            sweeper_harness.claim_accumulated_tips,
            ( tokens, RECIPIENT )
        );
        usdc.set_reentrancy_call( address(sweeper_harness), reentrancy_call );

        vm.prank( SWEEPER );
        sweeper_harness.claim_accumulated_tips( tokens, RECIPIENT );

        assertFalse( usdc.did_reentrancy_succeed(), "Reentrancy attack should fail - missing reentrancy guard!" );
    }

    function test_claim_accumulated_tips_skips_tokens_with_no_tips() public
    {
        vm.prank( USER );
        usdc.approve( address(sweeper_harness), 100e6 );

        vm.prank( USER );
        sweeper_harness.tip( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](2);
        tokens[ 0 ]  =  usdc;
        tokens[ 1 ]  =  dai;

        uint256 usdc_balance_before  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_before   =  dai.balanceOf( RECIPIENT );

        vm.prank( SWEEPER );
        sweeper_harness.claim_accumulated_tips( tokens, RECIPIENT );

        uint256 usdc_balance_after  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_after   =  dai.balanceOf( RECIPIENT );

        assertEq( usdc_balance_after, usdc_balance_before + 100e6 - 1, "Should claim USDC tips" );
        assertEq( dai_balance_after, dai_balance_before, "Should skip DAI with no tips" );
    }
}
