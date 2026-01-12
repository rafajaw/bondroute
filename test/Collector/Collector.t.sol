// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import { Collector, NewCollectorAppointed, NewCollector, BondLiquidated, AirdropReceived, AirdropCredited, AirdropClaimed, BondNotExpired } from "@BondRoute/Collector.sol";
import { BondAlreadySettled, BondStatus } from "@BondRoute/Storage.sol";
import { Invalid } from "@BondRoute/Core.sol";
import { Unauthorized } from "@BondRouteProtected/BondRouteProtected.sol";
import { NativeAmountMismatch } from "@BondRoute/User.sol";
import { IERC20, TokenAmount } from "@BondRouteProtected/BondRouteProtected.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockFeeOnTransferToken } from "@test/mocks/MockFeeOnTransferToken.sol";
import { MockProtocolToken } from "@test/mocks/MockProtocolToken.sol";
import "@BondRoute/Definitions.sol";

/**
 * @title CollectorHarness
 * @notice Test harness exposing Collector's internal functions for testing
 */
contract CollectorHarness is Collector {

    constructor( address collector ) Collector( collector ) {}

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

    function exposed_get_collector() external view returns ( address )
    {
        return _collector;
    }

    function exposed_get_pending_collector() external view returns ( address )
    {
        return _pending_collector;
    }

    function exposed_get_accumulated_airdrops( IERC20 token ) external view returns ( uint256 )
    {
        return _accumulated_airdrops[ token ];
    }
}

/**
 * @title CollectorTest
 * @notice Tests for Collector contract (expired bond liquidation and airdrop management)
 * @dev Implements ICollectorTests from TestManifest.sol
 */
contract CollectorTest is Test {

    CollectorHarness public collector_harness;
    MockERC20 public usdc;
    MockERC20 public dai;
    MockFeeOnTransferToken public fee_token;
    MockProtocolToken public protocol_token;

    address public constant COLLECTOR      =  address(0x5555);
    address public constant NEW_COLLECTOR  =  address(0x6666);
    address public constant RECIPIENT      =  address(0x7777);
    address public constant USER           =  address(0x1111);

    function setUp() public
    {
        collector_harness =  new CollectorHarness( COLLECTOR );
        usdc              =  new MockERC20( "USDC", "USDC" );
        dai               =  new MockERC20( "DAI", "DAI" );
        fee_token         =  new MockFeeOnTransferToken( "FeeToken", "FEE" );
        fee_token.set_fee_percentage( 1 );
        protocol_token    =  new MockProtocolToken( "ProtocolToken", "PTOK" );
        protocol_token.set_collector( address(collector_harness) );

        usdc.mint( USER, 10000e6 );
        usdc.mint( address(collector_harness), 10000e6 );
        dai.mint( USER, 10000e18 );
        dai.mint( address(collector_harness), 10000e18 );
        fee_token.mint( USER, 10000e18 );
        fee_token.mint( address(collector_harness), 10000e18 );

        vm.deal( USER, 100 ether );
        vm.deal( address(collector_harness), 100 ether );
        vm.deal( COLLECTOR, 10 ether );
        vm.deal( RECIPIENT, 1 ether );
    }


    // ━━━━  HELPER FUNCTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function _create_expired_bond( TokenAmount memory stake, uint256 amount_received ) internal returns ( bytes32 commitment_hash )
    {
        commitment_hash  =  keccak256( abi.encodePacked( "test_commitment", block.timestamp ) );
        collector_harness.exposed_create_bond_internal( commitment_hash, stake, amount_received );

        vm.warp( block.timestamp + MAX_BOND_LIFETIME + 1 );
    }

    function _create_not_yet_expired_bond( TokenAmount memory stake, uint256 amount_received ) internal returns ( bytes32 commitment_hash )
    {
        commitment_hash  =  keccak256( abi.encodePacked( "test_commitment", block.timestamp ) );
        collector_harness.exposed_create_bond_internal( commitment_hash, stake, amount_received );
    }


    // ━━━━  COLLECTOR ROLE MANAGEMENT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_constructor_sets_initial_collector() public view
    {
        address initial_collector  =  collector_harness.exposed_get_collector();
        assertEq( initial_collector, COLLECTOR, "Constructor should set initial collector" );
    }

    function test_constructor_reverts_on_zero_collector() public
    {
        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "collector", 0 ) );
        new CollectorHarness( address(0) );
    }

    function test_appoint_new_collector_success() public
    {
        vm.prank( COLLECTOR );
        collector_harness.appoint_new_collector( NEW_COLLECTOR );

        address pending  =  collector_harness.exposed_get_pending_collector();
        assertEq( pending, NEW_COLLECTOR, "Should set pending collector" );
    }

    function test_appoint_new_collector_emits_event() public
    {
        vm.expectEmit( true, false, false, false );
        emit NewCollectorAppointed( NEW_COLLECTOR );

        vm.prank( COLLECTOR );
        collector_harness.appoint_new_collector( NEW_COLLECTOR );
    }

    function test_appoint_new_collector_reverts_if_not_collector() public
    {
        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, COLLECTOR ) );

        vm.prank( USER );
        collector_harness.appoint_new_collector( NEW_COLLECTOR );
    }

    function test_appoint_new_collector_reverts_on_zero_address() public
    {
        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "new_collector", 0 ) );

        vm.prank( COLLECTOR );
        collector_harness.appoint_new_collector( address(0) );
    }

    function test_claim_collector_role_success() public
    {
        vm.prank( COLLECTOR );
        collector_harness.appoint_new_collector( NEW_COLLECTOR );

        vm.prank( NEW_COLLECTOR );
        collector_harness.claim_collector_role();

        address current_collector  =  collector_harness.exposed_get_collector();
        assertEq( current_collector, NEW_COLLECTOR, "Should update current collector" );
    }

    function test_claim_collector_role_emits_event() public
    {
        vm.prank( COLLECTOR );
        collector_harness.appoint_new_collector( NEW_COLLECTOR );

        vm.expectEmit( true, false, false, false );
        emit NewCollector( NEW_COLLECTOR );

        vm.prank( NEW_COLLECTOR );
        collector_harness.claim_collector_role();
    }

    function test_claim_collector_role_reverts_if_not_pending() public
    {
        vm.prank( COLLECTOR );
        collector_harness.appoint_new_collector( NEW_COLLECTOR );

        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, NEW_COLLECTOR ) );

        vm.prank( USER );
        collector_harness.claim_collector_role();
    }

    function test_claim_collector_role_clears_pending() public
    {
        vm.prank( COLLECTOR );
        collector_harness.appoint_new_collector( NEW_COLLECTOR );

        vm.prank( NEW_COLLECTOR );
        collector_harness.claim_collector_role();

        address pending  =  collector_harness.exposed_get_pending_collector();
        assertEq( pending, address(0), "Should clear pending collector" );
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

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

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

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        uint256 recipient_balance_after  =  RECIPIENT.balance;
        assertEq( recipient_balance_after, recipient_balance_before + 1 ether, "Recipient should receive native stake" );

        ( CollectorHarness.BondInfo memory bond_info, , )  =  collector_harness.exposed_get_bond_info( commitment_hash, stake );
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

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

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

        vm.expectEmit( true, true, false, true );
        emit BondLiquidated( commitment_hash, address(usdc), 100e6, RECIPIENT );

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
    }

    function test_liquidate_expired_bonds_transfers_stakes() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        uint256 contract_balance_before   =  usdc.balanceOf( address(collector_harness) );
        uint256 recipient_balance_before  =  usdc.balanceOf( RECIPIENT );

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        uint256 contract_balance_after   =  usdc.balanceOf( address(collector_harness) );
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

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        ( CollectorHarness.BondInfo memory bond_info, , )  =  collector_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.LIQUIDATED), "Bond should be marked as liquidated" );
    }

    function test_liquidate_expired_bonds_reverts_if_not_collector() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, COLLECTOR ) );

        vm.prank( USER );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
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

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, address(0) );
    }

    function test_liquidate_expired_bonds_reverts_on_array_mismatch() public
    {
        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  keccak256( "test" );

        TokenAmount[] memory stakes  =  new TokenAmount[](2);
        stakes[ 0 ]  =  TokenAmount({ token: usdc, amount: 100e6 });
        stakes[ 1 ]  =  TokenAmount({ token: dai, amount: 200e18 });

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "array_length_mismatch", 0 ) );

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
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

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
    }

    function test_liquidate_expired_bonds_reverts_if_already_executed() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        ( , bytes32 bond_key, uint256 packed_value )  =  collector_harness.exposed_get_bond_info( commitment_hash, stake );
        collector_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.EXECUTED );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.expectRevert( abi.encodeWithSelector( BondAlreadySettled.selector, BondStatus.EXECUTED ) );

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
    }

    function test_liquidate_expired_bonds_reverts_if_already_liquidated() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_expired_bond( stake, 100e6 );

        ( , bytes32 bond_key, uint256 packed_value )  =  collector_harness.exposed_get_bond_info( commitment_hash, stake );
        collector_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.LIQUIDATED );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        vm.expectRevert( abi.encodeWithSelector( BondAlreadySettled.selector, BondStatus.LIQUIDATED ) );

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );
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
            collector_harness.liquidate_expired_bonds,
            ( hashes, stakes, RECIPIENT )
        );
        usdc.set_reentrancy_call( address(collector_harness), reentrancy_call );

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( hashes, stakes, RECIPIENT );

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

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        ( CollectorHarness.BondInfo memory bond_info, , )  =  collector_harness.exposed_get_bond_info( commitment_hash, stake );
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

        vm.prank( COLLECTOR );
        collector_harness.liquidate_expired_bonds( commitment_hashes, stakes, RECIPIENT );

        ( CollectorHarness.BondInfo memory bond_info, , )  =  collector_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.LIQUIDATED), "Should liquidate one second after expiration" );
    }


    // ━━━━  AIRDROP()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_airdrop_with_erc20() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        uint256 accumulated  =  collector_harness.exposed_get_accumulated_airdrops( usdc );
        assertEq( accumulated, 100e6, "Should accumulate ERC20 airdrop" );
    }

    function test_airdrop_with_native() public
    {
        vm.prank( USER );
        collector_harness.airdrop{ value: 1 ether }( IERC20(address(0)), 1 ether, "" );

        uint256 accumulated  =  collector_harness.exposed_get_accumulated_airdrops( IERC20(address(0)) );
        assertEq( accumulated, 1 ether, "Should accumulate native airdrop" );
    }

    function test_airdrop_with_message() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.expectEmit( true, true, false, true );
        emit AirdropReceived( USER, address(usdc), 100e6, "Thank you!" );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "Thank you!" );
    }

    function test_airdrop_without_message() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.expectEmit( true, true, false, true );
        emit AirdropReceived( USER, address(usdc), 100e6, "" );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );
    }

    function test_airdrop_emits_event() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.expectEmit( true, true, false, true );
        emit AirdropReceived( USER, address(usdc), 100e6, "Great work!" );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "Great work!" );
    }

    function test_airdrop_accumulates_correctly() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 300e6 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 200e6, "" );

        uint256 accumulated  =  collector_harness.exposed_get_accumulated_airdrops( usdc );
        assertEq( accumulated, 300e6, "Should accumulate multiple airdrops" );
    }

    function test_airdrop_handles_fee_on_transfer() public
    {
        vm.prank( USER );
        fee_token.approve( address(collector_harness), 1000e18 );

        vm.prank( USER );
        collector_harness.airdrop( IERC20(address(fee_token)), 1000e18, "" );

        uint256 accumulated  =  collector_harness.exposed_get_accumulated_airdrops( IERC20(address(fee_token)) );
        assertEq( accumulated, 990e18, "Should accumulate actual received amount after fee" );
    }

    function test_airdrop_gracefully_handles_zero_amount() public
    {
        uint256 accumulated_before  =  collector_harness.get_claimable_airdrop_amount( usdc );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 0, "" );

        uint256 accumulated_after  =  collector_harness.get_claimable_airdrop_amount( usdc );
        assertEq( accumulated_after, accumulated_before, "Should not change accumulated airdrops on zero amount" );
    }

    function test_airdrop_truncates_long_message() public
    {
        // Build a message longer than MAX_MESSAGE_LENGTH.
        bytes memory long_bytes  =  new bytes( MAX_MESSAGE_LENGTH + 10 );
        for(  uint i = 0  ;  i < long_bytes.length  ;  i++  )  long_bytes[ i ]  =  "a";
        string memory long_message  =  string( long_bytes );

        // Build expected truncated message.
        bytes memory truncated_bytes  =  new bytes( MAX_MESSAGE_LENGTH );
        for(  uint i = 0  ;  i < MAX_MESSAGE_LENGTH  ;  i++  )  truncated_bytes[ i ]  =  "a";
        string memory expected_message  =  string( truncated_bytes );

        vm.expectEmit( true, true, false, true );
        emit AirdropReceived( USER, address(0), 1 ether, expected_message );

        vm.prank( USER );
        collector_harness.airdrop{ value: 1 ether }( IERC20(address(0)), 1 ether, long_message );
    }

    function test_airdrop_reverts_on_native_amount_mismatch() public
    {
        vm.expectRevert( abi.encodeWithSelector( NativeAmountMismatch.selector, 0.5 ether, 1 ether ) );

        vm.prank( USER );
        collector_harness.airdrop{ value: 0.5 ether }( IERC20(address(0)), 1 ether, "" );
    }

    function test_airdrop_reverts_on_reentrancy() public
    {
        bytes memory reentrancy_call  =  abi.encodeCall(
            collector_harness.airdrop,
            ( IERC20(address(usdc)), 100e6, "Reentrancy attack!" )
        );
        usdc.set_reentrancy_call( address(collector_harness), reentrancy_call );

        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        collector_harness.airdrop( IERC20(address(usdc)), 100e6, "Initial airdrop" );

        assertFalse( usdc.did_reentrancy_succeed(), "Reentrancy attack should fail - missing reentrancy guard!" );
    }


    // ━━━━  NOTIFY_PROTOCOL_AIRDROP()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_notify_protocol_airdrop_success() public
    {
        protocol_token.mint_and_notify_airdrop( 100e18, bytes32(0) );

        uint256 accumulated  =  collector_harness.exposed_get_accumulated_airdrops( IERC20(address(protocol_token)) );
        assertEq( accumulated, 100e18, "Should accumulate notified airdrop" );
    }

    function test_notify_protocol_airdrop_with_message() public
    {
        vm.expectEmit( true, false, false, true );
        emit AirdropCredited( address(protocol_token), 100e18, bytes32("FromProtocol") );

        protocol_token.mint_and_notify_airdrop( 100e18, bytes32("FromProtocol") );
    }

    function test_notify_protocol_airdrop_emits_event() public
    {
        vm.expectEmit( true, false, false, true );
        emit AirdropCredited( address(protocol_token), 100e18, bytes32("test") );

        protocol_token.mint_and_notify_airdrop( 100e18, bytes32("test") );
    }

    function test_notify_protocol_airdrop_silent_mode_no_event() public
    {
        vm.recordLogs();

        protocol_token.mint_and_notify_airdrop( 100e18, bytes32(0) );

        Vm.Log[] memory logs  =  vm.getRecordedLogs();

        // Only Transfer event from mint, no AirdropCredited.
        assertEq( logs.length, 1, "Silent mode should not emit AirdropCredited" );
    }

    function test_notify_protocol_airdrop_accumulates_correctly() public
    {
        protocol_token.mint_and_notify_airdrop( 100e18, bytes32(0) );
        protocol_token.mint_and_notify_airdrop( 200e18, bytes32(0) );

        uint256 accumulated  =  collector_harness.exposed_get_accumulated_airdrops( IERC20(address(protocol_token)) );
        assertEq( accumulated, 300e18, "Should accumulate multiple notifications" );
    }

    function test_notify_protocol_airdrop_gracefully_handles_zero_amount() public
    {
        uint256 accumulated_before  =  collector_harness.get_claimable_airdrop_amount( IERC20(address(protocol_token)) );

        protocol_token.mint_and_notify_airdrop( 0, bytes32(0) );

        uint256 accumulated_after  =  collector_harness.get_claimable_airdrop_amount( IERC20(address(protocol_token)) );
        assertEq( accumulated_after, accumulated_before, "Should not change accumulated airdrops on zero amount" );
    }

    // ━━━━  GET_CLAIMABLE_AIRDROPS()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_get_claimable_airdrop_amount_returns_zero_when_none() public view
    {
        uint256 claimable  =  collector_harness.get_claimable_airdrop_amount( usdc );
        assertEq( claimable, 0, "Should return zero when no airdrops" );
    }

    function test_get_claimable_airdrop_returns_zero_when_only_dust() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 1 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 1, "" );

        uint256 claimable  =  collector_harness.get_claimable_airdrop_amount( usdc );
        assertEq( claimable, 0, "Should return zero when only 1 wei (dust)" );
    }

    function test_get_claimable_airdrop_excludes_dust() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        uint256 claimable  =  collector_harness.get_claimable_airdrop_amount( usdc );
        assertEq( claimable, 100e6 - 1, "Should exclude 1 wei dust" );
    }

    function test_get_claimable_airdrop_multiple_tokens() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        dai.approve( address(collector_harness), 200e18 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        vm.prank( USER );
        collector_harness.airdrop( dai, 200e18, "" );

        uint256 usdc_claimable  =  collector_harness.get_claimable_airdrop_amount( usdc );
        uint256 dai_claimable   =  collector_harness.get_claimable_airdrop_amount( dai );

        assertEq( usdc_claimable, 100e6 - 1, "Should return USDC claimable" );
        assertEq( dai_claimable, 200e18 - 1, "Should return DAI claimable" );
    }


    // ━━━━  CLAIM_ACCUMULATED_AIRDROPS()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_claim_airdrops_single_token() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        uint256 recipient_balance_before  =  usdc.balanceOf( RECIPIENT );

        vm.prank( COLLECTOR );
        collector_harness.claim_airdrops( tokens, RECIPIENT );

        uint256 recipient_balance_after  =  usdc.balanceOf( RECIPIENT );
        assertEq( recipient_balance_after, recipient_balance_before + 100e6 - 1, "Recipient should receive airdrops minus dust" );
    }

    function test_claim_airdrops_multiple_tokens() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        dai.approve( address(collector_harness), 200e18 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        vm.prank( USER );
        collector_harness.airdrop( dai, 200e18, "" );

        IERC20[] memory tokens  =  new IERC20[](2);
        tokens[ 0 ]  =  usdc;
        tokens[ 1 ]  =  dai;

        uint256 usdc_balance_before  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_before   =  dai.balanceOf( RECIPIENT );

        vm.prank( COLLECTOR );
        collector_harness.claim_airdrops( tokens, RECIPIENT );

        uint256 usdc_balance_after  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_after   =  dai.balanceOf( RECIPIENT );

        assertEq( usdc_balance_after, usdc_balance_before + 100e6 - 1, "Recipient should receive USDC airdrops" );
        assertEq( dai_balance_after, dai_balance_before + 200e18 - 1, "Recipient should receive DAI airdrops" );
    }

    function test_claim_airdrops_leaves_dust() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        vm.prank( COLLECTOR );
        collector_harness.claim_airdrops( tokens, RECIPIENT );

        uint256 accumulated  =  collector_harness.exposed_get_accumulated_airdrops( usdc );
        assertEq( accumulated, 1, "Should leave 1 wei dust" );
    }

    function test_claim_airdrops_emits_events() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        vm.expectEmit( true, false, false, true );
        emit AirdropClaimed( address(usdc), 100e6 - 1, RECIPIENT );

        vm.prank( COLLECTOR );
        collector_harness.claim_airdrops( tokens, RECIPIENT );
    }

    function test_claim_airdrops_transfers_correctly() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        uint256 contract_balance_before  =  usdc.balanceOf( address(collector_harness) );
        uint256 recipient_balance_before  =  usdc.balanceOf( RECIPIENT );

        vm.prank( COLLECTOR );
        collector_harness.claim_airdrops( tokens, RECIPIENT );

        uint256 contract_balance_after  =  usdc.balanceOf( address(collector_harness) );
        uint256 recipient_balance_after  =  usdc.balanceOf( RECIPIENT );

        assertEq( contract_balance_after, contract_balance_before - (100e6 - 1), "Contract should lose airdrops" );
        assertEq( recipient_balance_after, recipient_balance_before + (100e6 - 1), "Recipient should gain airdrops" );
    }

    function test_claim_airdrops_reverts_if_not_collector() public
    {
        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, COLLECTOR ) );

        vm.prank( USER );
        collector_harness.claim_airdrops( tokens, RECIPIENT );
    }

    function test_claim_airdrops_reverts_on_zero_recipient() public
    {
        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "recipient", 0 ) );

        vm.prank( COLLECTOR );
        collector_harness.claim_airdrops( tokens, address(0) );
    }

    function test_claim_airdrops_reverts_on_empty_array() public
    {
        IERC20[] memory tokens  =  new IERC20[](0);

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "tokens.length", 0 ) );

        vm.prank( COLLECTOR );
        collector_harness.claim_airdrops( tokens, RECIPIENT );
    }

    function test_claim_airdrops_reverts_on_reentrancy() public
    {
        // Setup: Accumulate some airdrops.
        vm.prank( USER );
        usdc.approve( address(collector_harness), 1000e6 );

        vm.prank( USER );
        collector_harness.airdrop( IERC20(address(usdc)), 1000e6, "Setup airdrop" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        bytes memory reentrancy_call  =  abi.encodeCall(
            collector_harness.claim_airdrops,
            ( tokens, RECIPIENT )
        );
        usdc.set_reentrancy_call( address(collector_harness), reentrancy_call );

        vm.prank( COLLECTOR );
        collector_harness.claim_airdrops( tokens, RECIPIENT );

        assertFalse( usdc.did_reentrancy_succeed(), "Reentrancy attack should fail - missing reentrancy guard!" );
    }

    function test_claim_airdrops_skips_tokens_with_no_airdrops() public
    {
        vm.prank( USER );
        usdc.approve( address(collector_harness), 100e6 );

        vm.prank( USER );
        collector_harness.airdrop( usdc, 100e6, "" );

        IERC20[] memory tokens  =  new IERC20[](2);
        tokens[ 0 ]  =  usdc;
        tokens[ 1 ]  =  dai;

        uint256 usdc_balance_before  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_before   =  dai.balanceOf( RECIPIENT );

        vm.prank( COLLECTOR );
        collector_harness.claim_airdrops( tokens, RECIPIENT );

        uint256 usdc_balance_after  =  usdc.balanceOf( RECIPIENT );
        uint256 dai_balance_after   =  dai.balanceOf( RECIPIENT );

        assertEq( usdc_balance_after, usdc_balance_before + 100e6 - 1, "Should claim USDC airdrops" );
        assertEq( dai_balance_after, dai_balance_before, "Should skip DAI with no airdrops" );
    }
}
