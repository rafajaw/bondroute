// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import { BondRoute } from "@BondRoute/BondRoute.sol";
import { IERC20, TokenAmount } from "@BondRouteProtected/BondRouteProtected.sol";
import { ExecutionData, Invalid } from "@BondRoute/Core.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockProtocol, FundingTransfer } from "@test/mocks/MockProtocol.sol";
import "@BondRoute/Definitions.sol";

/**
 * @title BondRouteTest
 * @notice Tests for BondRoute contract (main entry point and integration)
 * @dev Implements IBondRouteTests from TestManifest.sol
 */
contract BondRouteTest is Test {

    BondRoute public bond_route;
    MockProtocol public mock_protocol;
    MockERC20 public usdc;
    MockERC20 public dai;

    address public constant COLLECTOR  =  address(0x5555);
    address public constant USER       =  address(0x1111);
    address public constant USER2      =  address(0x2222);
    address public constant RELAYER    =  address(0x3333);

    uint256 public constant USER_PRIVATE_KEY = 0xA11CE;

    function setUp() public
    {
        bond_route        =  new BondRoute( COLLECTOR );
        mock_protocol     =  new MockProtocol();
        usdc              =  new MockERC20( "USDC", "USDC" );
        dai               =  new MockERC20( "DAI", "DAI" );

        usdc.mint( USER, 10000e6 );
        usdc.mint( USER2, 10000e6 );
        usdc.mint( RELAYER, 10000e6 );
        dai.mint( USER, 10000e18 );
        dai.mint( USER2, 10000e18 );

        vm.deal( USER, 100 ether );
        vm.deal( USER2, 100 ether );
        vm.deal( RELAYER, 100 ether );
        vm.deal( COLLECTOR, 10 ether );

        vm.prank( USER );
        usdc.approve( address(bond_route), type(uint256).max );

        vm.prank( USER );
        dai.approve( address(bond_route), type(uint256).max );

        vm.prank( USER2 );
        usdc.approve( address(bond_route), type(uint256).max );

        vm.prank( USER2 );
        dai.approve( address(bond_route), type(uint256).max );

        vm.prank( RELAYER );
        usdc.approve( address(bond_route), type(uint256).max );

        vm.prank( RELAYER );
        dai.approve( address(bond_route), type(uint256).max );
    }


    // ━━━━  HELPER FUNCTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function _create_basic_execution_data( ) internal view returns ( ExecutionData memory )
    {
        return ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });
    }

    function _create_bond_from_execution( address bond_creator, address user, ExecutionData memory execution_data ) internal returns ( bytes32 commitment_hash )
    {
        commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( user, execution_data );

        vm.prank( bond_creator );
        bond_route.create_bond( commitment_hash, execution_data.stake );
    }

    function _create_bond_from_execution_with_value( address bond_creator, address user, ExecutionData memory execution_data, uint256 value ) internal returns ( bytes32 commitment_hash )
    {
        commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( user, execution_data );

        vm.prank( bond_creator );
        bond_route.create_bond{ value: value }( commitment_hash, execution_data.stake );
    }


    // ━━━━  DEPLOYMENT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_constructor_success() public
    {
        BondRoute new_bond_route  =  new BondRoute( COLLECTOR );
        assertTrue( address(new_bond_route) != address(0), "BondRoute should deploy successfully" );
    }

    function test_constructor_reverts_on_zero_collector() public
    {
        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "collector", 0 ) );
        new BondRoute( address(0) );
    }


    // ━━━━  DOMAIN_SEPARATOR()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_domain_separator_returns_correct_value() public view
    {
        bytes32 domain_separator  =  bond_route.DOMAIN_SEPARATOR();
        assertTrue( domain_separator != bytes32(0), "Domain separator should not be zero" );
    }

    function test_domain_separator_matches_eip712_domain() public view
    {
        bytes32 domain_separator  =  bond_route.DOMAIN_SEPARATOR();

        bytes32 expected_domain_separator  =  keccak256(
            abi.encode(
                keccak256( "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)" ),
                keccak256( bytes(EIP712_DOMAIN_NAME) ),
                keccak256( bytes(EIP712_DOMAIN_VERSION) ),
                block.chainid,
                address(bond_route)
            )
        );

        assertEq( domain_separator, expected_domain_separator, "Domain separator should match EIP-712 spec" );
    }


    // ━━━━  RECEIVE()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_receive_reverts() public
    {
        vm.prank( USER );
        (bool success, bytes memory return_data)  =  address(bond_route).call{ value: 1 ether }( "" );

        assertFalse( success, "Direct ETH transfer should fail" );
        assertEq( string(return_data), string(abi.encodeWithSignature("Error(string)", "Use airdrop() to donate")), "Should revert with correct message" );
    }


    // ━━━━  FULL INTEGRATION: HAPPY PATH  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_integration_create_and_execute_basic() public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        bytes32 commitment_hash  =  _create_bond_from_execution( USER, USER, execution_data );

        assertTrue( commitment_hash != bytes32(0), "Bond should be created" );

        uint256 user_balance_after_create  =  usdc.balanceOf( USER );
        assertEq( user_balance_after_create, user_balance_before - 100e6, "Stake should be taken" );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, ) = bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );

        uint256 user_balance_after_execute  =  usdc.balanceOf( USER );
        assertEq( user_balance_after_execute, user_balance_before, "Stake should be refunded" );
    }

    function test_integration_create_and_execute_with_funding() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: dai, amount: 50e18 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 54321,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        FundingTransfer[] memory transfers  =  new FundingTransfer[](1);
        transfers[ 0 ]  =  FundingTransfer({
            to: address(mock_protocol),
            token: dai,
            amount: 50e18
        });
        mock_protocol.set_funding_transfers( transfers );

        _create_bond_from_execution( USER, USER, execution_data );

        vm.roll( block.number + 1 );

        uint256 dai_balance_before  =  dai.balanceOf( USER );

        vm.prank( USER );
        ( BondStatus status, ) = bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );

        uint256 dai_balance_after  =  dai.balanceOf( USER );
        assertEq( dai_balance_after, dai_balance_before - 50e18, "Funding should be transferred" );
    }

    function test_integration_create_wait_execute() public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        _create_bond_from_execution( USER, USER, execution_data );

        vm.warp( block.timestamp + 30 minutes );
        vm.roll( block.number + 100 );

        vm.prank( USER );
        ( BondStatus status, ) = bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond should execute after waiting" );
    }

    function test_integration_create_expire_liquidate() public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        bytes32 commitment_hash  =  _create_bond_from_execution( USER, USER, execution_data );

        vm.warp( block.timestamp + MAX_BOND_LIFETIME + 1 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  execution_data.stake;

        uint256 collector_balance_before  =  usdc.balanceOf( COLLECTOR );

        vm.prank( COLLECTOR );
        bond_route.liquidate_expired_bonds( commitment_hashes, stakes, COLLECTOR );

        uint256 collector_balance_after  =  usdc.balanceOf( COLLECTOR );
        assertEq( collector_balance_after, collector_balance_before + 100e6, "Collector should receive liquidated stake" );
    }

    function test_integration_multiple_bonds_same_user() public
    {
        ExecutionData memory execution_data1  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 1,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        ExecutionData memory execution_data2  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 2,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        ExecutionData memory execution_data3  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 3,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash1  =  _create_bond_from_execution( USER, USER, execution_data1 );
        bytes32 commitment_hash2  =  _create_bond_from_execution( USER, USER, execution_data2 );
        bytes32 commitment_hash3  =  _create_bond_from_execution( USER, USER, execution_data3 );

        assertTrue( commitment_hash1 != commitment_hash2 && commitment_hash2 != commitment_hash3 && commitment_hash1 != commitment_hash3, "All commitment hashes should be unique" );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status1, ) = bond_route.execute_bond( execution_data1 );

        vm.prank( USER );
        ( BondStatus status2, ) = bond_route.execute_bond( execution_data2 );

        vm.prank( USER );
        ( BondStatus status3, ) = bond_route.execute_bond( execution_data3 );

        assertEq( uint(status1), uint(BondStatus.EXECUTED), "Bond 1 should execute successfully" );
        assertEq( uint(status2), uint(BondStatus.EXECUTED), "Bond 2 should execute successfully" );
        assertEq( uint(status3), uint(BondStatus.EXECUTED), "Bond 3 should execute successfully" );
    }

    function test_integration_multiple_bonds_different_users() public
    {
        ExecutionData memory execution_data_user1  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 111,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        ExecutionData memory execution_data_user2  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 222,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash1  =  _create_bond_from_execution( USER, USER, execution_data_user1 );
        bytes32 commitment_hash2  =  _create_bond_from_execution( USER2, USER2, execution_data_user2 );

        assertTrue( commitment_hash1 != commitment_hash2, "Different users should have different commitment hashes" );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status1, ) = bond_route.execute_bond( execution_data_user1 );

        vm.prank( USER2 );
        ( BondStatus status2, ) = bond_route.execute_bond( execution_data_user2 );

        assertEq( uint(status1), uint(BondStatus.EXECUTED), "User 1 should execute successfully" );
        assertEq( uint(status2), uint(BondStatus.EXECUTED), "User 2 should execute successfully" );
    }


    // ━━━━  FULL INTEGRATION: RELAYER FLOW  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_integration_relayer_fronts_stake() public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        address actual_user  =  vm.addr( USER_PRIVATE_KEY );

        ( bytes32 digest, , , )  =  bond_route.__OFF_CHAIN__get_signing_info( execution_data );

        (uint8 v, bytes32 r, bytes32 s)  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        uint256 user_balance_before  =  usdc.balanceOf( actual_user );
        uint256 relayer_balance_before  =  usdc.balanceOf( RELAYER );

        _create_bond_from_execution( RELAYER, actual_user, execution_data );

        uint256 relayer_balance_after_create  =  usdc.balanceOf( RELAYER );
        assertEq( relayer_balance_after_create, relayer_balance_before - 100e6, "Relayer should front stake" );

        vm.roll( block.number + 1 );

        vm.prank( RELAYER );
        ( BondStatus status, ) = bond_route.execute_bond_as( execution_data, actual_user, signature, false );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution via relayer should succeed" );

        uint256 user_balance_after  =  usdc.balanceOf( actual_user );
        assertEq( user_balance_after, user_balance_before + 100e6, "User should receive stake refund" );
    }

    function test_integration_relayer_fronts_native() public
    {
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 1 ether }),
            salt: 99999,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        address actual_user  =  vm.addr( USER_PRIVATE_KEY );

        ( bytes32 digest, , , )  =  bond_route.__OFF_CHAIN__get_signing_info( execution_data );

        (uint8 v, bytes32 r, bytes32 s)  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        uint256 user_balance_before  =  actual_user.balance;
        uint256 relayer_balance_before  =  RELAYER.balance;

        _create_bond_from_execution_with_value( RELAYER, actual_user, execution_data, 1 ether );

        uint256 relayer_balance_after_create  =  RELAYER.balance;
        assertEq( relayer_balance_after_create, relayer_balance_before - 1 ether, "Relayer should front native stake" );

        vm.roll( block.number + 1 );

        vm.prank( RELAYER );
        ( BondStatus status, ) = bond_route.execute_bond_as( execution_data, actual_user, signature, false );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution via relayer should succeed" );

        uint256 user_balance_after  =  actual_user.balance;
        assertEq( user_balance_after, user_balance_before + 1 ether, "User should receive native stake refund" );
    }

    function test_integration_relayer_user_receives_refunds() public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        address actual_user  =  vm.addr( USER_PRIVATE_KEY );

        _create_bond_from_execution( RELAYER, actual_user, execution_data );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  bond_route.__OFF_CHAIN__get_signing_info( execution_data );
        (uint8 v, bytes32 r, bytes32 s)  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        uint256 user_balance_before  =  usdc.balanceOf( actual_user );
        uint256 relayer_balance_before  =  usdc.balanceOf( RELAYER );

        vm.prank( RELAYER );
        ( BondStatus status, ) = bond_route.execute_bond_as( execution_data, actual_user, signature, false );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );

        uint256 user_balance_after  =  usdc.balanceOf( actual_user );
        uint256 relayer_balance_after  =  usdc.balanceOf( RELAYER );

        assertEq( user_balance_after, user_balance_before + 100e6, "User (not relayer) should receive stake" );
        assertEq( relayer_balance_after, relayer_balance_before, "Relayer should not receive stake" );
    }

    function test_integration_relayer_gasless_execution() public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        address actual_user  =  vm.addr( USER_PRIVATE_KEY );

        _create_bond_from_execution( RELAYER, actual_user, execution_data );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  bond_route.__OFF_CHAIN__get_signing_info( execution_data );
        (uint8 v, bytes32 r, bytes32 s)  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        uint256 user_eth_balance_before  =  actual_user.balance;

        vm.prank( RELAYER );
        bond_route.execute_bond_as( execution_data, actual_user, signature, false );

        uint256 user_eth_balance_after  =  actual_user.balance;

        assertEq( user_eth_balance_after, user_eth_balance_before, "User should not spend gas (gasless execution)" );
    }


    // ━━━━  INTEGRATION TESTS: RETURN VALUES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_integration_execute_returns_protocol_output() public
    {
        bytes memory expected_output  =  abi.encode( uint256(12345), address(0xABCD), true );
        mock_protocol.set_return_data( expected_output );

        ExecutionData memory execution_data  =  _create_basic_execution_data( );
        _create_bond_from_execution( USER, USER, execution_data );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, bytes memory output ) = bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should return EXECUTED status" );
        assertEq( output, expected_output, "Output should match protocol return data" );

        ( uint256 decoded_value, address decoded_address, bool decoded_flag )  =  abi.decode( output, (uint256, address, bool) );
        assertEq( decoded_value, 12345, "Decoded value should match" );
        assertEq( decoded_address, address(0xABCD), "Decoded address should match" );
        assertEq( decoded_flag, true, "Decoded flag should match" );
    }

    function test_integration_failed_bond_returns_error_data() public
    {
        bytes memory custom_error  =  abi.encodeWithSignature( "InsufficientBalance(uint256,uint256)", 100, 50 );
        mock_protocol.set_should_revert( true, custom_error );

        ExecutionData memory execution_data  =  _create_basic_execution_data( );
        _create_bond_from_execution( USER, USER, execution_data );

        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, bytes memory output ) = bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.PROTOCOL_REVERTED), "Should return PROTOCOL_REVERTED status" );
        assertEq( output, custom_error, "Output should contain protocol error data" );

        bytes4 error_selector  =  bytes4(output);
        assertEq( error_selector, bytes4(keccak256( "InsufficientBalance(uint256,uint256)" )), "Should preserve error selector" );
    }

    function test_integration_smart_wallet_can_decode_output() public
    {
        address actual_user  =  vm.addr( USER_PRIVATE_KEY );

        usdc.mint( actual_user, 10000e6 );
        vm.prank( actual_user );
        usdc.approve( address(bond_route), type(uint256).max );

        bytes memory swap_result_encoded  =  abi.encode(
            address(usdc),
            address(dai),
            uint256(1000e6),
            uint256(999e18),
            uint256(1e6)
        );
        mock_protocol.set_return_data( swap_result_encoded );

        ExecutionData memory execution_data  =  _create_basic_execution_data( );
        _create_bond_from_execution( actual_user, actual_user, execution_data );

        vm.roll( block.number + 1 );

        ( bytes32 digest, , , )  =  bond_route.__OFF_CHAIN__get_signing_info( execution_data );
        (uint8 v, bytes32 r, bytes32 s)  =  vm.sign( USER_PRIVATE_KEY, digest );
        bytes memory signature  =  abi.encodePacked( r, s, v );

        vm.prank( RELAYER );
        ( BondStatus status, bytes memory output ) = bond_route.execute_bond_as( execution_data, actual_user, signature, false );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed" );

        ( address token_in, address token_out, uint256 amount_in, uint256 amount_out, uint256 fee )  =  abi.decode( output, (address, address, uint256, uint256, uint256) );

        assertEq( token_in, address(usdc), "token_in should match" );
        assertEq( token_out, address(dai), "token_out should match" );
        assertEq( amount_in, 1000e6, "amount_in should match" );
        assertEq( amount_out, 999e18, "amount_out should match" );
        assertEq( fee, 1e6, "fee should match" );
    }
}
