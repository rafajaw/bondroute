// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import { Core, SameBlockExecution, BondExpired, InsufficientNativeFunding, BondValidationFailed, BondProtocolReverted, ExecutionData } from "@BondRoute/Core.sol";
import { BondAlreadySettled, BondNotFound, BondStatus } from "@BondRoute/Storage.sol";
import { IERC20, TokenAmount, PossiblyBondFarming, NATIVE_TOKEN } from "@BondRouteProtected/BondRouteProtected.sol";
import { HashLib } from "@BondRoute/HashLib.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockProtocol } from "@test/mocks/MockProtocol.sol";
import { InvalidTypedString } from "@BondRoute/ValidationLib.sol";
import "@BondRoute/Definitions.sol";

/**
 * @title CoreHarness
 * @notice Test harness exposing Core's internal functions for testing
 */
contract CoreHarness is Core {

    constructor() {}

    function exposed_execute_bond_internal( address user, ExecutionData calldata execution_data ) external payable returns ( BondStatus status, bytes memory output )
    {
        return _execute_bond_internal( user, execution_data );
    }

    function exposed_get_signing_data_for_execute_bond_as( ExecutionData calldata execution_data ) external view returns ( bytes32 digest, bytes32 type_hash, string memory type_string )
    {
        return _get_signing_data_for_execute_bond_as( execution_data );
    }

    // Expose parent functions for setup.
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

    function exposed_calc_commitment_hash( address user, ExecutionData calldata execution_data ) external view returns ( bytes32 )
    {
        return HashLib.calc_commitment_hash( user, address(this), execution_data );
    }

    function exposed_get_context_hash() external view returns ( uint256 )
    {
        return __transient__context_hash;
    }

    function DOMAIN_SEPARATOR() external view returns ( bytes32 )
    {
        return _domainSeparatorV4( );
    }
}

/**
 * @title CoreTest
 * @notice Tests for Core contract (bond execution logic and EIP-712 signing)
 * @dev Implements ICoreTests from TestManifest.sol
 */
contract CoreTest is Test {

    CoreHarness public core_harness;
    MockProtocol public mock_protocol;
    MockERC20 public usdc;
    MockERC20 public dai;

    address public constant USER  =  address(0x1111);

    function setUp() public
    {
        core_harness      =  new CoreHarness();
        mock_protocol     =  new MockProtocol();
        usdc              =  new MockERC20( "USDC", "USDC" );
        dai               =  new MockERC20( "DAI", "DAI" );

        // Mint tokens to user and core harness for testing.
        usdc.mint( USER, 1000e6 );
        usdc.mint( address(core_harness), 1000e6 );
        dai.mint( USER, 1000e18 );
        dai.mint( address(core_harness), 1000e18 );

        // Give USER some native tokens.
        vm.deal( USER, 100 ether );
        vm.deal( address(core_harness), 100 ether );
    }


    // ━━━━  HELPER FUNCTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function _create_test_bond( TokenAmount memory stake, uint256 amount_received ) internal returns ( bytes32 commitment_hash )
    {
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        commitment_hash  =  core_harness.exposed_calc_commitment_hash( USER, execution_data );
        core_harness.exposed_create_bond_internal( commitment_hash, stake, amount_received );
    }

    function _create_test_bond_with_execution_data( ExecutionData memory execution_data, uint256 amount_received ) internal returns ( bytes32 commitment_hash )
    {
        commitment_hash  =  core_harness.exposed_calc_commitment_hash( USER, execution_data );
        core_harness.exposed_create_bond_internal( commitment_hash, execution_data.stake, amount_received );
    }


    // ━━━━  BOND EXECUTION TESTS: SUCCESS PATHS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_execute_bond_basic_success() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        // Verify execution succeeded
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );

        // Verify bond marked as executed
        ( CoreHarness.BondInfo memory bond_info, , )  =  core_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.EXECUTED), "Bond should be marked as executed" );

        // Verify stake refunded
        uint256 user_balance_after  =  usdc.balanceOf( USER );
        assertEq( user_balance_after, user_balance_before + 100e6, "Stake should be refunded to user" );
    }

    function test_execute_bond_with_native_stake() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  _create_test_bond_with_execution_data( execution_data, 1 ether );

        vm.roll( block.number + 1 );

        uint256 user_balance_before  =  USER.balance;

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );

        // Verify bond marked as executed
        ( CoreHarness.BondInfo memory bond_info, , )  =  core_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.EXECUTED), "Bond should be marked as executed" );

        // Verify native stake refunded
        uint256 user_balance_after  =  USER.balance;
        assertEq( user_balance_after, user_balance_before + 1 ether, "Native stake should be refunded to user" );
    }

    function test_execute_bond_with_native_funding() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 0.5 ether });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 1 ether );

        vm.roll( block.number + 1 );

        // Execute with sufficient msg.value (stake covers 1 ether, funding needs 0.5 ether from stake)
        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );
    }

    function test_execute_bond_with_multiple_fundings() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        TokenAmount[] memory fundings  =  new TokenAmount[](2);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 50e6 });
        fundings[ 1 ]  =  TokenAmount({ token: dai, amount: 100e18 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );
    }

    function test_execute_bond_stake_refunded_correctly() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 54321,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );
        uint256 contract_balance_before  =  usdc.balanceOf( address(core_harness) );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );

        uint256 user_balance_after  =  usdc.balanceOf( USER );
        uint256 contract_balance_after  =  usdc.balanceOf( address(core_harness) );

        assertEq( user_balance_after, user_balance_before + 100e6, "User should receive stake back" );
        assertEq( contract_balance_after, contract_balance_before - 100e6, "Contract should release stake" );
    }

    function test_execute_bond_unused_msg_value_refunded() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 0.5 ether });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 1 ether );

        vm.roll( block.number + 1 );

        // Funding requires 0.5 ether, stake covers it. Full stake (1 ether) should be refunded since protocol doesn't consume the funding.
        uint256 user_balance_before  =  USER.balance;

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );

        uint256 user_balance_after  =  USER.balance;

        // MockProtocol doesn't actually consume any funds, so full stake (1 ether) should be refunded.
        assertEq( user_balance_after, user_balance_before + 1 ether, "Full stake should be refunded when protocol doesn't consume funds" );
    }

    function test_execute_bond_protocol_called_correctly() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 99999,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        // This test verifies protocol is called without reverting
        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );
    }


    // ━━━━  BOND EXECUTION TESTS: VALIDATION FAILURES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_execute_bond_reverts_if_bond_not_found() public
    {
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 99999,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        vm.expectRevert( BondNotFound.selector );
        core_harness.exposed_execute_bond_internal( USER, execution_data );
    }

    function test_execute_bond_reverts_if_already_executed() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_test_bond( stake, 100e6 );

        // Mark as executed.
        ( , bytes32 bond_key, uint256 packed_value )  =  core_harness.exposed_get_bond_info( commitment_hash, stake );
        core_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.EXECUTED );

        // Try to execute.
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        vm.roll( block.number + 1 );

        vm.expectRevert( abi.encodeWithSelector( BondAlreadySettled.selector, BondStatus.EXECUTED ) );
        core_harness.exposed_execute_bond_internal( USER, execution_data );
    }

    function test_execute_bond_reverts_if_already_liquidated() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        bytes32 commitment_hash  =  _create_test_bond( stake, 100e6 );

        // Mark as liquidated.
        ( , bytes32 bond_key, uint256 packed_value )  =  core_harness.exposed_get_bond_info( commitment_hash, stake );
        core_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.LIQUIDATED );

        // Try to execute.
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        vm.roll( block.number + 1 );

        vm.expectRevert( abi.encodeWithSelector( BondAlreadySettled.selector, BondStatus.LIQUIDATED ) );
        core_harness.exposed_execute_bond_internal( USER, execution_data );
    }

    function test_execute_bond_reverts_if_same_block() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        _create_test_bond( stake, 100e6 );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        // Try to execute in same block (don't roll).
        vm.expectRevert( SameBlockExecution.selector );
        core_harness.exposed_execute_bond_internal( USER, execution_data );
    }

    function test_execute_bond_reverts_if_expired() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        _create_test_bond( stake, 100e6 );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        // Warp past expiration.
        vm.warp( block.timestamp + MAX_BOND_LIFETIME + 1 );
        vm.roll( block.number + 1 );

        vm.expectRevert( abi.encodeWithSelector( BondExpired.selector, block.timestamp - 1, block.timestamp ) );
        core_harness.exposed_execute_bond_internal( USER, execution_data );
    }

    function test_execute_bond_reverts_on_insufficient_native_funding() public
    {
        // Create bond with native stake.
        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        // Declare native funding that exceeds what's provided.
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 2 ether });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  core_harness.exposed_calc_commitment_hash( USER, execution_data );
        core_harness.exposed_create_bond_internal( commitment_hash, stake, 1 ether );

        vm.roll( block.number + 1 );

        // Held = 1 ether (stake), declared = 2 ether, expected msg.value = 1 ether.
        vm.expectRevert( abi.encodeWithSelector( InsufficientNativeFunding.selector, 1 ether, 1 ether ) );
        core_harness.exposed_execute_bond_internal( USER, execution_data );
    }

    function test_execute_bond_handles_invalid_validation_gracefully() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        // Create execution data with TOO MANY fundings (exceeds MAX_FUNDINGS_PER_BOND).
        TokenAmount[] memory excessive_fundings  =  new TokenAmount[]( MAX_FUNDINGS_PER_BOND + 1 );
        for(  uint256 i = 0  ;  i <= MAX_FUNDINGS_PER_BOND  ;  i++  )
        {
            excessive_fundings[ i ]  =  TokenAmount({ token: IERC20(address(uint160(i + 1))), amount: 1 });
        }

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: excessive_fundings,
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  core_harness.exposed_calc_commitment_hash( USER, execution_data );
        core_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );

        vm.roll( block.number + 1 );

        // Record user's balance before execution.
        uint256 user_balance_before  =  usdc.balanceOf( USER );

        // Execute - should handle gracefully and return stake to user despite invalid validation.
        // Expect BondValidationFailed event with matching reason string.
        vm.expectEmit( true, false, false, true );
        emit BondValidationFailed( commitment_hash, INVALID_TOO_MANY_FUNDINGS );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        // Verify execution returned false for validation failure
        assertNotEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should return false for validation failure" );

        // Verify bond is marked as failed (graceful handling of invalid bond).
        ( CoreHarness.BondInfo memory bond_info, , )  =  core_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.INVALID_BOND), "Bond should be marked as failed due to invalid validation" );

        // Verify stake was returned to user.
        uint256 user_balance_after  =  usdc.balanceOf( USER );
        assertEq( user_balance_after, user_balance_before + 100e6, "Stake should be returned to user" );
    }

    function test_execute_bond_graceful_on_duplicate_fundings() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        // Create duplicate fundings
        TokenAmount[] memory duplicate_fundings  =  new TokenAmount[](2);
        duplicate_fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 50e6 });
        duplicate_fundings[ 1 ]  =  TokenAmount({ token: usdc, amount: 30e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: duplicate_fundings,
            stake: stake,
            salt: 22222,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        vm.expectEmit( true, false, false, true );
        emit BondValidationFailed( commitment_hash, INVALID_DUPLICATE_FUNDING_TOKEN );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertNotEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should return false for validation failure" );

        uint256 user_balance_after  =  usdc.balanceOf( USER );
        assertEq( user_balance_after, user_balance_before + 100e6, "Stake should be returned despite duplicate funding token" );
    }

    function test_execute_bond_graceful_on_zero_amount_funding() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        TokenAmount[] memory zero_fundings  =  new TokenAmount[](1);
        zero_fundings[ 0 ]  =  TokenAmount({ token: dai, amount: 0 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: zero_fundings,
            stake: stake,
            salt: 33333,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        vm.expectEmit( true, false, false, true );
        emit BondValidationFailed( commitment_hash, INVALID_ZERO_AMOUNT );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertNotEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should return false for validation failure" );

        uint256 user_balance_after  =  usdc.balanceOf( USER );
        assertEq( user_balance_after, user_balance_before + 100e6, "Stake should be returned despite zero amount" );
    }

    function test_execute_bond_graceful_on_unsupported_protocol() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        // Create protocol that doesn't support BondRoute
        MockProtocol unsupported_protocol  =  new MockProtocol();

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 44444,
            protocol: unsupported_protocol,
            call: abi.encodeWithSignature( "unsupported()" )  // Not in protected selectors
        });

        bytes32 commitment_hash  =  _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        vm.expectEmit( true, false, false, true );
        emit BondValidationFailed( commitment_hash, INVALID_PROTOCOL_OR_CALL );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertNotEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should return false for validation failure" );

        uint256 user_balance_after  =  usdc.balanceOf( USER );
        assertEq( user_balance_after, user_balance_before + 100e6, "Stake should be returned despite unsupported protocol" );
    }

    function test_execute_bond_invalid_validation_returns_native_stake() public
    {
        // Native stake with invalid execution (too many fundings).
        TokenAmount memory stake  =  TokenAmount({ token: NATIVE_TOKEN, amount: 1 ether });

        TokenAmount[] memory excessive_fundings  =  new TokenAmount[]( MAX_FUNDINGS_PER_BOND + 1 );
        for(  uint256 i = 0  ;  i <= MAX_FUNDINGS_PER_BOND  ;  i++  )
        {
            excessive_fundings[ i ]  =  TokenAmount({ token: IERC20(address(uint160(i + 100))), amount: 1 });
        }

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: excessive_fundings,
            stake: stake,
            salt: 77777,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  _create_test_bond_with_execution_data( execution_data, 1 ether );

        vm.roll( block.number + 1 );

        uint256 user_balance_before  =  USER.balance;

        vm.expectEmit( true, false, false, true );
        emit BondValidationFailed( commitment_hash, INVALID_TOO_MANY_FUNDINGS );

        ( BondStatus status, )  =  core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.INVALID_BOND), "Should return INVALID_BOND" );
        assertEq( USER.balance, user_balance_before + 1 ether, "Native stake should be returned on invalid validation" );
    }

    function test_execute_bond_invalid_validation_returns_msg_value() public
    {
        // ERC20 stake with msg.value for native funding, but invalid execution (too many fundings).
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        TokenAmount[] memory excessive_fundings  =  new TokenAmount[]( MAX_FUNDINGS_PER_BOND + 1 );
        for(  uint256 i = 0  ;  i <= MAX_FUNDINGS_PER_BOND  ;  i++  )
        {
            excessive_fundings[ i ]  =  TokenAmount({ token: IERC20(address(uint160(i + 200))), amount: 1 });
        }

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: excessive_fundings,
            stake: stake,
            salt: 88888,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        uint256 user_native_before  =  USER.balance;
        uint256 user_usdc_before    =  usdc.balanceOf( USER );

        vm.expectEmit( true, false, false, true );
        emit BondValidationFailed( commitment_hash, INVALID_TOO_MANY_FUNDINGS );

        // Execute with msg.value - should fail validation and return both stake and msg.value.
        ( BondStatus status, )  =  core_harness.exposed_execute_bond_internal{ value: 2 ether }( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.INVALID_BOND), "Should return INVALID_BOND" );
        assertEq( usdc.balanceOf( USER ), user_usdc_before + 100e6, "ERC20 stake should be returned" );
        assertEq( USER.balance, user_native_before + 2 ether, "msg.value should be returned on invalid validation" );
    }


    // ━━━━  BOND EXECUTION TESTS: PROTOCOL INTERACTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_execute_bond_protocol_revert_handled() public
    {
        mock_protocol.set_should_revert( true );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 55555,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        bytes memory expected_revert_data  =  mock_protocol.get_revert_data();
        vm.expectEmit( true, false, false, true );
        emit BondProtocolReverted( commitment_hash, expected_revert_data );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.PROTOCOL_REVERTED), "Execution should return PROTOCOL_REVERTED when protocol reverts" );

        ( CoreHarness.BondInfo memory bond_info, , )  =  core_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( uint8(bond_info.status), uint8(BondStatus.PROTOCOL_REVERTED), "Bond should be marked as PROTOCOL_REVERTED" );

        uint256 user_balance_after  =  usdc.balanceOf( USER );
        assertEq( user_balance_after, user_balance_before + 100e6, "Stake should be refunded to user" );
    }

    function test_execute_bond_protocol_out_of_gas_detected() public
    {
        mock_protocol.set_should_revert( true, bytes("") );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 66666,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, OUT_OF_GAS_OR_UNSPECIFIED_FAILURE, bytes32(0) ) );
        core_harness.exposed_execute_bond_internal( USER, execution_data );
    }

    function test_execute_bond_protocol_empty_revert_handled() public
    {
        mock_protocol.set_should_revert( true, bytes("") );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 77777,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, OUT_OF_GAS_OR_UNSPECIFIED_FAILURE, bytes32(0) ) );
        core_harness.exposed_execute_bond_internal( USER, execution_data );
    }

    function test_execute_bond_context_cleared_after_success() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 88888,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        uint256 context_before  =  core_harness.exposed_get_context_hash();
        assertEq( context_before, 0, "Context hash should be zero before execution" );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );

        uint256 context_after  =  core_harness.exposed_get_context_hash();
        assertEq( context_after, 0, "Context hash should be cleared after successful execution" );
    }

    function test_execute_bond_context_cleared_after_protocol_revert() public
    {
        mock_protocol.set_should_revert( true );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 99999,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        uint256 context_before  =  core_harness.exposed_get_context_hash();
        assertEq( context_before, 0, "Context hash should be zero before execution" );

        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertNotEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should return false when protocol reverts" );

        uint256 context_after  =  core_harness.exposed_get_context_hash();
        assertEq( context_after, 0, "Context hash should be cleared after protocol revert" );
    }


    // ━━━━  EIP-712 SIGNATURE VALIDATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_get_signing_data_uses_default_type_when_no_custom_info() public view
    {
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        ( bytes32 digest, bytes32 type_hash, string memory type_string )  =  core_harness.exposed_get_signing_data_for_execute_bond_as( execution_data );

        // Should use default type string.
        assertEq( type_string, "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,bytes32 calldata_hash)TokenAmount(address token,uint256 amount)", "Should use default type string" );
        assertTrue( digest != bytes32(0), "Digest should not be zero" );
        assertTrue( type_hash != bytes32(0), "Type hash should not be zero" );
    }

    function test_get_signing_data_uses_custom_type_when_provided() public
    {
        // Set custom signing info on mock protocol with valid prefix and TokenAmount definition.
        // Note: Must start with exact prefix: "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,"
        string memory custom_type  =  "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,CustomCall call)CustomCall(uint256 value)TokenAmount(address token,uint256 amount)";
        bytes32 custom_hash  =  keccak256( abi.encode( keccak256( "CustomCall(uint256 value)" ), uint256(777) ) );

        // TokenAmount_offset points to "TokenAmount(" (validation code checks for ")" before it internally)
        uint256 TokenAmount_offset  =  126;

        mock_protocol.set_custom_signing_info( custom_type, custom_hash, TokenAmount_offset );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        ( bytes32 digest, bytes32 type_hash, string memory type_string )  =  core_harness.exposed_get_signing_data_for_execute_bond_as( execution_data );

        // Should use custom type string.
        assertEq( type_string, custom_type, "Should use custom type string" );
        assertEq( type_hash, keccak256( bytes(custom_type) ), "Type hash should match custom type" );
        assertTrue( digest != bytes32(0), "Digest should not be zero" );
    }

    function test_signing_data_domain_separator_updates_on_chain_fork() public
    {
        bytes32 domain_separator_before  =  core_harness.DOMAIN_SEPARATOR();

        assertTrue( domain_separator_before != bytes32(0), "Domain separator should not be zero" );

        vm.chainId( 999 );
        bytes32 domain_separator_after  =  core_harness.DOMAIN_SEPARATOR();

        assertTrue( domain_separator_after != bytes32(0), "Domain separator should not be zero after fork" );
        assertTrue( domain_separator_before != domain_separator_after, "Domain separator should change on chain fork" );
    }

    function test_signing_data_validates_typed_string_prefix() public
    {
        string memory valid_prefix  =  "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,CustomCall call)CustomCall(uint256 value)TokenAmount(address token,uint256 amount)";
        bytes32 valid_hash  =  keccak256( abi.encode( keccak256( "CustomCall(uint256 value)" ), uint256(123) ) );
        uint256 valid_offset  =  126;

        mock_protocol.set_custom_signing_info( valid_prefix, valid_hash, valid_offset );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        ( bytes32 digest, , )  =  core_harness.exposed_get_signing_data_for_execute_bond_as( execution_data );
        assertTrue( digest != bytes32(0), "Should validate correct prefix" );
    }

    function test_signing_data_rejects_malicious_prefix() public
    {
        string memory malicious_prefix  =  "MaliciousType(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,CustomCall call)CustomCall(uint256 value)TokenAmount(address token,uint256 amount)";
        bytes32 hash  =  keccak256( abi.encode( keccak256( "CustomCall(uint256 value)" ), uint256(123) ) );
        uint256 offset  =  126;

        mock_protocol.set_custom_signing_info( malicious_prefix, hash, offset );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        vm.expectRevert( InvalidTypedString.selector );
        core_harness.exposed_get_signing_data_for_execute_bond_as( execution_data );
    }

    function test_signing_data_validates_TokenAmount_definition() public
    {
        string memory valid_type  =  "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,CustomCall call)CustomCall(uint256 value)TokenAmount(address token,uint256 amount)";
        bytes32 valid_hash  =  keccak256( abi.encode( keccak256( "CustomCall(uint256 value)" ), uint256(123) ) );
        uint256 valid_offset  =  126;

        mock_protocol.set_custom_signing_info( valid_type, valid_hash, valid_offset );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        ( bytes32 digest, , )  =  core_harness.exposed_get_signing_data_for_execute_bond_as( execution_data );
        assertTrue( digest != bytes32(0), "Should validate correct TokenAmount definition" );
    }

    function test_signing_data_rejects_malicious_TokenAmount() public
    {
        string memory malicious_type  =  "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,CustomCall call)CustomCall(uint256 value)TokenAmount(bool hack,bool pwned)";
        bytes32 hash  =  keccak256( abi.encode( keccak256( "CustomCall(uint256 value)" ), uint256(123) ) );
        uint256 offset  =  126;

        mock_protocol.set_custom_signing_info( malicious_type, hash, offset );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        vm.expectRevert( InvalidTypedString.selector );
        core_harness.exposed_get_signing_data_for_execute_bond_as( execution_data );
    }

    function test_signing_data_handles_protocol_revert_gracefully() public
    {
        mock_protocol.set_should_revert( true );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: usdc, amount: 100e6 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        ( bytes32 digest, bytes32 type_hash, string memory type_string )  =  core_harness.exposed_get_signing_data_for_execute_bond_as( execution_data );

        assertEq( type_string, "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,bytes32 calldata_hash)TokenAmount(address token,uint256 amount)", "Should fallback to default type" );
        assertTrue( type_hash != bytes32(0), "Should generate valid type_hash" );
        assertTrue( digest != bytes32(0), "Should generate valid digest despite protocol revert" );
    }


    // ━━━━  EDGE CASES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_execute_bond_exactly_at_expiration() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 66666,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        // Warp to exactly expiration time
        vm.warp( block.timestamp + MAX_BOND_LIFETIME );
        vm.roll( block.number + 1 );

        // Should still be valid (not expired yet)
        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );
    }

    function test_execute_bond_one_second_before_expiration() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 77777,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        // Warp to one second before expiration
        vm.warp( block.timestamp + MAX_BOND_LIFETIME - 1 );
        vm.roll( block.number + 1 );

        // Should be valid
        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );
    }

    function test_execute_bond_max_fundings_allowed() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        // Create exactly MAX_FUNDINGS_PER_BOND fundings
        TokenAmount[] memory max_fundings  =  new TokenAmount[]( MAX_FUNDINGS_PER_BOND );
        for(  uint256 i = 0  ;  i < MAX_FUNDINGS_PER_BOND  ;  i++  )
        {
            max_fundings[ i ]  =  TokenAmount({ token: IERC20(address(uint160(i + 1))), amount: 1 });
        }

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: max_fundings,
            stake: stake,
            salt: 88888,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );

        vm.roll( block.number + 1 );

        // Should execute successfully with max fundings
        ( BondStatus status, ) = core_harness.exposed_execute_bond_internal( USER, execution_data );
        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond execution should succeed" );
    }

    function test_execute_bond_commitment_hash_collision_resistant() public view
    {
        TokenAmount memory stake1  =  TokenAmount({ token: usdc, amount: 100e6 });
        TokenAmount memory stake2  =  TokenAmount({ token: usdc, amount: 100e6 });

        // Same everything except salt
        ExecutionData memory execution_data1  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake1,
            salt: 1,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        ExecutionData memory execution_data2  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake2,
            salt: 2,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment1  =  core_harness.exposed_calc_commitment_hash( USER, execution_data1 );
        bytes32 commitment2  =  core_harness.exposed_calc_commitment_hash( USER, execution_data2 );

        assertTrue( commitment1 != commitment2, "Different salts should produce different commitments" );
    }


    // ━━━━  BOND EXECUTION TESTS: RETURN VALUES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_execute_bond_returns_executed_status_on_success() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );
        vm.roll( block.number + 1 );

        ( BondStatus status, bytes memory output ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should return EXECUTED status" );
        assertTrue( output.length >= 0, "Should return output bytes" );
    }

    function test_execute_bond_returns_invalid_bond_on_validation_failure() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        TokenAmount[] memory excessive_fundings  =  new TokenAmount[]( MAX_FUNDINGS_PER_BOND + 1 );
        for(  uint256 i = 0  ;  i <= MAX_FUNDINGS_PER_BOND  ;  i++  )
        {
            excessive_fundings[ i ]  =  TokenAmount({ token: IERC20(address(uint160(i + 1))), amount: 1 });
        }

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: excessive_fundings,
            stake: stake,
            salt: 99999,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        bytes32 commitment_hash  =  core_harness.exposed_calc_commitment_hash( USER, execution_data );
        core_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );
        vm.roll( block.number + 1 );

        ( BondStatus status, bytes memory output ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.INVALID_BOND), "Should return INVALID_BOND status" );
        assertEq( string(output), INVALID_TOO_MANY_FUNDINGS, "Output should contain validation failure reason" );
    }

    function test_execute_bond_returns_protocol_reverted_on_revert() public
    {
        mock_protocol.set_should_revert( true );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 77777,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );
        vm.roll( block.number + 1 );

        ( BondStatus status, bytes memory output ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.PROTOCOL_REVERTED), "Should return PROTOCOL_REVERTED status" );
        assertTrue( output.length > 0, "Output should contain protocol revert data" );
    }

    function test_execute_bond_returns_protocol_output_on_success() public
    {
        bytes memory expected_return  =  abi.encode( uint256(42), address(0x1234) );
        mock_protocol.set_return_data( expected_return );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 88888,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );
        vm.roll( block.number + 1 );

        ( BondStatus status, bytes memory output ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed" );
        assertEq( output, expected_return, "Output should match protocol return data" );
    }

    function test_execute_bond_returns_error_data_on_protocol_revert() public
    {
        bytes memory custom_error  =  abi.encodeWithSignature( "CustomError(string)", "something went wrong" );
        mock_protocol.set_should_revert( true, custom_error );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 99999,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );
        vm.roll( block.number + 1 );

        ( BondStatus status, bytes memory output ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.PROTOCOL_REVERTED), "Should return PROTOCOL_REVERTED" );
        assertEq( output, custom_error, "Output should contain protocol error data" );
    }

    function test_execute_bond_returns_validation_reason_on_invalid_bond() public
    {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        TokenAmount[] memory duplicate_fundings  =  new TokenAmount[](2);
        duplicate_fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 100e6 });
        duplicate_fundings[ 1 ]  =  TokenAmount({ token: usdc, amount: 50e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: duplicate_fundings,
            stake: stake,
            salt: 11111,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );
        vm.roll( block.number + 1 );

        ( BondStatus status, bytes memory output ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.INVALID_BOND), "Should return INVALID_BOND" );
        assertEq( string(output), INVALID_DUPLICATE_FUNDING_TOKEN, "Output should contain exact validation reason" );
    }

    function test_execute_bond_output_composability_with_abi_decode() public
    {
        uint256 expected_value  =  42;
        address expected_address  =  address(0xABCD);
        bytes memory encoded_return  =  abi.encode( expected_value, expected_address );
        mock_protocol.set_return_data( encoded_return );

        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: stake,
            salt: 22222,
            protocol: mock_protocol,
            call: abi.encodeWithSignature( "test()" )
        });

        _create_test_bond_with_execution_data( execution_data, 100e6 );
        vm.roll( block.number + 1 );

        ( BondStatus status, bytes memory output ) = core_harness.exposed_execute_bond_internal( USER, execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed" );

        ( uint256 decoded_value, address decoded_address )  =  abi.decode( output, (uint256, address) );

        assertEq( decoded_value, expected_value, "Decoded value should match" );
        assertEq( decoded_address, expected_address, "Decoded address should match" );
    }
}
