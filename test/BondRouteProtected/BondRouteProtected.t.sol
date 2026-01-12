// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "forge-std/console2.sol";
import { BondRoute } from "@BondRoute/BondRoute.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockBondRouteProtectedContract } from "@test/mocks/MockBondRouteProtectedContract.sol";
import { ProtocolAnnounced } from "@BondRoute/Provider.sol";
import { ExecutionData } from "@BondRoute/Core.sol";
import { IERC20, TokenAmount, BondConstraints, BondContext, Unauthorized, Range,
         PossiblyBondFarming, InsufficientStake, InvalidStakeToken, InsufficientFunding,
         BondCreatedTooLate, EXECUTION_TOO_SOON, EXECUTION_TOO_LATE, BEFORE_EXECUTION_WINDOW,
         AFTER_EXECUTION_WINDOW, BONDROUTE_ADDRESS } from "@BondRouteProtected/BondRouteProtected.sol";
import "@BondRoute/Definitions.sol";

/**
 * @title BondRouteProtectedTest
 * @notice Tests for BondRouteProtected integration library
 * @dev Implements IBondRouteProtectedTests from TestManifest.sol
 *
 * **CRITICAL TESTING CHALLENGE:**
 * BondRouteProtected.sol has a HARDCODED BondRoute address:
 *   `IBondRoute constant BondRoute = IBondRoute(address(...));`
 *
 * This address is immutable within the library code and cannot be changed without modifying the source.
 * To test the actual BondRouteProtected.sol file (not a modified copy), we use `vm.cloneAccount` to clone
 * our test BondRoute instance to the exact hardcoded address.
 *
 * **TESTING STRATEGY:**
 * 1. Import the hardcoded address constant from BondRouteProtected.sol
 * 2. Deploy our test BondRoute contract normally (with all constructor initialization)
 * 3. Use `vm.cloneAccount` to clone the deployed contract (code + storage + balance + nonce) to the hardcoded address
 * 4. All BondRouteProtected calls will now interact with our fully-initialized test instance
 *
 * **WHY vm.cloneAccount vs vm.etch:**
 * `vm.etch` only copies bytecode, losing all storage state (collector, EIP-712 domain, etc.)
 * `vm.cloneAccount` copies everything, preserving the complete initialized contract state
 */
contract BondRouteProtectedTest is Test {

    BondRoute public bond_route;
    MockBondRouteProtectedContract public mock_protected;
    MockERC20 public usdc;
    MockERC20 public dai;
    MockERC20 public weth;

    address public constant COLLECTOR  =  address(0x5555);
    address public constant USER       =  address(0x1111);

    function setUp() public
    {
        // Step 1: Deploy BondRoute normally.
        bond_route  =  new BondRoute( COLLECTOR );

        // Step 2: Clone the deployed BondRoute (code + storage + balance + nonce) to BONDROUTE_ADDRESS.
        //         This allows BondRouteProtected's hardcoded `BondRoute` constant to work in tests.
        //         Unlike vm.etch (which only copies bytecode), vm.cloneAccount preserves all storage state
        //         including constructor-initialized values like collector and EIP-712 domain.
        vm.cloneAccount( address(bond_route), BONDROUTE_ADDRESS );

        // Step 3: Update bond_route to point to the cloned instance at BONDROUTE_ADDRESS.
        bond_route  =  BondRoute(payable(BONDROUTE_ADDRESS));

        // Step 4: Verify the clone worked by checking DOMAIN_SEPARATOR (smoke test).
        bytes32 domain_separator  =  bond_route.DOMAIN_SEPARATOR( );
        assertTrue( domain_separator != bytes32(0), "vm.cloneAccount verification: DOMAIN_SEPARATOR should not be zero" );

        // Step 5: Deploy mock protocol that inherits BondRouteProtected.
        mock_protected  =  new MockBondRouteProtectedContract( "MockDEX", "MEV-protected test DEX" );

        // Step 6: Deploy test tokens.
        usdc  =  new MockERC20( "USDC", "USDC" );
        dai   =  new MockERC20( "DAI", "DAI" );
        weth  =  new MockERC20( "WETH", "WETH" );

        usdc.mint( USER, 10000e6 );
        dai.mint( USER, 10000e18 );
        weth.mint( USER, 100e18 );

        vm.deal( USER, 100 ether );

        // Step 7: User approves BondRoute for all tokens.
        vm.startPrank( USER );
        usdc.approve( address(bond_route), type(uint256).max );
        dai.approve( address(bond_route), type(uint256).max );
        weth.approve( address(bond_route), type(uint256).max );
        vm.stopPrank( );
    }


    // ━━━━  HELPER FUNCTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function _create_basic_execution_data( ) internal view returns ( ExecutionData memory )
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        return ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 12345,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 1000e6 )
        });
    }

    function _create_and_execute_bond( ExecutionData memory execution_data ) internal returns ( BondStatus status, bytes memory output )
    {
        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake);

        vm.roll( block.number + 1 );

        vm.prank( USER );
        return bond_route.execute_bond( execution_data );
    }


    // ━━━━  CONSTRUCTOR  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_constructor_announces_protocol( ) public
    {
        // We can't predict the exact address before deployment, so we check indexed=false for protocol field.
        vm.expectEmit( false, false, false, true );
        emit ProtocolAnnounced( address(0), "TestProtocol", "Test description" );

        MockBondRouteProtectedContract new_protocol  =  new MockBondRouteProtectedContract( "TestProtocol", "Test description" );

        assertTrue( address(new_protocol) != address(0), "Protocol should deploy successfully" );
    }

    function test_constructor_skips_announcement_on_empty_name( ) public
    {
        MockBondRouteProtectedContract new_protocol  =  new MockBondRouteProtectedContract( "", "" );

        assertTrue( address(new_protocol) != address(0), "Protocol should deploy successfully without announcement" );
    }


    // ━━━━  BONDROUTE_ENTRY_POINT()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_entry_point_only_callable_by_bondroute( ) public
    {
        BondContext memory fake_context  =  BondContext({
            user: USER,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            fundings: new TokenAmount[](0),
            creation_block: block.number,
            creation_timestamp: block.timestamp
        });

        bytes memory call  =  abi.encodeWithSelector( mock_protected.protected_swap.selector, 1000e6 );

        vm.prank( USER );
        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, address(bond_route) ) );
        mock_protected.BondRoute_entry_point( call, fake_context );
    }

    function test_entry_point_validates_context( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 10,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake);

        vm.roll( block.number + 1 );  // Only 1 block elapsed, but 10 required

        vm.prank( USER );
        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, EXECUTION_TOO_SOON, bytes32(uint256(10)) ) );
        bond_route.execute_bond( execution_data );
    }

    function test_entry_point_delegates_to_target( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        ( BondStatus status, ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond should execute successfully" );
        assertTrue( mock_protected.was_protected_function_called( ), "Protected function should be called via delegatecall" );
    }

    function test_entry_point_propagates_reverts( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        mock_protected.set_should_revert_on_protected_function( true );

        ( BondStatus status, ) = _create_and_execute_bond( execution_data );

        assertNotEq( uint(status), uint(BondStatus.EXECUTED), "Bond should fail when protocol reverts" );
    }

    function test_entry_point_preserves_msg_sender( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        _create_and_execute_bond( execution_data );

        assertEq( mock_protected.last_caller( ), address(bond_route), "msg.sender should be BondRoute during delegatecall" );
    }


    // ━━━━  BONDROUTE_INITIALIZE()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_initialize_extracts_context( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        _create_and_execute_bond( execution_data );

        BondContext memory captured_context  =  mock_protected.last_context( );

        assertEq( captured_context.user, USER, "Context should have correct user" );
        assertEq( address(captured_context.stake.token), address(weth), "Context should have correct stake token" );
        assertEq( captured_context.stake.amount, 10e18, "Context should have correct stake amount" );
    }

    function test_initialize_only_callable_by_bondroute( ) public
    {
        vm.prank( USER );
        vm.expectRevert( abi.encodeWithSelector( Unauthorized.selector, USER, address(bond_route) ) );
        mock_protected.protected_swap( 1000e6 );
    }

    // ━━━━  BONDROUTE_VALIDATE()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_validate_enforces_min_creation_time( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: block.timestamp + 1 hours, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        ( BondStatus status, ) = _create_and_execute_bond( execution_data );

        assertNotEq( uint(status), uint(BondStatus.EXECUTED), "Should fail validation (bond created too early)" );
    }

    function test_validate_enforces_max_creation_time( ) public
    {
        // Warp time forward so we can set a meaningful max_creation_time constraint.
        vm.warp( block.timestamp + 1000 );

        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 max_creation_time  =  block.timestamp - 500;
        uint256 actual_creation_time  =  block.timestamp;  // NOW, which is > max_creation_time

        // Configure constraints with max creation time in the past
        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: max_creation_time }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        BondContext memory context  =  BondContext({
            user: USER,
            stake: execution_data.stake,
            fundings: execution_data.fundings,
            creation_block: block.number,
            creation_timestamp: actual_creation_time  // Created now (too late)
        });

        // Should revert with BondCreatedTooLate(created_at=actual_creation_time, max=max_creation_time)
        vm.prank( address(bond_route) );
        vm.expectRevert( abi.encodeWithSelector( BondCreatedTooLate.selector, actual_creation_time, max_creation_time ) );
        mock_protected.BondRoute_entry_point( execution_data.call, context );
    }

    function test_validate_enforces_min_execution_delay( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 min_blocks  =  10;

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: min_blocks,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake);

        // Sad path: min_blocks - 1 should fail
        vm.roll( block.number + min_blocks - 1 );

        vm.prank( USER );
        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, EXECUTION_TOO_SOON, bytes32(min_blocks) ) );
        bond_route.execute_bond( execution_data );

        // Happy path: exactly min_blocks should pass
        vm.roll( block.number + 1 );

        vm.prank( USER );
        ( BondStatus status, ) = bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed at exactly min_blocks" );
    }

    function test_validate_enforces_max_execution_delay( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 max_seconds  =  60;

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: max_seconds,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake );

        uint256 creation_time  =  block.timestamp;
        vm.roll( block.number + 1 );

        // Sad path: exceeding max_seconds should fail.
        vm.warp( creation_time + max_seconds + 1 );

        vm.prank( USER );
        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, EXECUTION_TOO_LATE, bytes32(max_seconds) ) );
        bond_route.execute_bond( execution_data );

        // Happy path: exactly at max_seconds should pass.
        // *NOTE*  -  The revert above undoes all state changes, so we can retest with the same bond.
        vm.warp( creation_time + max_seconds );

        vm.prank( USER );
        ( BondStatus status, )  =  bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed at exactly max_seconds" );
    }

    function test_validate_enforces_stake_token( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );  // stake.token = weth

        // Configure constraints to require DAI instead of WETH
        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: dai, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        BondContext memory context  =  BondContext({
            user: USER,
            stake: execution_data.stake,  // weth
            fundings: execution_data.fundings,
            creation_block: block.number,
            creation_timestamp: block.timestamp
        });

        // Should revert with InvalidStakeToken(provided=weth, required=dai)
        vm.prank( address(bond_route) );
        vm.expectRevert( abi.encodeWithSelector( InvalidStakeToken.selector, address(weth), address(dai) ) );
        mock_protected.BondRoute_entry_point( execution_data.call, context );
    }

    function test_validate_enforces_stake_amount( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );  // stake.amount = 10e18

        // Configure constraints to require 20e18 instead of 10e18
        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 20e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        BondContext memory context  =  BondContext({
            user: USER,
            stake: execution_data.stake,  // 10e18
            fundings: execution_data.fundings,
            creation_block: block.number,
            creation_timestamp: block.timestamp
        });

        // Should revert with InsufficientStake(provided=10e18, required=20e18)
        vm.prank( address(bond_route) );
        vm.expectRevert( abi.encodeWithSelector( InsufficientStake.selector, 10e18, 20e18 ) );
        mock_protected.BondRoute_entry_point( execution_data.call, context );
    }

    function test_validate_enforces_funding_requirements( ) public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 500e6 });  // Providing only 500

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 999,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 500e6 )
        });

        TokenAmount[] memory required_fundings  =  new TokenAmount[](1);
        required_fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });  // Requiring 1000

        // Configure constraints to require 1000e6 USDC
        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: required_fundings,
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        BondContext memory context  =  BondContext({
            user: USER,
            stake: execution_data.stake,
            fundings: execution_data.fundings,  // Only 500e6
            creation_block: block.number,
            creation_timestamp: block.timestamp
        });

        // Should revert with InsufficientFunding(token=usdc, provided=500e6, required=1000e6)
        vm.prank( address(bond_route) );
        vm.expectRevert( abi.encodeWithSelector( InsufficientFunding.selector, address(usdc), 500e6, 1000e6 ) );
        mock_protected.BondRoute_entry_point( execution_data.call, context );
    }

    function test_validate_reverts_when_funding_token_not_found( ) public
    {
        // User provides USDC but protocol requires DAI.
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 888,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 1000e6 )
        });

        TokenAmount[] memory required_fundings  =  new TokenAmount[](1);
        required_fundings[ 0 ]  =  TokenAmount({ token: dai, amount: 1000e18 });  // Require DAI, but user has USDC

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: required_fundings,
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        BondContext memory context  =  BondContext({
            user: USER,
            stake: execution_data.stake,
            fundings: execution_data.fundings,
            creation_block: block.number,
            creation_timestamp: block.timestamp
        });

        // Should revert with InsufficientFunding(token=dai, provided=0, required=1000e18)
        vm.prank( address(bond_route) );
        vm.expectRevert( abi.encodeWithSelector( InsufficientFunding.selector, address(dai), 0, 1000e18 ) );
        mock_protected.BondRoute_entry_point( execution_data.call, context );
    }

    function test_validate_allows_excess_stake( ) public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 20e18 }),
            salt: 777,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 1000e6 )
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        ( BondStatus status, ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed with excess stake" );
    }

    function test_validate_allows_excess_funding( ) public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 2000e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 888,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 2000e6 )
        });

        TokenAmount[] memory required_fundings  =  new TokenAmount[](1);
        required_fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: required_fundings,
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        ( BondStatus status, ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed with excess funding" );
    }

    function test_validate_reverts_with_PossiblyBondFarming( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 min_blocks  =  10;

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: min_blocks,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake);

        vm.roll( block.number + 1 );  // Only 1 block, but 10 required

        vm.prank( USER );
        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, EXECUTION_TOO_SOON, bytes32(min_blocks) ) );
        bond_route.execute_bond( execution_data );
    }

    function test_validate_enforces_min_execution_time( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 min_execution_time  =  block.timestamp + 3600;

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: min_execution_time, max: 0 })
        }));

        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake);

        vm.roll( block.number + 1 );

        vm.prank( USER );
        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, BEFORE_EXECUTION_WINDOW, bytes32(min_execution_time) ) );
        bond_route.execute_bond( execution_data );
    }

    function test_validate_enforces_max_execution_time( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 max_execution_time  =  block.timestamp + 60;

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: max_execution_time })
        }));

        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake);

        vm.roll( block.number + 1 );
        vm.warp( block.timestamp + 120 );

        vm.prank( USER );
        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, AFTER_EXECUTION_WINDOW, bytes32(max_execution_time) ) );
        bond_route.execute_bond( execution_data );
    }

    function test_validate_allows_execution_within_absolute_time_window( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 min_execution_time  =  block.timestamp + 60;
        uint256 max_execution_time  =  block.timestamp + 3600;

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: min_execution_time, max: max_execution_time })
        }));

        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake);

        vm.roll( block.number + 1 );
        vm.warp( min_execution_time + 30 );

        vm.prank( USER );
        ( BondStatus status, ) = bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed when within execution window" );
    }

    function test_validate_allows_execution_exactly_at_min_time( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 min_execution_time  =  block.timestamp + 60;

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: min_execution_time, max: 0 })
        }));

        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake);

        vm.roll( block.number + 1 );
        vm.warp( min_execution_time );

        vm.prank( USER );
        ( BondStatus status, ) = bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed exactly at min execution time" );
    }

    function test_validate_allows_execution_exactly_at_max_time( ) public
    {
        ExecutionData memory execution_data  =  _create_basic_execution_data( );

        uint256 max_execution_time  =  block.timestamp + 3600;

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: max_execution_time })
        }));

        bytes32 commitment_hash  =  bond_route.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.prank( USER );
        bond_route.create_bond( commitment_hash, execution_data.stake);

        vm.roll( block.number + 1 );
        vm.warp( max_execution_time );

        vm.prank( USER );
        ( BondStatus status, ) = bond_route.execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed exactly at max execution time" );
    }


    // ━━━━  MULTI-FUNCTION SUPPORT  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_multiple_protected_functions_registered( ) public view
    {
        bytes4[] memory selectors  =  mock_protected.BondRoute_get_protected_selectors( );

        assertEq( selectors.length, 3, "Should have 3 protected functions" );
        assertEq( selectors[ 0 ], mock_protected.protected_swap.selector, "First selector should be protected_swap" );
        assertEq( selectors[ 1 ], mock_protected.protected_add_liquidity.selector, "Second selector should be protected_add_liquidity" );
        assertEq( selectors[ 2 ], mock_protected.protected_calc_minus_one.selector, "Third selector should be protected_calc_minus_one" );
    }

    function test_protected_add_liquidity_pulls_both_tokens( ) public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](2);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });
        fundings[ 1 ]  =  TokenAmount({ token: dai, amount: 500e18 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 777,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_add_liquidity.selector, 1000e6, 500e18 )
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        uint256 user_usdc_balance_before  =  usdc.balanceOf( USER );
        uint256 user_dai_balance_before   =  dai.balanceOf( USER );

        ( BondStatus status, ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond should execute successfully" );
        assertTrue( mock_protected.was_protected_function_called( ), "Protected function should be called" );

        uint256 user_usdc_balance_after  =  usdc.balanceOf( USER );
        uint256 user_dai_balance_after   =  dai.balanceOf( USER );
        uint256 protocol_usdc_balance    =  usdc.balanceOf( address(mock_protected) );
        uint256 protocol_dai_balance     =  dai.balanceOf( address(mock_protected) );

        assertEq( user_usdc_balance_after, user_usdc_balance_before - 1000e6, "User balance decreased by exactly 1000 USDC" );
        assertEq( user_dai_balance_after, user_dai_balance_before - 500e18, "User balance decreased by exactly 500 DAI" );
        assertEq( protocol_usdc_balance, 1000e6, "Protocol received 1000 USDC" );
        assertEq( protocol_dai_balance, 500e18, "Protocol received 500 DAI" );
    }

    function test_protected_add_liquidity_context_extraction( ) public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](2);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });
        fundings[ 1 ]  =  TokenAmount({ token: dai, amount: 500e18 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 888,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_add_liquidity.selector, 1000e6, 500e18 )
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        _create_and_execute_bond( execution_data );

        BondContext memory captured_context  =  mock_protected.last_context( );

        assertEq( captured_context.user, USER, "Context should have correct user" );
        assertEq( captured_context.fundings.length, 2, "Context should have 2 fundings" );
        assertEq( address(captured_context.fundings[ 0 ].token), address(usdc), "First funding should be USDC" );
        assertEq( address(captured_context.fundings[ 1 ].token), address(dai), "Second funding should be DAI" );
    }


    // ━━━━  FUNDINGSLIB  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_fundings_lib_pull( ) public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 555,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 1000e6 )
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        ( BondStatus status, ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond should execute successfully" );

        uint256 user_balance_after     =  usdc.balanceOf( USER );
        uint256 protocol_balance       =  usdc.balanceOf( address(mock_protected) );

        assertEq( user_balance_after, user_balance_before - 1000e6, "User balance decreased by exactly 1000 USDC" );
        assertEq( protocol_balance, 1000e6, "Protocol received 1000 USDC" );
    }

    function test_fundings_lib_send( ) public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 666,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 1000e6 )
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        ( BondStatus status, ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond should execute successfully" );

        uint256 user_balance_after     =  usdc.balanceOf( USER );
        uint256 protocol_balance       =  usdc.balanceOf( address(mock_protected) );

        assertEq( user_balance_after, user_balance_before - 1000e6, "User balance decreased by exactly 1000 USDC" );
        assertEq( protocol_balance, 1000e6, "Protocol received 1000 USDC" );
    }

    function test_fundings_lib_send_zero_amount_no_op( ) public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 777,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 0 )  // Pull zero amount
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        ( BondStatus status, ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Bond should execute successfully" );

        // User balance should be unchanged since zero was pulled.
        uint256 user_balance_after  =  usdc.balanceOf( USER );
        assertEq( user_balance_after, user_balance_before, "User balance unchanged on zero pull" );

        // Protocol should have received nothing.
        uint256 protocol_balance  =  usdc.balanceOf( address(mock_protected) );
        assertEq( protocol_balance, 0, "Protocol received nothing" );
    }


    // ━━━━  ENTRY POINT RETURN VALUES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_entry_point_returns_delegatecall_output( ) public
    {
        bytes memory expected_output  =  abi.encode( uint256(42), address(0x1234) );
        mock_protected.set_entry_point_return_data( expected_output );

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 777,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 1000e6 )
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        ( BondStatus status, bytes memory output ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed" );

        bytes memory decoded_output  =  abi.decode( output, (bytes) );
        assertEq( decoded_output, expected_output, "Output should match entry point return data" );
    }

    function test_entry_point_output_preserved_through_bondroute( ) public
    {
        uint256 swap_amount_in  =  1000e6;
        uint256 swap_amount_out  =  995e18;
        address swap_token_out  =  address(dai);

        bytes memory swap_return  =  abi.encode( swap_amount_in, swap_amount_out, swap_token_out );
        mock_protected.set_entry_point_return_data( swap_return );

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: swap_amount_in });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 888,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, swap_amount_in )
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        ( BondStatus status, bytes memory output ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed" );

        bytes memory decoded_bytes  =  abi.decode( output, (bytes) );
        ( uint256 decoded_amount_in, uint256 decoded_amount_out, address decoded_token_out )  =  abi.decode( decoded_bytes, (uint256, uint256, address) );

        assertEq( decoded_amount_in, swap_amount_in, "Amount in should be preserved" );
        assertEq( decoded_amount_out, swap_amount_out, "Amount out should be preserved" );
        assertEq( decoded_token_out, swap_token_out, "Token out should be preserved" );
    }

    function test_entry_point_returns_empty_bytes_on_void_function( ) public
    {
        mock_protected.set_entry_point_return_data( "" );

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 999,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_swap.selector, 1000e6 )
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        ( BondStatus status, bytes memory output ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed" );

        bytes memory decoded_output  =  abi.decode( output, (bytes) );
        assertEq( decoded_output.length, 0, "Decoded output should be empty bytes for void functions" );
    }

    function test_entry_point_returns_single_uint256( ) public
    {
        uint256 input_value  =  100;

        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: weth, amount: 10e18 }),
            salt: 1111,
            protocol: mock_protected,
            call: abi.encodeWithSelector( mock_protected.protected_calc_minus_one.selector, input_value )
        });

        mock_protected.configure_constraints( BondConstraints({
            min_stake: TokenAmount({ token: weth, amount: 10e18 }),
            min_fundings: new TokenAmount[](0),
            min_execution_delay_in_blocks: 0,
            max_execution_delay_in_seconds: 0,
            valid_creation_timestamp_range: Range({ min: 0, max: 0 }),
            valid_execution_timestamp_range: Range({ min: 0, max: 0 })
        }));

        ( BondStatus status, bytes memory output ) = _create_and_execute_bond( execution_data );

        assertEq( uint(status), uint(BondStatus.EXECUTED), "Should succeed" );

        uint256 decoded_value  =  abi.decode( output, (uint256) );

        assertEq( decoded_value, input_value - 1, "Decoded uint256 should equal input minus one" );
    }


    // ━━━━  BondRoute_airdrop() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_BondRoute_airdrop_with_erc20() public
    {
        uint256 airdrop_amount  =  1000e6;
        usdc.mint( address(mock_protected), airdrop_amount );

        uint256 bondroute_balance_before  =  usdc.balanceOf( address(bond_route) );

        mock_protected.exposed_BondRoute_airdrop( usdc, airdrop_amount, "Test airdrop" );

        uint256 bondroute_balance_after  =  usdc.balanceOf( address(bond_route) );
        assertEq( bondroute_balance_after - bondroute_balance_before, airdrop_amount, "BondRoute should receive airdrop" );
    }

    function test_BondRoute_airdrop_with_native() public
    {
        uint256 airdrop_amount  =  1 ether;
        vm.deal( address(mock_protected), airdrop_amount );

        uint256 bondroute_balance_before  =  address(bond_route).balance;

        mock_protected.exposed_BondRoute_airdrop{ value: airdrop_amount }( IERC20(address(0)), airdrop_amount, "Native airdrop" );

        uint256 bondroute_balance_after  =  address(bond_route).balance;
        assertEq( bondroute_balance_after - bondroute_balance_before, airdrop_amount, "BondRoute should receive native airdrop" );
    }

    function test_BondRoute_airdrop_zero_amount_no_op() public
    {
        uint256 bondroute_balance_before  =  usdc.balanceOf( address(bond_route) );

        mock_protected.exposed_BondRoute_airdrop( usdc, 0, "Zero airdrop" );

        uint256 bondroute_balance_after  =  usdc.balanceOf( address(bond_route) );
        assertEq( bondroute_balance_after, bondroute_balance_before, "Zero airdrop should be no-op" );
    }
}
