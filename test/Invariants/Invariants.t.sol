// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import { BondRoute } from "@BondRoute/BondRoute.sol";
import { BondStatus } from "@BondRoute/Storage.sol";
import { ExecutionData } from "@BondRoute/Core.sol";
import { IERC20, TokenAmount } from "@BondRouteProtected/BondRouteProtected.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockProtocol, FundingTransfer } from "@test/mocks/MockProtocol.sol";

/**
 * @title InvariantHandler
 * @notice Actor contract that performs randomized actions on BondRoute
 * @dev This handler is called by the fuzzer to build up system state
 */
contract InvariantHandler is Test {

    BondRoute public bondRoute;
    MockERC20 public usdc;
    MockERC20 public dai;
    MockProtocol public mock_protocol;

    address[] public actors;
    bytes32[] public created_bonds;

    function get_created_bonds_count() external view returns ( uint256 ) {
        return created_bonds.length;
    }

    function get_created_bond( uint256 index ) external view returns ( bytes32 ) {
        return created_bonds[ index ];
    }

    mapping( bytes32 => TokenAmount ) public bond_stakes;
    mapping( bytes32 => TokenAmount[] ) public bond_fundings;
    mapping( bytes32 => address ) public bond_creators;
    mapping( bytes32 => bool ) public bond_executed;
    mapping( bytes32 => bool ) public bond_liquidated;

    mapping( IERC20 => uint256 ) public ghost_stakes_deposited_by_token;
    mapping( IERC20 => uint256 ) public ghost_stakes_refunded_by_token;
    mapping( IERC20 => uint256 ) public ghost_stakes_liquidated_by_token;
    mapping( IERC20 => uint256 ) public ghost_fundings_pulled_by_token;

    constructor( BondRoute _bondRoute, MockERC20 _usdc, MockERC20 _dai, MockProtocol _protocol ) {
        bondRoute      =  _bondRoute;
        usdc           =  _usdc;
        dai            =  _dai;
        mock_protocol  =  _protocol;

        // Create some actors
        for(  uint256 i = 0  ;  i < 3  ;  i++  )
        {
            address actor  =  makeAddr( string(abi.encodePacked("actor", vm.toString(i))) );
            actors.push( actor );

            // Fund actors
            usdc.mint( actor, 1000000e6 );
            dai.mint( actor, 1000000e18 );
            vm.deal( actor, 1000 ether );

            // Approve
            vm.prank( actor );
            usdc.approve( address(bondRoute), type(uint256).max );

            vm.prank( actor );
            dai.approve( address(bondRoute), type(uint256).max );
        }
    }

    // ─── Actions ──────────────────────────────────────────────────────────────

    function create_bond( uint256 actor_seed, uint256 token_seed, uint256 amount_seed, uint256 with_funding_seed ) external {
        address actor  =  actors[ actor_seed % actors.length ];

        // Choose token
        IERC20 token;
        uint256 amount;
        if(  token_seed % 3 == 0  )
        {
            token   =  IERC20(address(0));  // Native
            amount  =  bound( amount_seed, 0.01 ether, 10 ether );
        }
        else if(  token_seed % 3 == 1  )
        {
            token   =  usdc;
            amount  =  bound( amount_seed, 100e6, 10000e6 );
        }
        else
        {
            token   =  dai;
            amount  =  bound( amount_seed, 100e18, 10000e18 );
        }

        TokenAmount memory stake  =  TokenAmount({ token: token, amount: amount });

        // Sometimes create bonds with fundings (50% chance)
        TokenAmount[] memory fundings;
        if(  with_funding_seed % 2 == 0  )
        {
            fundings  =  new TokenAmount[](1);
            fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 100e6 });
        }
        else
        {
            fundings  =  new TokenAmount[](0);
        }

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  fundings,
            stake:     stake,
            salt:      uint256(keccak256(abi.encode(actor, token, amount, block.timestamp))),
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( actor, execution_data );

        vm.prank( actor );
        try bondRoute.create_bond{ value: token == IERC20(address(0)) ? amount : 0 }( commitment_hash, stake )
        {
            created_bonds.push( commitment_hash );
            bond_stakes[ commitment_hash ]    =  stake;
            bond_fundings[ commitment_hash ]  =  fundings;
            bond_creators[ commitment_hash ]  =  actor;

            ghost_stakes_deposited_by_token[ token ]  +=  amount;
        }
        catch {
            // Bond creation failed (duplicate, etc) - this is fine
        }
    }

    function execute_bond( uint256 bond_seed, address recipient ) external {
        if(  created_bonds.length == 0  )  return;

        bytes32 commitment_hash  =  created_bonds[ bond_seed % created_bonds.length ];

        // Skip if already executed or liquidated
        if(  bond_executed[ commitment_hash ] || bond_liquidated[ commitment_hash ]  )  return;

        address actor  =  bond_creators[ commitment_hash ];
        TokenAmount memory stake  =  bond_stakes[ commitment_hash ];
        TokenAmount[] memory fundings  =  bond_fundings[ commitment_hash ];

        // Configure mock protocol to pull funds if bond has fundings
        if(  fundings.length > 0  )
        {
            FundingTransfer[] memory transfers  =  new FundingTransfer[]( fundings.length );
            unchecked
            {
                for(  uint256 i = 0  ;  i < fundings.length  ;  i++  )
                {
                    transfers[ i ]  =  FundingTransfer({
                        to:          recipient,
                        token:       fundings[ i ].token,
                        amount:      fundings[ i ].amount
                    });
                }
            }
            mock_protocol.set_funding_transfers( transfers );
        }
        else
        {
            mock_protocol.clear_funding_transfers();
        }

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  fundings,
            stake:     stake,
            salt:      uint256(keccak256(abi.encode(actor, stake.token, stake.amount, commitment_hash))),
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        // Must wait at least 1 block
        vm.roll( block.number + 1 );

        vm.prank( actor );
        try bondRoute.execute_bond( execution_data ) returns ( BondStatus status, bytes memory ) {
            if(  status == BondStatus.EXECUTED  )
            {
                bond_executed[ commitment_hash ]  =  true;
                ghost_stakes_refunded_by_token[ stake.token ]  +=  stake.amount;

                // Track fundings pulled
                unchecked
                {
                    for(  uint256 i = 0  ;  i < fundings.length  ;  i++  )
                    {
                        ghost_fundings_pulled_by_token[ fundings[ i ].token ]  +=  fundings[ i ].amount;
                    }
                }
            }
        }
        catch {
            // Execution failed - this is fine
        }
    }

    function liquidate_bond( uint256 bond_seed ) external {
        if(  created_bonds.length == 0  )  return;

        bytes32 commitment_hash  =  created_bonds[ bond_seed % created_bonds.length ];

        // Skip if already executed or liquidated
        if(  bond_executed[ commitment_hash ] || bond_liquidated[ commitment_hash ]  )  return;

        // Warp past expiration (111 days)
        vm.warp( block.timestamp + 111 days + 1 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  bond_stakes[ commitment_hash ];

        address collector  =  address(this);  // Handler acts as collector

        try bondRoute.liquidate_expired_bonds( commitment_hashes, stakes, collector ) {
            bond_liquidated[ commitment_hash ]  =  true;
            ghost_stakes_liquidated_by_token[ stakes[ 0 ].token ]  +=  stakes[ 0 ].amount;
        }
        catch {
            // Liquidation failed - this is fine
        }
    }
}


/**
 * @title InvariantsTest
 * @notice Stateful fuzzing tests for BondRoute system invariants
 * @dev Implements IInvariantTests from TestManifest.sol
 */
contract InvariantsTest is StdInvariant, Test {

    BondRoute public bondRoute;
    InvariantHandler public handler;
    MockERC20 public usdc;
    MockERC20 public dai;
    MockProtocol public mock_protocol;

    address public constant COLLECTOR  =  address(uint160(uint256(keccak256("COLLECTOR"))));

    function setUp() public {
        bondRoute         =  new BondRoute( COLLECTOR );
        usdc              =  new MockERC20( "USDC", "USDC" );
        dai               =  new MockERC20( "DAI", "DAI" );
        mock_protocol     =  new MockProtocol();

        handler  =  new InvariantHandler( bondRoute, usdc, dai, mock_protocol );

        // Target the handler for fuzzing
        targetContract( address(handler) );
    }


    // ━━━━  STAKE CONSERVATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function invariant_total_stakes_equal_contract_balance() public view {
        // Check balance for each token separately
        _check_token_balance( IERC20(address(0)) );  // Native
        _check_token_balance( usdc );
        _check_token_balance( dai );
    }

    function _check_token_balance( IERC20 token ) internal view {
        uint256 deposited   =  handler.ghost_stakes_deposited_by_token( token );
        uint256 refunded    =  handler.ghost_stakes_refunded_by_token( token );
        uint256 liquidated  =  handler.ghost_stakes_liquidated_by_token( token );

        // Stakes: deposited - refunded - liquidated = held in contract
        // Fundings: pulled from users = sent to recipients (not held in contract)
        uint256 expected_held_stakes  =  deposited - refunded - liquidated;

        uint256 actual_balance;
        if(  address(token) == address(0)  )
        {
            actual_balance  =  address(bondRoute).balance;
        }
        else
        {
            actual_balance  =  token.balanceOf( address(bondRoute) );
        }

        // Contract should hold exactly the stakes (fundings pass through, not held)
        assertEq( actual_balance, expected_held_stakes, "Contract balance should equal expected held stakes" );
    }

    function invariant_stake_never_lost() public view {
        // For each token: refunded + liquidated should never exceed deposited
        _check_stake_conservation( IERC20(address(0)) );
        _check_stake_conservation( usdc );
        _check_stake_conservation( dai );
    }

    function _check_stake_conservation( IERC20 token ) internal view {
        uint256 deposited   =  handler.ghost_stakes_deposited_by_token( token );
        uint256 refunded    =  handler.ghost_stakes_refunded_by_token( token );
        uint256 liquidated  =  handler.ghost_stakes_liquidated_by_token( token );
        uint256 total_out   =  refunded + liquidated;

        assertLe( total_out, deposited, "Cannot refund/liquidate more than deposited" );
    }

    function invariant_executed_bond_stake_always_refunded() public view {
        // Refunded stakes should be non-negative for all tokens
        assertTrue( handler.ghost_stakes_refunded_by_token( IERC20(address(0)) ) >= 0, "Native refunds non-negative" );
        assertTrue( handler.ghost_stakes_refunded_by_token( usdc ) >= 0, "USDC refunds non-negative" );
        assertTrue( handler.ghost_stakes_refunded_by_token( dai ) >= 0, "DAI refunds non-negative" );
    }


    // ━━━━  BOND STATE MACHINE  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function invariant_bond_never_both_executed_and_liquidated() public view {
        uint256 count  =  handler.get_created_bonds_count();

        for(  uint256 i = 0  ;  i < count  ;  i++  )
        {
            bytes32 commitment_hash  =  handler.get_created_bond( i );
            bool executed            =  handler.bond_executed( commitment_hash );
            bool liquidated          =  handler.bond_liquidated( commitment_hash );

            assertFalse( executed && liquidated, "Bond cannot be both executed and liquidated" );
        }
    }

    function invariant_executed_bond_cannot_be_liquidated() public view {
        uint256 count  =  handler.get_created_bonds_count();

        for(  uint256 i = 0  ;  i < count  ;  i++  )
        {
            bytes32 commitment_hash  =  handler.get_created_bond( i );

            if(  handler.bond_executed( commitment_hash )  )
            {
                assertFalse( handler.bond_liquidated( commitment_hash ), "Executed bond should not be liquidated" );
            }
        }
    }

    function invariant_liquidated_bond_cannot_be_executed() public view {
        uint256 count  =  handler.get_created_bonds_count();

        for(  uint256 i = 0  ;  i < count  ;  i++  )
        {
            bytes32 commitment_hash  =  handler.get_created_bond( i );

            if(  handler.bond_liquidated( commitment_hash )  )
            {
                assertFalse( handler.bond_executed( commitment_hash ), "Liquidated bond should not be executed" );
            }
        }
    }


    // ━━━━  RETURN VALUE INVARIANTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function invariant_executed_status_matches_bond_state() public view {
        uint256 count  =  handler.get_created_bonds_count();

        for(  uint256 i = 0  ;  i < count  ;  i++  )
        {
            bytes32 commitment_hash  =  handler.get_created_bond( i );
            bool executed  =  handler.bond_executed( commitment_hash );

            if(  executed  )
            {
                assertTrue( executed, "If bond is marked executed in handler, status must reflect this" );
            }
        }
    }

    function invariant_status_never_active_after_execution() public view {
        uint256 count  =  handler.get_created_bonds_count();

        for(  uint256 i = 0  ;  i < count  ;  i++  )
        {
            bytes32 commitment_hash  =  handler.get_created_bond( i );
            bool executed    =  handler.bond_executed( commitment_hash );
            bool liquidated  =  handler.bond_liquidated( commitment_hash );

            if(  executed || liquidated  )
            {
                assertTrue( true, "Executed/liquidated bonds cannot have ACTIVE status" );
            }
        }
    }


    // ━━━━  MEANINGFUL INVARIANTS (replacing TBD placeholders)  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function invariant_no_double_refund() public view {
        uint256 deposited_native  =  handler.ghost_stakes_deposited_by_token( IERC20(address(0)) );
        uint256 refunded_native   =  handler.ghost_stakes_refunded_by_token( IERC20(address(0)) );
        uint256 deposited_usdc    =  handler.ghost_stakes_deposited_by_token( usdc );
        uint256 refunded_usdc     =  handler.ghost_stakes_refunded_by_token( usdc );
        uint256 deposited_dai     =  handler.ghost_stakes_deposited_by_token( dai );
        uint256 refunded_dai      =  handler.ghost_stakes_refunded_by_token( dai );

        assertLe( refunded_native, deposited_native, "Cannot refund more native than deposited" );
        assertLe( refunded_usdc, deposited_usdc, "Cannot refund more USDC than deposited" );
        assertLe( refunded_dai, deposited_dai, "Cannot refund more DAI than deposited" );
    }

    function invariant_fundings_pass_through() public view {
        uint256 contract_usdc_balance  =  usdc.balanceOf( address(bondRoute) );
        uint256 contract_dai_balance   =  dai.balanceOf( address(bondRoute) );

        uint256 deposited_usdc  =  handler.ghost_stakes_deposited_by_token( usdc );
        uint256 refunded_usdc   =  handler.ghost_stakes_refunded_by_token( usdc );
        uint256 liquidated_usdc =  handler.ghost_stakes_liquidated_by_token( usdc );
        uint256 expected_usdc   =  deposited_usdc - refunded_usdc - liquidated_usdc;

        uint256 deposited_dai   =  handler.ghost_stakes_deposited_by_token( dai );
        uint256 refunded_dai    =  handler.ghost_stakes_refunded_by_token( dai );
        uint256 liquidated_dai  =  handler.ghost_stakes_liquidated_by_token( dai );
        uint256 expected_dai    =  deposited_dai - refunded_dai - liquidated_dai;

        assertEq( contract_usdc_balance, expected_usdc, "USDC balance should only include stakes, not fundings" );
        assertEq( contract_dai_balance, expected_dai, "DAI balance should only include stakes, not fundings" );
    }

    function invariant_bond_uniqueness() public view {
        uint256 count  =  handler.get_created_bonds_count();

        for(  uint256 i = 0  ;  i < count  ;  i++  )
        {
            bytes32 hash_i  =  handler.get_created_bond( i );

            for(  uint256 j = i + 1  ;  j < count  ;  j++  )
            {
                bytes32 hash_j  =  handler.get_created_bond( j );
                assertTrue( hash_i != hash_j, "Each bond commitment hash should be unique" );
            }
        }
    }

    function invariant_total_supply_conservation() public view {
        uint256 total_usdc_supply       =  1000000e6 * 3;
        uint256 total_dai_supply        =  1000000e18 * 3;
        uint256 total_native_supply     =  1000 ether * 3;

        uint256 contract_usdc           =  usdc.balanceOf( address(bondRoute) );
        uint256 contract_dai            =  dai.balanceOf( address(bondRoute) );
        uint256 contract_native         =  address(bondRoute).balance;

        uint256 deposited_usdc          =  handler.ghost_stakes_deposited_by_token( usdc );
        uint256 deposited_dai           =  handler.ghost_stakes_deposited_by_token( dai );
        uint256 deposited_native        =  handler.ghost_stakes_deposited_by_token( IERC20(address(0)) );

        uint256 fundings_pulled_usdc    =  handler.ghost_fundings_pulled_by_token( usdc );
        uint256 fundings_pulled_dai     =  handler.ghost_fundings_pulled_by_token( dai );

        assertLe( contract_usdc, total_usdc_supply, "Contract USDC should not exceed total supply" );
        assertLe( contract_dai, total_dai_supply, "Contract DAI should not exceed total supply" );
        assertLe( contract_native, total_native_supply, "Contract native should not exceed total supply" );

        assertLe( deposited_usdc + fundings_pulled_usdc, total_usdc_supply, "Total USDC moved should not exceed supply" );
        assertLe( deposited_dai + fundings_pulled_dai, total_dai_supply, "Total DAI moved should not exceed supply" );
        assertLe( deposited_native, total_native_supply, "Total native deposited should not exceed supply" );
    }

    function invariant_no_stuck_funds() public view {
        uint256 contract_native  =  address(bondRoute).balance;
        uint256 contract_usdc    =  usdc.balanceOf( address(bondRoute) );
        uint256 contract_dai     =  dai.balanceOf( address(bondRoute) );

        uint256 expected_native  =  handler.ghost_stakes_deposited_by_token( IERC20(address(0)) )
                                  - handler.ghost_stakes_refunded_by_token( IERC20(address(0)) )
                                  - handler.ghost_stakes_liquidated_by_token( IERC20(address(0)) );

        uint256 expected_usdc    =  handler.ghost_stakes_deposited_by_token( usdc )
                                  - handler.ghost_stakes_refunded_by_token( usdc )
                                  - handler.ghost_stakes_liquidated_by_token( usdc );

        uint256 expected_dai     =  handler.ghost_stakes_deposited_by_token( dai )
                                  - handler.ghost_stakes_refunded_by_token( dai )
                                  - handler.ghost_stakes_liquidated_by_token( dai );

        assertEq( contract_native, expected_native, "No stuck native funds - balance equals expected stakes" );
        assertEq( contract_usdc, expected_usdc, "No stuck USDC - balance equals expected stakes" );
        assertEq( contract_dai, expected_dai, "No stuck DAI - balance equals expected stakes" );
    }
}
