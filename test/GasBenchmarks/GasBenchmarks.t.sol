// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { BondRoute } from "@BondRoute/BondRoute.sol";
import { ExecutionData } from "@BondRoute/Core.sol";
import { IERC20, TokenAmount } from "@BondRouteProtected/BondRouteProtected.sol";
import { EIP1153Detector } from "@EIP1153Detector/EIP1153Detector.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockEIP1153Detector } from "@test/mocks/MockEIP1153Detector.sol";
import { MockProtocol, FundingTransfer } from "@test/mocks/MockProtocol.sol";

/**
 * @title GasBenchmarksTest
 * @notice Gas benchmarking tests for BondRoute operations
 * @dev Implements IGasBenchmarkTests from TestManifest.sol
 *
 * TESTING STRATEGY:
 * - Pure overhead tests: Measure ONLY BondRoute's gas cost (mock does nothing)
 * - Realistic tests: Measure end-to-end cost including protocol work (mock pulls funds)
 */
contract GasBenchmarksTest is Test {

    BondRoute public bondRoute;
    MockERC20 public usdc;
    MockERC20 public dai;
    MockProtocol public mock_protocol;
    EIP1153Detector public eip1153_detector;

    address public constant SWEEPER    =  address(uint160(uint256(keccak256("SWEEPER"))));
    address public constant USER       =  address(0x1111);
    address public constant RECIPIENT  =  address(0x2222);

    function setUp() public {
        eip1153_detector  =  new EIP1153Detector();
        bondRoute         =  new BondRoute( SWEEPER, address(eip1153_detector) );
        usdc              =  new MockERC20( "USDC", "USDC" );
        dai               =  new MockERC20( "DAI", "DAI" );
        mock_protocol     =  new MockProtocol();

        // Fund user
        usdc.mint( USER, 1000000e6 );
        dai.mint( USER, 1000000e18 );
        vm.deal( USER, 1000 ether );

        // Approve
        vm.prank( USER );
        usdc.approve( address(bondRoute), type(uint256).max );

        vm.prank( USER );
        dai.approve( address(bondRoute), type(uint256).max );
    }


    // ━━━━  CORE OPERATIONS - PURE BONDROUTE OVERHEAD  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_gas_create_bond_erc20() external {
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt: 12345,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
        uint256 deadline  =  block.timestamp + 1 hours;

        vm.prank( USER );
        uint256 gas_start  =  gasleft();
        bondRoute.create_bond( commitment_hash, stake, deadline );
        uint256 gas_used  =  gas_start - gasleft();

        console.log("Gas for create_bond (ERC20):  ", gas_used);

        // Reasonable bounds: ~60-80k (storage write + ERC20 transfer)
        assertLt( gas_used, 100000, "create_bond ERC20 should be under 100k gas" );
    }

    function test_gas_create_bond_native() external {
        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt: 12345,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
        uint256 deadline  =  block.timestamp + 1 hours;

        vm.prank( USER );
        uint256 gas_start  =  gasleft();
        bondRoute.create_bond{ value: 1 ether }( commitment_hash, stake, deadline );
        uint256 gas_used  =  gas_start - gasleft();

        console.log("Gas for create_bond (native): ", gas_used);

        // Reasonable bounds: ~50-70k (storage write + native transfer)
        assertLt( gas_used, 100000, "create_bond native should be under 100k gas" );
    }

    function test_gas_execute_bond_minimal() external {
        // Setup: Create bond
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt: 12345,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
        uint256 deadline  =  block.timestamp + 1 hours;

        vm.prank( USER );
        bondRoute.create_bond( commitment_hash, stake, deadline );

        // Mock does NOTHING - pure BondRoute overhead
        mock_protocol.clear_funding_transfers();

        vm.roll( block.number + 1 );

        // Measure execute_bond with do-nothing protocol
        vm.prank( USER );
        uint256 gas_start  =  gasleft();
        bondRoute.execute_bond( execution_data );
        uint256 gas_used  =  gas_start - gasleft();

        console.log("Gas for execute_bond (minimal):", gas_used);

        // This measures PURE BondRoute overhead: validation + context setup + stake refund
        // Should be well under 100k
        assertLt( gas_used, 100000, "execute_bond minimal should be under 100k gas" );
    }

    function test_gas_execute_bond_with_funding() external {
        // Setup: Create bond with funding
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        // Configure mock to PULL funds (realistic scenario)
        FundingTransfer[] memory transfers  =  new FundingTransfer[](1);
        transfers[ 0 ]  =  FundingTransfer({
            to:          RECIPIENT,
            token:       usdc,
            amount:      1000e6
        });
        mock_protocol.set_funding_transfers( transfers );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  fundings,
            stake:     stake,
            salt: 12345,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
        uint256 deadline  =  block.timestamp + 1 hours;

        vm.prank( USER );
        bondRoute.create_bond( commitment_hash, stake, deadline );

        vm.roll( block.number + 1 );

        // Measure execute_bond with realistic funding pull
        vm.prank( USER );
        uint256 gas_start  =  gasleft();
        bondRoute.execute_bond( execution_data );
        uint256 gas_used  =  gas_start - gasleft();

        console.log("Gas for execute_bond (with funding):", gas_used);

        // Includes: BondRoute overhead + ERC20 transfer from user to recipient
        assertLt( gas_used, 150000, "execute_bond with funding should be under 150k gas" );
    }

    function test_gas_liquidate_single_bond() external {
        // Setup: Create expired bond
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt: 12345,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
        uint256 deadline  =  block.timestamp + 1 hours;

        uint256 creation_time  =  block.timestamp;

        vm.prank( USER );
        bondRoute.create_bond( commitment_hash, stake, deadline );

        // Warp past expiration (creation_time + MAX_BOND_LIFETIME = 111 days)
        vm.warp( creation_time + 111 days + 1 );

        bytes32[] memory commitment_hashes  =  new bytes32[](1);
        commitment_hashes[ 0 ]  =  commitment_hash;

        TokenAmount[] memory stakes  =  new TokenAmount[](1);
        stakes[ 0 ]  =  stake;

        // Measure liquidation
        vm.prank( SWEEPER );
        uint256 gas_start  =  gasleft();
        bondRoute.liquidate_expired_bonds( commitment_hashes, stakes, SWEEPER );
        uint256 gas_used  =  gas_start - gasleft();

        console.log("Gas for liquidate_single_bond:      ", gas_used);

        assertLt( gas_used, 100000, "liquidate single bond should be under 100k gas" );
    }

    function test_gas_liquidate_batch_10_bonds() external {
        // Setup: Create 10 expired bonds
        bytes32[] memory commitment_hashes  =  new bytes32[](10);
        TokenAmount[] memory stakes  =  new TokenAmount[](10);
        uint256 deadline  =  block.timestamp + 1 hours;
        uint256 creation_time  =  block.timestamp;

        unchecked
        {
            for(  uint256 i = 0  ;  i < 10  ;  i++  )
            {
                TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

                ExecutionData memory execution_data  =  ExecutionData({
                    fundings:  new TokenAmount[](0),
                    stake:     stake,
                    salt:      12345 + i,
                    protocol:  mock_protocol,
                    call:      abi.encodeWithSignature("test()")
                });

                bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

                vm.prank( USER );
                bondRoute.create_bond( commitment_hash, stake, deadline );

                commitment_hashes[ i ]  =  commitment_hash;
                stakes[ i ]             =  stake;
            }
        }

        // Warp past expiration (creation_time + MAX_BOND_LIFETIME = 111 days)
        vm.warp( creation_time + 111 days + 1 );

        // Measure batch liquidation
        vm.prank( SWEEPER );
        uint256 gas_start  =  gasleft();
        bondRoute.liquidate_expired_bonds( commitment_hashes, stakes, SWEEPER );
        uint256 gas_used  =  gas_start - gasleft();

        console.log("Gas for liquidate_batch_10_bonds:   ", gas_used);

        // Batch of 10 should be significantly more efficient per bond
        uint256 gas_per_bond  =  gas_used / 10;
        console.log("Gas per bond (batch):                ", gas_per_bond);

        assertLt( gas_used, 500000, "liquidate 10 bonds should be under 500k gas" );
    }

    function test_gas_claim_tips_single_token() external {
        // Setup: Accumulate tips
        vm.prank( USER );
        bondRoute.tip{ value: 1 ether }( IERC20(address(0)), 1 ether, "" );

        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  IERC20(address(0));

        // Measure claim
        vm.prank( SWEEPER );
        uint256 gas_start  =  gasleft();
        bondRoute.claim_accumulated_tips( tokens, SWEEPER );
        uint256 gas_used  =  gas_start - gasleft();

        console.log("Gas for claim_tips_single_token:    ", gas_used);

        assertLt( gas_used, 50000, "claim single token tips should be under 50k gas" );
    }

    function test_gas_claim_tips_multiple_tokens() external {
        // Setup: Accumulate tips in multiple tokens
        vm.prank( USER );
        bondRoute.tip{ value: 1 ether }( IERC20(address(0)), 1 ether, "" );

        vm.prank( USER );
        bondRoute.tip( usdc, 1000e6, "" );

        vm.prank( USER );
        bondRoute.tip( dai, 1000e18, "" );

        IERC20[] memory tokens  =  new IERC20[](3);
        tokens[ 0 ]  =  IERC20(address(0));
        tokens[ 1 ]  =  usdc;
        tokens[ 2 ]  =  dai;

        // Measure claim
        vm.prank( SWEEPER );
        uint256 gas_start  =  gasleft();
        bondRoute.claim_accumulated_tips( tokens, SWEEPER );
        uint256 gas_used  =  gas_start - gasleft();

        console.log("Gas for claim_tips_multiple_tokens: ", gas_used);

        assertLt( gas_used, 120000, "claim 3 token tips should be under 120k gas" );
    }


    // ━━━━  STORAGE OPTIMIZATIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_gas_transient_vs_regular_storage() external {
        // Create detector that returns TRUE (has EIP-1153)
        MockEIP1153Detector detector_with_support  =  new MockEIP1153Detector( true );
        BondRoute bondRoute_with_transient  =  new BondRoute( SWEEPER, address(detector_with_support) );

        // Create detector that returns FALSE (no EIP-1153)
        MockEIP1153Detector detector_without_support  =  new MockEIP1153Detector( false );
        BondRoute bondRoute_without_transient  =  new BondRoute( SWEEPER, address(detector_without_support) );

        // Prepare identical execution data
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        // Configure mock to pull funds
        FundingTransfer[] memory transfers  =  new FundingTransfer[](1);
        transfers[ 0 ]  =  FundingTransfer({
            to:          RECIPIENT,
            token:       usdc,
            amount:      1000e6
        });
        mock_protocol.set_funding_transfers( transfers );

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  fundings,
            stake:     stake,
            salt:      12345,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        // Setup user approvals for both contracts
        vm.prank( USER );
        usdc.approve( address(bondRoute_with_transient), type(uint256).max );

        vm.prank( USER );
        usdc.approve( address(bondRoute_without_transient), type(uint256).max );

        // Test WITH transient storage
        bytes32 commitment_hash_1  =  bondRoute_with_transient.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        uint256 initial_block  =  block.number;
        vm.prank( USER );
        bondRoute_with_transient.create_bond( commitment_hash_1, stake, block.timestamp + 1 hours );

        vm.roll( initial_block + 1 );

        vm.prank( USER );
        uint256 gas_start_transient  =  gasleft();
        bondRoute_with_transient.execute_bond( execution_data );
        uint256 gas_used_with_transient  =  gas_start_transient - gasleft();

        // Test WITHOUT transient storage (regular storage fallback)
        bytes32 commitment_hash_2  =  bondRoute_without_transient.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );

        vm.roll( initial_block + 2 );  // Move to different block for second bond
        vm.prank( USER );
        bondRoute_without_transient.create_bond( commitment_hash_2, stake, block.timestamp + 1 hours );

        vm.roll( initial_block + 3 );  // Move forward again for execution

        vm.prank( USER );
        uint256 gas_start_regular  =  gasleft();
        bondRoute_without_transient.execute_bond( execution_data );
        uint256 gas_used_without_transient  =  gas_start_regular - gasleft();

        // Report results
        console.log("Gas with transient storage:         ", gas_used_with_transient);
        console.log("Gas without transient storage:      ", gas_used_without_transient);
        console.log("Gas saved by transient storage:     ", gas_used_without_transient - gas_used_with_transient);

        // Verify transient storage uses less gas
        assertLt( gas_used_with_transient, gas_used_without_transient, "Transient storage should use less gas" );

        // Expected savings: SLOT_CURRENT_CONTEXT_HASH, SLOT_HELD_STAKE, SLOT_HELD_MSG_VALUE
        // Transient: TSTORE (100 gas) vs Regular: SSTORE non-zero (2900 gas)
        // Conservative estimate: should save at least 5k gas
        assertGe( gas_used_without_transient - gas_used_with_transient, 5000, "Should save at least 5k gas with transient storage" );
    }

    function test_gas_tip_dust_optimization() external {
        // Test that leaving 1 wei dust saves gas on subsequent tips

        // First tip (zero to non-zero write - expensive)
        vm.prank( USER );
        uint256 gas_start_first  =  gasleft();
        bondRoute.tip( usdc, 1000e6, "" );
        uint256 gas_used_first  =  gas_start_first - gasleft();

        // Sweeper claims (leaves 1 wei dust)
        IERC20[] memory tokens  =  new IERC20[](1);
        tokens[ 0 ]  =  usdc;

        vm.prank( SWEEPER );
        bondRoute.claim_accumulated_tips( tokens, SWEEPER );

        // Second tip (non-zero to non-zero write - cheaper)
        vm.prank( USER );
        uint256 gas_start_second  =  gasleft();
        bondRoute.tip( usdc, 1000e6, "" );
        uint256 gas_used_second  =  gas_start_second - gasleft();

        console.log("Gas for first tip (zero->nonzero):  ", gas_used_first);
        console.log("Gas for second tip (nonzero->nonzero):", gas_used_second);
        console.log("Gas saved by dust optimization:     ", gas_used_first - gas_used_second);

        // Second tip should be cheaper due to dust optimization
        // Zero->nonzero SSTORE costs 20k, nonzero->nonzero costs 2.9k
        // Should save ~15-17k gas
        assertLt( gas_used_second, gas_used_first, "Second tip should be cheaper due to dust optimization" );
        assertGe( gas_used_first - gas_used_second, 10000, "Dust optimization should save at least 10k gas" );
    }

    function test_gas_bit_packing_effectiveness() external {
        // This test demonstrates that bit packing allows us to store
        // bond info in a single storage slot

        // Create a bond
        TokenAmount memory stake  =  TokenAmount({ token: usdc, amount: 100e6 });

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt: 12345,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
        uint256 deadline  =  block.timestamp + 1 hours;

        vm.prank( USER );
        bondRoute.create_bond( commitment_hash, stake, deadline );

        // Retrieve bond info - should only cost 1 SLOAD (2100 gas) + decoding
        uint256 gas_start  =  gasleft();
        bondRoute.__OFF_CHAIN__get_bond_info( commitment_hash, stake );
        uint256 gas_used  =  gas_start - gasleft();

        console.log("Gas for get_bond_info (1 slot read): ", gas_used);

        // Should be very cheap - just 1 SLOAD + minimal decoding
        // Without bit packing, would need 3-4 SLOADs (6300-8400 gas)
        assertLt( gas_used, 10000, "Bond info retrieval should be under 10k gas with bit packing" );
    }


    // ━━━━  TARGET: ~45K GAS OVERHEAD CLAIM  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_gas_overhead_create_plus_execute_under_45k() external {
        // This test validates the "~45k gas overhead" claim in the README
        //
        // MEASUREMENT STRATEGY:
        // - Use ZERO stake to exclude ERC20 transfer costs
        // - Warm up target protocol first
        // - Mock does NOTHING (no funding pulls)
        // - Measure only BondRoute's pure logic overhead

        // ━━━━  OFF-CHAIN PREPARATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 0 });  // Native, zero stake!

        ExecutionData memory execution_data  =  ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt: 12345,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        });

        bytes32 commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, execution_data );
        uint256 deadline  =  block.timestamp + 1 hours;

        // Mock does NOTHING
        mock_protocol.clear_funding_transfers();

        // ━━━━  WARM UP ALL STORAGE SLOTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        // Create and execute a warmup bond to warm all mock storage slots
        bytes32 warmup_commitment_hash  =  bondRoute.__OFF_CHAIN__calc_commitment_hash( USER, ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt: 99999,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        }));

        vm.prank( USER );
        bondRoute.create_bond( warmup_commitment_hash, stake, deadline );

        vm.roll( 2 );

        vm.prank( USER );
        bondRoute.execute_bond( ExecutionData({
            fundings:  new TokenAmount[](0),
            stake:     stake,
            salt: 99999,
            protocol:  mock_protocol,
            call:      abi.encodeWithSignature("test()")
        }));

        // ━━━━  MEASURE: create_bond()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        vm.roll( 3 );

        vm.prank( USER );
        uint256 gas_start_create  =  gasleft();
        bondRoute.create_bond( commitment_hash, stake, deadline );
        uint256 gas_used_create  =  gas_start_create - gasleft();

        vm.roll( 4 );

        // ━━━━  MEASURE: execute_bond()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

        vm.prank( USER );
        uint256 gas_start_execute  =  gasleft();
        bondRoute.execute_bond( execution_data );
        uint256 gas_used_execute  =  gas_start_execute - gasleft();

        uint256 total_overhead  =  gas_used_create + gas_used_execute;

        console.log("");
        console.log("================================================================");
        console.log("BONDROUTE PURE OVERHEAD (zero stake, warm protocol):");
        console.log("================================================================");
        console.log("create_bond gas:                     ", gas_used_create);
        console.log("execute_bond gas:                    ", gas_used_execute);
        console.log("================================================================");
        console.log("TOTAL BONDROUTE OVERHEAD:            ", total_overhead);
        console.log("================================================================");
        console.log("");

        // This measures PURE BondRoute logic overhead:
        // - Storage write (create_bond)
        // - Validation, context setup, protocol call (execute_bond)
        // - NO token transfers (zero stake)
        // - Warm protocol contract

        assertLt( total_overhead, 45000, "Pure BondRoute overhead should be under 45k gas" );

        console.log("SUCCESS: BondRoute overhead verified under 45k gas!");
    }
}
