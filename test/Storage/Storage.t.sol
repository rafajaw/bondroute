// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { Storage, BondNotFound, BondAlreadyExists, UnsupportedStake, BondStatus } from "@BondRoute/Storage.sol";
import { IERC20, TokenAmount } from "@BondRouteProtected/BondRouteProtected.sol";
import { HashLib } from "@BondRoute/HashLib.sol";
import { EIP1153Detector } from "@EIP1153Detector/EIP1153Detector.sol";
import { MockEIP1153Detector } from "@test/mocks/MockEIP1153Detector.sol";

/**
 * @title StorageHarness
 * @notice Test harness exposing Storage's internal functions for testing
 */
contract StorageHarness is Storage {

    constructor( address eip1153_detector ) Storage( eip1153_detector ) {}

    function exposed_create_bond_internal( bytes32 commitment_hash, TokenAmount memory stake, uint256 amount_received ) external
    {
        _create_bond_internal( commitment_hash, stake, amount_received );
    }

    function exposed_get_bond_info( bytes32 commitment_hash, TokenAmount memory stake ) external view returns ( BondInfo memory bond_info, bytes32 bond_key, uint256 packed_value )
    {
        return _get_bond_info( commitment_hash, stake );
    }

    function exposed_set_bond_status( bytes32 bond_key, uint256 previous_packed_value, BondStatus new_status ) external
    {
        _set_bond_status( bond_key, previous_packed_value, new_status );
    }

    function exposed_read_smart_var( uint256 slot ) external view returns ( uint256 value )
    {
        return _read_smart_var( slot );
    }

    function exposed_write_smart_var( uint256 slot, uint256 value ) external
    {
        _write_smart_var( slot, value );
    }

    function exposed_has_transient_storage_support( ) external view returns ( bool )
    {
        return _has_transient_storage_support( );
    }
}

/**
 * @title StorageTest
 * @notice Tests for Storage contract (bond creation, info retrieval, state management)
 * @dev Implements IStorageTests from TestManifest.sol
 */
contract StorageTest is Test {

    StorageHarness public storage_harness;
    EIP1153Detector public eip1153_detector;

    IERC20 public constant USDC  =  IERC20(address(0x1111));
    IERC20 public constant DAI   =  IERC20(address(0x2222));
    IERC20 public constant WETH  =  IERC20(address(0x3333));

    function setUp() public
    {
        eip1153_detector    =   new EIP1153Detector();
        storage_harness     =   new StorageHarness( address(eip1153_detector) );
    }


    // ━━━━  BOND CREATION TESTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_create_bond_basic() public
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );

        ( , bytes32 bond_key, )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_key, HashLib.calc_bond_key( commitment_hash, stake ), "Bond key should match calculated key" );
    }

    function test_create_bond_stores_correct_data() public
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );

        ( Storage.BondInfo memory bond_info, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.stake_amount_received, 100e6, "Stake amount should match" );
        assertEq( bond_info.creation_time, block.timestamp, "Creation time should match" );
        assertEq( bond_info.creation_block, block.number, "Creation block should match" );
        assertEq( uint8(bond_info.status), uint8(BondStatus.ACTIVE), "Should be active" );
    }

    function test_create_bond_fee_on_transfer() public
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        // Simulate fee-on-transfer: intended 100, received 95
        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 95e6 );

        ( Storage.BondInfo memory bond_info, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.stake_amount_received, 95e6, "Should store actual received amount (95)" );
    }

    function test_create_bond_bonus_on_transfer() public
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        // Simulate bonus-on-transfer: intended 100, received 105
        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 105e6 );

        ( Storage.BondInfo memory bond_info, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.stake_amount_received, 105e6, "Should store actual received amount (105)" );
    }

    function test_create_bond_reverts_if_already_exists() public
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );

        vm.expectRevert( BondAlreadyExists.selector );
        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );
    }

    function test_create_bond_reverts_on_excessive_fee() public
    {
        bytes32 commitment_hash  =  keccak256( "test_commitment" );

        // Loss exceeds int128 max.
        uint256 max_int128_as_uint  =  uint256( uint128( type(int128).max ) );
        uint256 excessive_loss      =  max_int128_as_uint + 1;

        // Stake needs to be large enough so (stake - excessive_loss) doesn't underflow.
        uint256 large_stake      =  excessive_loss + 1000;
        uint256 amount_received  =  1000;

        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: large_stake });

        vm.expectRevert( abi.encodeWithSelector( UnsupportedStake.selector, large_stake, amount_received, max_int128_as_uint ) );
        storage_harness.exposed_create_bond_internal( commitment_hash, stake, amount_received );
    }

    function test_create_bond_reverts_on_excessive_bonus() public
    {
        bytes32 commitment_hash  =  keccak256( "test_commitment" );
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        // Bonus exceeds int128 max.
        uint256 max_int128_as_uint  =  uint256( uint128( type(int128).max ) );
        uint256 excessive_bonus     =  max_int128_as_uint + 1;
        uint256 amount_received     =  100e6 + excessive_bonus;

        vm.expectRevert( abi.encodeWithSelector( UnsupportedStake.selector, 100e6, amount_received, max_int128_as_uint ) );
        storage_harness.exposed_create_bond_internal( commitment_hash, stake, amount_received );
    }

    function test_create_bond_zero_stake_allowed() public
    {
        bytes32 commitment_hash  =  keccak256("test_commitment_zero");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 0 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 0 );

        ( Storage.BondInfo memory bond_info, bytes32 bond_key, )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.stake_amount_received, 0, "Zero stake should be stored" );
        assertTrue( bond_key != bytes32(0), "Bond key should be generated even for zero stake" );
    }

    function test_create_bond_with_native_token() public
    {
        bytes32 commitment_hash  =  keccak256("test_commitment_native");
        TokenAmount memory stake  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 1 ether );

        ( Storage.BondInfo memory bond_info, bytes32 bond_key, )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.stake_amount_received, 1 ether, "Native token stake should be stored" );
        assertTrue( bond_key != bytes32(0), "Bond key should be generated for native token" );
    }

    function test_create_bond_different_tokens_same_commitment() public
    {
        bytes32 commitment_hash  =  keccak256("shared_commitment");
        TokenAmount memory stake_usdc  =  TokenAmount({ token: USDC, amount: 100e6 });
        TokenAmount memory stake_dai   =  TokenAmount({ token: DAI, amount: 100e18 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake_usdc, 100e6 );
        storage_harness.exposed_create_bond_internal( commitment_hash, stake_dai, 100e18 );

        ( Storage.BondInfo memory bond_info_usdc, bytes32 bond_key_usdc, )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake_usdc );
        ( Storage.BondInfo memory bond_info_dai, bytes32 bond_key_dai, )   =  storage_harness.exposed_get_bond_info( commitment_hash, stake_dai );

        assertTrue( bond_key_usdc != bond_key_dai, "Different stake tokens should create different bond keys" );

        assertEq( bond_info_usdc.stake_amount_received, 100e6, "USDC bond should store correct amount" );
        assertEq( bond_info_dai.stake_amount_received, 100e18, "DAI bond should store correct amount" );
    }

    function test_bond_key_unaffected_by_dirty_address_upper_bits() public pure
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        bytes32 bond_key_clean  =  HashLib.calc_bond_key( commitment_hash, stake );

        assembly {
            let addr  :=  mload( stake )
            mstore( stake, or( addr, shl( 160, 0xDEADBEEFCAFEBABE ) ) )
        }

        bytes32 bond_key_dirty  =  HashLib.calc_bond_key( commitment_hash, stake );

        assertTrue( bond_key_clean == bond_key_dirty, "Dirty upper bits MUST NOT change bond key" );
    }


    // ━━━━  BOND RETRIEVAL TESTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_get_bond_info_reverts_if_not_found() public
    {
        bytes32 commitment_hash  =  keccak256("nonexistent");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        vm.expectRevert( BondNotFound.selector );
        storage_harness.exposed_get_bond_info( commitment_hash, stake );
    }

    function test_get_bond_info_different_stakes_different_bonds() public
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake1  =  TokenAmount({ token: USDC, amount: 100e6 });
        TokenAmount memory stake2  =  TokenAmount({ token: USDC, amount: 200e6 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake1, 100e6 );

        // Same commitment, different stake → different bond
        vm.expectRevert( BondNotFound.selector );
        storage_harness.exposed_get_bond_info( commitment_hash, stake2 );
    }

    function test_get_bond_info_returns_accurate_delta() public
    {
        bytes32 commitment_hash  =  keccak256("test_delta");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        // Test with fee (received less)
        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 95e6 );
        ( Storage.BondInfo memory bond_info, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );
        assertEq( bond_info.stake_amount_received, 95e6, "Should accurately reflect 5e6 loss" );

        // Test with bonus (received more) - need different commitment
        bytes32 commitment_hash2  =  keccak256("test_delta_2");
        storage_harness.exposed_create_bond_internal( commitment_hash2, stake, 105e6 );
        ( Storage.BondInfo memory bond_info2, , )  =  storage_harness.exposed_get_bond_info( commitment_hash2, stake );
        assertEq( bond_info2.stake_amount_received, 105e6, "Should accurately reflect 5e6 gain" );
    }

    function test_get_bond_info_zero_delta_reconstruction() public
    {
        bytes32 commitment_hash  =  keccak256("test_zero_delta");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );

        ( Storage.BondInfo memory bond_info, , uint256 packed_value )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.stake_amount_received, 100e6, "Should reconstruct exact amount when delta is zero" );
        assertEq( bond_info.stake_amount_received, stake.amount, "Received amount should equal intended stake" );

        uint128 stored_delta  =  uint128( packed_value );
        assertEq( stored_delta, 0, "Stored delta should be zero" );
    }


    // ━━━━  BOND STATE MANAGEMENT TESTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_set_bond_as_executed() public
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );
        ( Storage.BondInfo memory bond_info_before, bytes32 bond_key, uint256 packed_value )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( uint8(bond_info_before.status), uint8(BondStatus.ACTIVE), "Should be active initially" );

        storage_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.EXECUTED );

        ( Storage.BondInfo memory bond_info_after, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( uint8(bond_info_after.status), uint8(BondStatus.EXECUTED), "Should be marked as executed" );
        assertEq( bond_info_after.stake_amount_received, 100e6, "Other fields should remain unchanged" );
    }

    function test_set_bond_as_failed() public
    {
        bytes32 commitment_hash  =  keccak256("test_failed");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );
        ( Storage.BondInfo memory bond_info_before, bytes32 bond_key, uint256 packed_value )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( uint8(bond_info_before.status), uint8(BondStatus.ACTIVE), "Should be active initially" );

        storage_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.INVALID_BOND );

        ( Storage.BondInfo memory bond_info_after, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( uint8(bond_info_after.status), uint8(BondStatus.INVALID_BOND), "Should be marked as failed" );
        assertEq( bond_info_after.stake_amount_received, 100e6, "Other fields should remain unchanged" );
    }

    function test_set_bond_as_liquidated() public
    {
        bytes32 commitment_hash  =  keccak256("test_liquidated");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );
        ( Storage.BondInfo memory bond_info_before, bytes32 bond_key, uint256 packed_value )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( uint8(bond_info_before.status), uint8(BondStatus.ACTIVE), "Should be active initially" );

        storage_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.LIQUIDATED );

        ( Storage.BondInfo memory bond_info_after, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( uint8(bond_info_after.status), uint8(BondStatus.LIQUIDATED), "Should be marked as liquidated" );
        assertEq( bond_info_after.stake_amount_received, 100e6, "Other fields should remain unchanged" );
    }

    function test_bond_status_persist_across_reads() public
    {
        bytes32 commitment_hash  =  keccak256("test_persistence");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );
        ( , bytes32 bond_key, uint256 packed_value )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        storage_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.EXECUTED );

        // Read multiple times to ensure persistence
        ( Storage.BondInfo memory read1, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );
        ( Storage.BondInfo memory read2, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );
        ( Storage.BondInfo memory read3, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( uint8(read1.status), uint8(BondStatus.EXECUTED), "First read should show executed" );
        assertEq( uint8(read2.status), uint8(BondStatus.EXECUTED), "Second read should show executed" );
        assertEq( uint8(read3.status), uint8(BondStatus.EXECUTED), "Third read should show executed" );
    }


    // ━━━━  SMART VARIABLE TESTS (TRANSIENT VS REGULAR STORAGE)  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_smart_var_with_transient_storage_support() public
    {
        // Create harness with mock detector that SUPPORTS transient storage.
        MockEIP1153Detector detector  =  new MockEIP1153Detector( true );
        StorageHarness harness  =  new StorageHarness( address(detector) );

        assertTrue( harness.exposed_has_transient_storage_support( ), "Should report transient storage support" );

        // Use arbitrary test slots.
        uint256 test_slot_1  =  uint256(keccak256( "test.slot.one" ));
        uint256 test_slot_2  =  uint256(keccak256( "test.slot.two" ));

        // Write and read back values.
        harness.exposed_write_smart_var( test_slot_1, 12345 );
        harness.exposed_write_smart_var( test_slot_2, 67890 );

        assertEq( harness.exposed_read_smart_var( test_slot_1 ), 12345, "Should read correct value from slot 1" );
        assertEq( harness.exposed_read_smart_var( test_slot_2 ), 67890, "Should read correct value from slot 2" );

        // Update and verify.
        harness.exposed_write_smart_var( test_slot_1, 99999 );
        assertEq( harness.exposed_read_smart_var( test_slot_1 ), 99999, "Should read updated value" );
    }

    function test_smart_var_without_transient_storage_support() public
    {
        // Create harness with mock detector that DOES NOT support transient storage.
        MockEIP1153Detector detector  =  new MockEIP1153Detector( false );
        StorageHarness harness  =  new StorageHarness( address(detector) );

        assertEq( harness.exposed_has_transient_storage_support( ), false, "Should report no transient storage support" );

        // Use arbitrary test slots.
        uint256 test_slot_1  =  uint256(keccak256( "test.slot.alpha" ));
        uint256 test_slot_2  =  uint256(keccak256( "test.slot.beta" ));

        // Write and read back values.
        harness.exposed_write_smart_var( test_slot_1, 11111 );
        harness.exposed_write_smart_var( test_slot_2, 22222 );

        assertEq( harness.exposed_read_smart_var( test_slot_1 ), 11111, "Should read correct value from slot 1" );
        assertEq( harness.exposed_read_smart_var( test_slot_2 ), 22222, "Should read correct value from slot 2" );

        // Update and verify.
        harness.exposed_write_smart_var( test_slot_1, 33333 );
        assertEq( harness.exposed_read_smart_var( test_slot_1 ), 33333, "Should read updated value" );
    }

    function test_smart_var_isolation_between_different_detectors() public
    {
        // Create two harnesses with different storage modes.
        MockEIP1153Detector detector_transient  =  new MockEIP1153Detector( true );
        MockEIP1153Detector detector_regular    =  new MockEIP1153Detector( false );

        StorageHarness harness_transient  =  new StorageHarness( address(detector_transient) );
        StorageHarness harness_regular    =  new StorageHarness( address(detector_regular) );

        uint256 test_slot  =  uint256(keccak256( "test.slot.shared" ));

        // Write different values to same slot on different harnesses.
        harness_transient.exposed_write_smart_var( test_slot, 777 );
        harness_regular.exposed_write_smart_var( test_slot, 888 );

        // Each should maintain its own value.
        assertEq( harness_transient.exposed_read_smart_var( test_slot ), 777, "Transient harness should have its value" );
        assertEq( harness_regular.exposed_read_smart_var( test_slot ), 888, "Regular harness should have its value" );
    }

    function test_smart_var_multiple_slots_independent() public
    {
        uint256 slot_a  =  uint256(keccak256( "slot.a" ));
        uint256 slot_b  =  uint256(keccak256( "slot.b" ));
        uint256 slot_c  =  uint256(keccak256( "slot.c" ));

        // Write to multiple slots
        storage_harness.exposed_write_smart_var( slot_a, 111 );
        storage_harness.exposed_write_smart_var( slot_b, 222 );
        storage_harness.exposed_write_smart_var( slot_c, 333 );

        // Verify all slots maintained independently
        assertEq( storage_harness.exposed_read_smart_var( slot_a ), 111, "Slot A should maintain value" );
        assertEq( storage_harness.exposed_read_smart_var( slot_b ), 222, "Slot B should maintain value" );
        assertEq( storage_harness.exposed_read_smart_var( slot_c ), 333, "Slot C should maintain value" );

        // Update one slot, others shouldn't change
        storage_harness.exposed_write_smart_var( slot_b, 999 );

        assertEq( storage_harness.exposed_read_smart_var( slot_a ), 111, "Slot A should remain unchanged" );
        assertEq( storage_harness.exposed_read_smart_var( slot_b ), 999, "Slot B should be updated" );
        assertEq( storage_harness.exposed_read_smart_var( slot_c ), 333, "Slot C should remain unchanged" );
    }

    function test_smart_var_persistence_across_calls() public
    {
        uint256 test_slot  =  uint256(keccak256( "persistence.test" ));

        // Write value
        storage_harness.exposed_write_smart_var( test_slot, 42 );

        // Simulate multiple external calls by reading multiple times
        for( uint i = 0; i < 5; i = i + 1 )
        {
            assertEq( storage_harness.exposed_read_smart_var( test_slot ), 42, "Value should persist across reads" );
        }

        // Update and verify persistence again
        storage_harness.exposed_write_smart_var( test_slot, 84 );

        for( uint i = 0; i < 5; i = i + 1 )
        {
            assertEq( storage_harness.exposed_read_smart_var( test_slot ), 84, "Updated value should persist across reads" );
        }
    }


    // ━━━━  BIT PACKING VALIDATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_bit_packing_max_timestamp() public
    {
        bytes32 commitment_hash  =  keccak256("max_timestamp_test");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        // Warp to near max uint56 timestamp
        uint256 max_timestamp  =  type(uint56).max;
        vm.warp( max_timestamp );

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );

        ( Storage.BondInfo memory bond_info, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.creation_time, max_timestamp, "Should handle max uint56 timestamp" );
    }

    function test_bit_packing_max_block_number() public
    {
        bytes32 commitment_hash  =  keccak256("max_block_test");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 100e6 });

        // Roll to near max uint64 block number
        uint256 max_block  =  type(uint64).max;
        vm.roll( max_block );

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 100e6 );

        ( Storage.BondInfo memory bond_info, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.creation_block, max_block, "Should handle max uint64 block number" );
    }

    function test_bit_packing_max_delta_positive() public
    {
        bytes32 commitment_hash  =  keccak256("max_positive_delta");

        // Max positive delta (int128.max as gain)
        uint256 max_positive_delta  =  uint256( uint128( type(int128).max ) );
        uint256 intended_stake      =  100e6;
        uint256 received_stake      =  intended_stake + max_positive_delta;

        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: intended_stake });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, received_stake );

        ( Storage.BondInfo memory bond_info, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.stake_amount_received, received_stake, "Should handle max positive delta" );
    }

    function test_bit_packing_max_delta_negative() public
    {
        bytes32 commitment_hash  =  keccak256("max_negative_delta");

        // Max negative delta (int128.max as loss)
        uint256 max_negative_delta  =  uint256( uint128( type(int128).max ) );
        uint256 intended_stake      =  max_negative_delta + 100e6;
        uint256 received_stake      =  100e6;

        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: intended_stake });

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, received_stake );

        ( Storage.BondInfo memory bond_info, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info.stake_amount_received, received_stake, "Should handle max negative delta" );
    }

    function test_bit_packing_no_collision_between_fields() public
    {
        bytes32 commitment_hash  =  keccak256("collision_test");
        TokenAmount memory stake  =  TokenAmount({ token: USDC, amount: 123456789 });

        // Set specific timestamp and block
        vm.warp( 1234567890 );
        vm.roll( 9876543210 );

        storage_harness.exposed_create_bond_internal( commitment_hash, stake, 123456789 );

        ( Storage.BondInfo memory bond_info, bytes32 bond_key, uint256 packed_value )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        // Verify all fields stored correctly (no bit collision)
        assertEq( bond_info.creation_time, 1234567890, "Timestamp should be correct" );
        assertEq( bond_info.creation_block, 9876543210, "Block number should be correct" );
        assertEq( bond_info.stake_amount_received, 123456789, "Stake amount should be correct" );
        assertEq( uint8(bond_info.status), uint8(BondStatus.ACTIVE), "Status should be ACTIVE" );

        // Set status and verify no interference with other fields
        storage_harness.exposed_set_bond_status( bond_key, packed_value, BondStatus.EXECUTED );
        ( Storage.BondInfo memory bond_info_after, , )  =  storage_harness.exposed_get_bond_info( commitment_hash, stake );

        assertEq( bond_info_after.creation_time, 1234567890, "Timestamp should remain unchanged" );
        assertEq( bond_info_after.creation_block, 9876543210, "Block number should remain unchanged" );
        assertEq( bond_info_after.stake_amount_received, 123456789, "Stake amount should remain unchanged" );
        assertEq( uint8(bond_info_after.status), uint8(BondStatus.EXECUTED), "Status should be EXECUTED" );
    }
}
