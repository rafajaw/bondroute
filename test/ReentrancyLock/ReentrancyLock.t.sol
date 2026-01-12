// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { ReentrancyLock, Reentrancy } from "@BondRoute/utils/ReentrancyLock.sol";

/**
 * @title ReentrancyLockHarness
 * @notice Exposes ReentrancyLock modifiers for testing
 */
contract ReentrancyLockHarness is ReentrancyLock {

    bytes20 public constant LOCK_A  =  bytes20(keccak256("LOCK_A"));
    bytes20 public constant LOCK_B  =  bytes20(keccak256("LOCK_B"));

    uint256 public call_count;

    // ─── nonReentrant Tests ──────────────────────────────────────────────────────

    function protected_function() external nonReentrant( LOCK_A )
    {
        call_count  =  call_count + 1;
    }

    function try_reenter_same_lock() external nonReentrant( LOCK_A )
    {
        this.protected_function();  // Should revert - same lock.
    }

    function try_reenter_different_lock() external nonReentrant( LOCK_A )
    {
        this.protected_function_b();  // Should succeed - different lock.
    }

    function protected_function_b() external nonReentrant( LOCK_B )
    {
        call_count  =  call_count + 1;
    }

    // ─── nonReentrantView Tests ──────────────────────────────────────────────────

    function view_during_lock() external view nonReentrantView( LOCK_A ) returns ( uint256 )
    {
        return call_count;
    }

    function call_view_during_protected() external nonReentrant( LOCK_A ) returns ( uint256 )
    {
        return this.view_during_lock();  // Should revert - lock is held.
    }

    function call_view_outside_lock() external view returns ( uint256 )
    {
        return this.view_during_lock();  // Should succeed - no lock held.
    }

    function call_view_different_lock() external nonReentrant( LOCK_B ) returns ( uint256 )
    {
        return this.view_during_lock();  // Should succeed - different lock.
    }

    // ─── Lock Cleared After Execution ────────────────────────────────────────────

    function verify_lock_cleared() external nonReentrant( LOCK_A )
    {
        // Lock is held here, but after this function returns it should be cleared.
    }
}

/**
 * @title ReentrancyLockTest
 * @notice Tests for ReentrancyLock (nonReentrant and nonReentrantView modifiers)
 * @dev Implements IReentrancyLockTests from TestManifest.sol
 */
contract ReentrancyLockTest is Test {

    ReentrancyLockHarness public harness;

    function setUp() public
    {
        harness  =  new ReentrancyLockHarness();
    }


    // ━━━━  nonReentrant() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_nonReentrant_allows_single_call() public
    {
        harness.protected_function();

        assertEq( harness.call_count(), 1, "Single call should succeed" );
    }

    function test_nonReentrant_reverts_on_same_lock_reentry() public
    {
        vm.expectRevert( Reentrancy.selector );
        harness.try_reenter_same_lock();
    }

    function test_nonReentrant_allows_different_lock_reentry() public
    {
        harness.try_reenter_different_lock();

        assertEq( harness.call_count(), 1, "Different lock should allow nested call" );
    }

    function test_nonReentrant_clears_lock_after_execution() public
    {
        harness.verify_lock_cleared();
        harness.protected_function();  // Should succeed - lock was cleared.

        assertEq( harness.call_count(), 1, "Lock should be cleared after function returns" );
    }

    function test_nonReentrant_allows_sequential_calls() public
    {
        harness.protected_function();
        harness.protected_function();
        harness.protected_function();

        assertEq( harness.call_count(), 3, "Sequential calls should all succeed" );
    }


    // ━━━━  nonReentrantView() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_nonReentrantView_allows_call_when_unlocked() public view
    {
        uint256 result  =  harness.call_view_outside_lock();

        assertEq( result, 0, "View should succeed when lock not held" );
    }

    function test_nonReentrantView_reverts_when_same_lock_held() public
    {
        vm.expectRevert( Reentrancy.selector );
        harness.call_view_during_protected();
    }

    function test_nonReentrantView_allows_different_lock() public
    {
        uint256 result  =  harness.call_view_different_lock();

        assertEq( result, 0, "View should succeed with different lock" );
    }
}
