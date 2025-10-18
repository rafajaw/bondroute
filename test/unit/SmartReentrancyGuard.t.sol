// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/utils/SmartReentrancyGuard.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";


contract TestableReentrancyGuard is SmartReentrancyGuard {
    
    bool public entered_protected_function;
    
    constructor( address eip1153_detector ) SmartReentrancyGuard( eip1153_detector ) { }
    
    function protected_function( ) external nonReentrant( bytes20(uint160(uint256(keccak256("test_lock")))) ) {
        entered_protected_function = true;
        
        // Try to call itself recursively - should fail
        if( msg.data.length == 4 ) { // Only on first call
            this.protected_function( );
        }
    }
    
    function protected_function_simple( ) external nonReentrant( bytes20(uint160(uint256(keccak256("test_lock")))) ) {
        entered_protected_function = true;
        // This function doesn't try to call itself, so it should work normally
    }
    
    function protected_function_view( ) external view nonReentrantView( bytes20(uint160(uint256(keccak256("test_lock")))) ) returns ( bool ) {
        return true;
    }
    
    function check_reentrancy_status( bytes20 key ) external view returns ( bool ) {
        return _has_entered_reentrancy_guard( key );
    }
}


contract SmartReentrancyGuardTest is Test {

    TestableReentrancyGuard guard;
    EIP1153Detector detector;

    function setUp( ) public
    {
        detector = new EIP1153Detector( );
        guard = new TestableReentrancyGuard( address(detector) );
    }

    function test_constructor_reverts_zero_detector( ) public
    {
        vm.expectRevert( "Missing eip1153_detector" );
        new TestableReentrancyGuard( address(0) );
    }

    function test_constructor_reverts_detector_not_deployed( ) public
    {
        address fake_detector = makeAddr( "fake_detector" );
        
        vm.expectRevert( "eip1153_detector not deployed" );
        new TestableReentrancyGuard( fake_detector );
    }

    function test_nonreentrant_prevents_reentrancy( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("Reentrancy()") );
        guard.protected_function( );
    }

    function test_nonreentrant_allows_normal_execution( ) public
    {
        // Create a separate function that doesn't try to recursively call itself
        guard.protected_function_simple( );
        
        assertTrue( guard.entered_protected_function( ) );
    }

    function test_nonreentrant_view_works( ) public view
    {
        bool result = guard.protected_function_view( );
        assertTrue( result );
    }

    function test_has_entered_reentrancy_guard_returns_false_initially( ) public view
    {
        bytes20 test_key = bytes20(uint160(uint256(keccak256("test_lock"))));
        bool entered = guard.check_reentrancy_status( test_key );
        assertFalse( entered );
    }

    function test_different_keys_dont_interfere( ) public view
    {
        bytes20 key1 = bytes20(uint160(uint256(keccak256("key1"))));
        bytes20 key2 = bytes20(uint160(uint256(keccak256("key2"))));
        
        bool entered1 = guard.check_reentrancy_status( key1 );
        bool entered2 = guard.check_reentrancy_status( key2 );
        
        assertFalse( entered1 );
        assertFalse( entered2 );
    }
}