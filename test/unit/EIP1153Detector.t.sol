// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";


contract EIP1153DetectorTest is Test {

    EIP1153Detector detector;

    function setUp( ) public
    {
        detector = new EIP1153Detector( );
    }

    function test_get_transient_storage_support_returns_valid_code( ) public
    {
        uint256 result = detector.get_transient_storage_support( );
        
        // Should return either SUPPORTED or NOT_SUPPORTED
        assertTrue( result == SUPPORTED || result == NOT_SUPPORTED );
    }

    function test_get_transient_storage_support_is_deterministic( ) public
    {
        uint256 result1 = detector.get_transient_storage_support( );
        uint256 result2 = detector.get_transient_storage_support( );
        
        assertEq( result1, result2 );
    }

    function test_constants_have_expected_values( ) public pure
    {
        assertEq( SUPPORTED, 0x1153 );
        assertEq( NOT_SUPPORTED, 0x404 );
    }

    function test_issue_tstore_internal_is_external_but_works( ) public
    {
        // This function is external and should work when called directly
        // It's meant to be called by the detector itself via try/catch
        detector._issue_tstore_internal( );
    }

    function test_receive_reverts_on_native_token_deposit( ) public
    {
        vm.expectRevert( "Possibly accidental deposit" );
        payable(address(detector)).transfer( 1 ether );
    }

    function test_detector_has_correct_bytecode( ) public view
    {
        // Verify the detector contract was deployed successfully
        assertTrue( address(detector).code.length > 0 );
    }
}