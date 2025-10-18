// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/BondRoute.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";


contract BondRouteTest is Test {

    BondRoute bondroute;
    EIP1153Detector detector;
    address admin;

    function setUp( ) public
    {
        admin = makeAddr( "admin" );
        detector = new EIP1153Detector( );
        bondroute = new BondRoute( admin, address(detector) );
    }

    function test_domain_separator_returns_valid_hash( ) public view
    {
        bytes32 domain_separator = bondroute.DOMAIN_SEPARATOR( );
        
        assertTrue( domain_separator != bytes32(0) );
    }

    function test_receive_reverts_on_native_token_deposit( ) public
    {
        vm.expectRevert( "Possibly accidental deposit" );
        payable(address(bondroute)).transfer( 1 ether );
    }

    function test_constructor_sets_correct_admin( ) public
    {
        vm.prank( admin );
        
        // Admin functions should work with the initial admin
        address treasury = makeAddr( "treasury" );
        bondroute.set_protocol_treasury( treasury );
    }

    function test_bondroute_implements_user_interface( ) public
    {
        // Test that create_bond function exists and works as expected
        vm.expectRevert( abi.encodeWithSignature("Invalid(string,uint256)", "commitment_proof", 0) );
        bondroute.create_bond( bytes21(0) );
    }

    function test_bondroute_implements_admin_interface( ) public
    {
        // Test that admin functions exist and work as expected
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", "Admin access required") );
        bondroute.appoint_new_admin( makeAddr("new_admin") );
    }
}