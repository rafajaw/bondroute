// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/admin/Admin.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";


contract TestableAdmin is Admin {
    constructor( address initial_admin, address eip1153_detector ) Admin( initial_admin, eip1153_detector ) { }
}


contract AdminTest is Test {

    TestableAdmin admin_contract;
    EIP1153Detector detector;
    address admin;
    address new_admin;

    function setUp( ) public
    {
        admin = makeAddr( "admin" );
        new_admin = makeAddr( "new_admin" );
        detector = new EIP1153Detector( );
        admin_contract = new TestableAdmin( admin, address(detector) );
    }

    function test_constructor_sets_initial_admin( ) public
    {
        vm.prank( admin );
        admin_contract.set_protocol_treasury( makeAddr("treasury") );
    }

    function test_constructor_reverts_with_zero_admin( ) public
    {
        vm.expectRevert( "Admin cannot be zero address" );
        new TestableAdmin( address(0), address(detector) );
    }

    function test_appoint_new_admin_success( ) public
    {
        vm.prank( admin );
        
        vm.expectEmit( true, true, false, false );
        emit AdminAppointed( new_admin, admin );
        
        admin_contract.appoint_new_admin( new_admin );
    }

    function test_appoint_new_admin_reverts_non_admin( ) public
    {
        vm.prank( new_admin );
        
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", "Admin access required") );
        admin_contract.appoint_new_admin( new_admin );
    }

    function test_appoint_new_admin_reverts_zero_address( ) public
    {
        vm.prank( admin );
        
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", "Admin cannot be zero address") );
        admin_contract.appoint_new_admin( address(0) );
    }

    function test_accept_admin_appointment_success( ) public
    {
        vm.prank( admin );
        admin_contract.appoint_new_admin( new_admin );
        
        vm.prank( new_admin );
        
        vm.expectEmit( true, true, false, false );
        emit AdminChanged( new_admin, admin );
        
        admin_contract.accept_admin_appointment( );
    }

    function test_accept_admin_appointment_reverts_wrong_caller( ) public
    {
        vm.prank( admin );
        admin_contract.appoint_new_admin( new_admin );
        
        vm.prank( admin );
        
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", "Must be the appointed admin") );
        admin_contract.accept_admin_appointment( );
    }

    function test_set_protocol_treasury_success( ) public
    {
        address treasury = makeAddr( "treasury" );
        
        vm.prank( admin );
        
        vm.expectEmit( true, true, false, false );
        emit ProtocolTreasuryChanged( treasury, admin );
        
        admin_contract.set_protocol_treasury( treasury );
    }

    function test_set_protocol_treasury_reverts_zero_address( ) public
    {
        vm.prank( admin );
        
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", "Invalid address") );
        admin_contract.set_protocol_treasury( address(0) );
    }

    function test_liquidate_defaulted_bonds_reverts_empty_array( ) public
    {
        uint64[] memory empty_bonds = new uint64[](0);
        
        vm.prank( admin );
        
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", "Empty array") );
        admin_contract.liquidate_defaulted_bonds( empty_bonds, makeAddr("beneficiary") );
    }

    function test_liquidate_defaulted_bonds_reverts_zero_beneficiary( ) public
    {
        uint64[] memory bonds = new uint64[](1);
        bonds[0] = 1;
        
        vm.prank( admin );
        
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", "Invalid address") );
        admin_contract.liquidate_defaulted_bonds( bonds, address(0) );
    }
}