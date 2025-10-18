// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/provider/Provider.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";
import "@OpenZeppelin/token/ERC20/ERC20.sol";


contract TestableProvider is Provider {
    constructor( address initial_admin, address eip1153_detector ) Provider( initial_admin, eip1153_detector ) { }
}

contract MockToken is ERC20 {
    constructor( ) ERC20( "Mock", "MOCK" ) {
        _mint( msg.sender, 1_000_000 * 10**18 );
    }
}


contract ProviderTest is Test {

    TestableProvider provider;
    EIP1153Detector detector;
    MockToken token;
    address admin;
    address user;

    function setUp( ) public
    {
        admin = makeAddr( "admin" );
        user = makeAddr( "user" );
        detector = new EIP1153Detector( );
        provider = new TestableProvider( admin, address(detector) );
        token = new MockToken( );
    }

    function test_get_available_funds_reverts_unauthorized( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("Unauthorized(address)", address(this)) );
        provider.get_available_funds( );
    }

    function test_get_available_amount_for_token_reverts_unauthorized( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("Unauthorized(address)", address(this)) );
        provider.get_available_amount_for_token( token );
    }

    function test_push_funds_reverts_unauthorized( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("Unauthorized(address)", address(this)) );
        provider.push_funds( token, 1000 );
    }

    function test_pull_funds_reverts_unauthorized( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("Unauthorized(address)", address(this)) );
        provider.pull_funds( token, 1000 );
    }

    function test_send_funds_reverts_unauthorized( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("Unauthorized(address)", address(this)) );
        provider.send_funds( token, 1000, user );
    }

    function test_provider_inherits_from_admin( ) public
    {
        vm.prank( admin );
        provider.set_protocol_treasury( makeAddr("treasury") );
        // Should work since admin has access
    }
}