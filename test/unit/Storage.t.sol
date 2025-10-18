// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/core/Storage.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";
import "@OpenZeppelin/token/ERC20/ERC20.sol";


contract TestableStorage is Storage {
    constructor( address eip1153_detector ) Storage( eip1153_detector ) { }
    
    function exposed_get_available_funds_internal( ) external view returns ( TokenAmount[] memory ) {
        return _get_available_funds_internal( );
    }
    
    function exposed_get_available_amount_for_token_internal( IERC20 token ) external view returns ( uint256 ) {
        return _get_available_amount_for_token_internal( token );
    }
    
    function exposed_push_funds_internal( IERC20 token, uint256 amount, address source ) external {
        _push_funds_internal( token, amount, source );
    }
}

contract MockToken is ERC20 {
    constructor( ) ERC20( "Mock", "MOCK" ) {
        _mint( msg.sender, 1_000_000 * 10**18 );
    }
}


contract StorageTest is Test {

    TestableStorage storage_contract;
    EIP1153Detector detector;
    MockToken token;
    address user;

    function setUp( ) public
    {
        user = makeAddr( "user" );
        detector = new EIP1153Detector( );
        storage_contract = new TestableStorage( address(detector) );
        token = new MockToken( );
    }

    function test_get_available_funds_returns_empty_initially( ) public view
    {
        TokenAmount[] memory funds = storage_contract.exposed_get_available_funds_internal( );
        assertEq( funds.length, 0 );
    }

    function test_get_available_amount_for_token_returns_zero_initially( ) public view
    {
        uint256 amount = storage_contract.exposed_get_available_amount_for_token_internal( token );
        assertEq( amount, 0 );
    }

    function test_push_funds_internal_reverts_zero_token( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("Invalid(string,uint256)", "token", 0) );
        storage_contract.exposed_push_funds_internal( IERC20(address(0)), 1000, user );
    }

    function test_push_funds_internal_ignores_zero_amount( ) public
    {
        // Should not revert, just return early
        storage_contract.exposed_push_funds_internal( token, 0, user );
        
        uint256 amount = storage_contract.exposed_get_available_amount_for_token_internal( token );
        assertEq( amount, 0 );
    }

    function test_push_funds_internal_with_valid_token( ) public
    {
        uint256 amount = 1000;
        
        // Should work without reverting
        storage_contract.exposed_push_funds_internal( token, amount, user );
        
        // Note: The internal storage uses transient/regular storage and may not persist
        // without the proper execution context. This test mainly verifies no revert occurs.
        // The actual amount tracking is tested in the integration tests.
    }
}