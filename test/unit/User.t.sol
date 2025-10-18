// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/user/User.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";
import "@OpenZeppelin/token/ERC20/ERC20.sol";


contract TestableUser is User {
    constructor( address initial_admin, address eip1153_detector ) User( initial_admin, eip1153_detector ) { }
}

contract MockToken is ERC20 {
    constructor( ) ERC20( "Mock", "MOCK" ) {
        _mint( msg.sender, 1_000_000 * 10**18 );
    }
}


contract UserTest is Test {

    TestableUser user_contract;
    EIP1153Detector detector;
    MockToken token;
    address admin;
    address user;

    function setUp( ) public
    {
        admin = makeAddr( "admin" );
        user = makeAddr( "user" );
        detector = new EIP1153Detector( );
        user_contract = new TestableUser( admin, address(detector) );
        token = new MockToken( );
    }

    function test_create_bond_reverts_zero_commitment_proof( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("Invalid(string,uint256)", "commitment_proof", 0) );
        user_contract.create_bond( bytes21(0) );
    }

    function test_create_bond_with_stakes_reverts_zero_commitment_proof( ) public
    {
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: token, amount: 1000 });
        
        vm.expectRevert( abi.encodeWithSignature("Invalid(string,uint256)", "commitment_proof", 0) );
        user_contract.create_bond( bytes21(0), stakes, 0 );
    }

    function test_create_bond_with_stakes_reverts_too_many_stakes( ) public
    {
        TokenAmount[] memory stakes = new TokenAmount[](10); // Max is 9
        for( uint i = 0; i < 10; i++ ) {
            stakes[i] = TokenAmount({ token: token, amount: 1000 });
        }
        
        vm.expectRevert( abi.encodeWithSignature("TooManyStakes(uint256,uint256)", 10, 9) );
        user_contract.create_bond( bytes21(0x123456789012345678901234567890123456789012), stakes, 0 );
    }

    function test_create_bond_with_stakes_reverts_past_deadline( ) public
    {
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: token, amount: 1000 });
        
        // Set a specific timestamp to have predictable behavior
        vm.warp( 1000 );
        uint256 past_deadline = 999; // Before current timestamp
        
        // First approve the token transfer to avoid TokenTransferFailed error
        token.approve( address(user_contract), 1000 );
        
        vm.expectRevert( abi.encodeWithSignature("BondCreationPastDeadline(uint256)", past_deadline) );
        user_contract.create_bond( bytes21(0x123456789012345678901234567890123456789012), stakes, past_deadline );
    }

    function test_create_bond_success( ) public
    {
        bytes21 proof = bytes21(0x123456789012345678901234567890123456789012);
        
        vm.expectEmit( true, false, false, false );
        emit BondCreated( 1, proof, 0 );
        
        user_contract.create_bond( proof );
    }

    function test_execute_bond_reverts_nonexistent_bond( ) public
    {
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret")
        });
        
        vm.expectRevert( abi.encodeWithSignature("BondNotFound(uint256)", 999) );
        user_contract.execute_bond( 999, execution_data );
    }

    function test_off_chain_get_bond_reverts_nonexistent( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("BondNotFound(uint256)", 999) );
        user_contract.__OFF_CHAIN__get_bond( 999 );
    }

    function test_off_chain_calculate_commitment_proof_returns_deterministic( ) public view
    {
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: token, amount: 1000 });
        
        CallEntry[] memory calls = new CallEntry[](0);
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("test_secret")
        });
        
        bytes21 proof1 = user_contract.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bytes21 proof2 = user_contract.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        
        assertEq( proof1, proof2 );
        assertTrue( proof1 != bytes21(0) );
    }
}