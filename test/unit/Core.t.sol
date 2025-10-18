// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/core/Core.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";
import "@OpenZeppelin/token/ERC20/ERC20.sol";


contract TestableCore is Core {
    constructor( address eip1153_detector ) Core( eip1153_detector ) { }
    
    function exposed_get_bond_internal( uint64 bond_id ) external view returns ( Bond memory ) {
        return _get_bond_internal( bond_id );
    }
    
    function exposed_calculate_commitment_proof( address user, ExecutionData calldata execution_data ) external view returns ( bytes21 ) {
        return _calculate_commitment_proof( user, execution_data );
    }
}

contract MockToken is ERC20 {
    constructor( ) ERC20( "Mock", "MOCK" ) {
        _mint( msg.sender, 1_000_000 * 10**18 );
    }
}


contract CoreTest is Test {

    TestableCore core;
    EIP1153Detector detector;
    MockToken token;
    address user;

    function setUp( ) public
    {
        user = makeAddr( "user" );
        detector = new EIP1153Detector( );
        core = new TestableCore( address(detector) );
        token = new MockToken( );
    }

    function test_get_bond_internal_reverts_nonexistent_bond( ) public
    {
        vm.expectRevert( abi.encodeWithSignature("BondNotFound(uint256)", 999) );
        core.exposed_get_bond_internal( 999 );
    }

    function test_calculate_commitment_proof_returns_deterministic_hash( ) public view
    {
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(token)), amount: 1000 });
        
        CallEntry[] memory calls = new CallEntry[](0);
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("test_secret")
        });
        
        bytes21 proof1 = core.exposed_calculate_commitment_proof( user, execution_data );
        bytes21 proof2 = core.exposed_calculate_commitment_proof( user, execution_data );
        
        assertEq( proof1, proof2 );
        assertTrue( proof1 != bytes21(0) );
    }

    function test_calculate_commitment_proof_different_for_different_users( ) public
    {
        address user2 = makeAddr( "user2" );
        
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(token)), amount: 1000 });
        
        CallEntry[] memory calls = new CallEntry[](0);
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("test_secret")
        });
        
        bytes21 proof1 = core.exposed_calculate_commitment_proof( user, execution_data );
        bytes21 proof2 = core.exposed_calculate_commitment_proof( user2, execution_data );
        
        assertTrue( proof1 != proof2 );
    }

    function test_calculate_commitment_proof_different_for_different_secrets( ) public view
    {
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(token)), amount: 1000 });
        
        CallEntry[] memory calls = new CallEntry[](0);
        
        ExecutionData memory execution_data1 = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret1")
        });
        
        ExecutionData memory execution_data2 = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret2")
        });
        
        bytes21 proof1 = core.exposed_calculate_commitment_proof( user, execution_data1 );
        bytes21 proof2 = core.exposed_calculate_commitment_proof( user, execution_data2 );
        
        assertTrue( proof1 != proof2 );
    }
}