// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/BondRoute.sol";
import "@BondRoute/integrations/BondRouteProtected.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";
import "@BondRoute/user/IUser.sol";
import "@OpenZeppelin/token/ERC20/ERC20.sol";


contract MockToken is ERC20 {
    constructor( ) ERC20( "MockToken", "MOCK" ) {
        _mint( msg.sender, 1_000_000 * 10**18 );
    }
    
    function mint( address to, uint256 amount ) external {
        _mint( to, amount );
    }
}


contract MaliciousContract is IBondRouteProtected {
    
    IBondRoute immutable bondroute;
    bool public should_revert;
    bool public should_oog;
    bool public should_return_wrong_magic;
    
    constructor( IBondRoute _bondroute ) {
        bondroute = _bondroute;
    }
    
    function set_malicious_behavior( bool _revert, bool _oog, bool _wrong_magic ) external {
        should_revert = _revert;
        should_oog = _oog;
        should_return_wrong_magic = _wrong_magic;
    }
    
    function BondRoute_is_BondRouteProtected( ) external pure returns ( bytes32 ) {
        return BONDROUTEPROTECTED_MAGIC_SIGNATURE;
    }
    
    function set_wrong_magic( ) external {
        should_return_wrong_magic = true;
    }
    
    function BondRoute_entry_point( bytes calldata target_calldata_with_appended_context ) external {
        if( msg.sender != address(bondroute) ) revert Unauthorized( msg.sender );
        
        if( should_oog ) {
            // Consume all gas
            uint256 i = 0;
            while( gasleft() > 1000 ) {
                i++;
            }
        }
        
        if( should_revert ) {
            revert( "Malicious revert" );
        }
        
        // Normal delegatecall
        ( bool success, bytes memory result ) = address(this).delegatecall( target_calldata_with_appended_context );
        if( !success ) {
            assembly {
                revert( add( result, 0x20 ), mload( result ) )
            }
        }
    }
    
    function BondRoute_get_execution_constraints( 
        bytes calldata, 
        IERC20, 
        TokenAmount[] memory 
    ) external pure override returns ( ExecutionConstraints memory ) {
        return ExecutionConstraints({
            min_bond_creation_time: 0,
            max_bond_creation_time: 0,
            min_execution_delay: 0,
            max_execution_delay: 0,
            min_bond_execution_time: 0,
            max_bond_execution_time: 0,
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 }),
            fundings: new TokenAmount[](0)
        });
    }
    
    function malicious_function( ) external pure {
        // Extract context to verify we're in bond execution
        if( msg.data.length < 96 ) revert( "Not in bond context" );
    }
}


contract WrongMagicContract is IBondRouteProtected {
    
    IBondRoute immutable bondroute;
    
    constructor( IBondRoute _bondroute ) {
        bondroute = _bondroute;
    }
    
    function BondRoute_is_BondRouteProtected( ) external pure returns ( bytes32 ) {
        return bytes32("wrong_magic");
    }
    
    function BondRoute_entry_point( bytes calldata target_calldata_with_appended_context ) external {
        if( msg.sender != address(bondroute) ) revert Unauthorized( msg.sender );
        
        ( bool success, bytes memory result ) = address(this).delegatecall( target_calldata_with_appended_context );
        if( !success ) {
            assembly {
                revert( add( result, 0x20 ), mload( result ) )
            }
        }
    }
    
    function BondRoute_get_execution_constraints( 
        bytes calldata, 
        IERC20, 
        TokenAmount[] memory 
    ) external pure override returns ( ExecutionConstraints memory ) {
        return ExecutionConstraints({
            min_bond_creation_time: 0,
            max_bond_creation_time: 0,
            min_execution_delay: 0,
            max_execution_delay: 0,
            min_bond_execution_time: 0,
            max_bond_execution_time: 0,
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 }),
            fundings: new TokenAmount[](0)
        });
    }
    
    function malicious_function( ) external pure {
        // Function to call
    }
}


contract OutOfGasContract is IBondRouteProtected {
    
    IBondRoute immutable bondroute;
    uint256 public gas_limit_for_failure;
    
    constructor( IBondRoute _bondroute ) {
        bondroute = _bondroute;
        gas_limit_for_failure = 50000; // Default gas limit to trigger OOG
    }
    
    function set_gas_limit( uint256 _limit ) external {
        gas_limit_for_failure = _limit;
    }
    
    function BondRoute_is_BondRouteProtected( ) external pure returns ( bytes32 ) {
        return BONDROUTEPROTECTED_MAGIC_SIGNATURE;
    }
    
    function BondRoute_entry_point( bytes calldata target_calldata_with_appended_context ) external {
        if( msg.sender != address(bondroute) ) revert Unauthorized( msg.sender );
        
        (bool success, bytes memory result) = address(this).delegatecall( target_calldata_with_appended_context );
        if( !success ) {
            if( result.length == 0 ) {
                // Empty result simulates out of gas condition
                revert PossiblyBondPicking( "Out of gas or unspecified failure" );
            }
            // Re-throw the original error
            assembly {
                revert( add( result, 0x20 ), mload( result ) )
            }
        }
    }
    
    function BondRoute_get_execution_constraints( 
        bytes calldata, 
        IERC20, 
        TokenAmount[] memory 
    ) external pure override returns ( ExecutionConstraints memory ) {
        return ExecutionConstraints({
            min_bond_creation_time: 0,
            max_bond_creation_time: 0,
            min_execution_delay: 0,
            max_execution_delay: 0,
            min_bond_execution_time: 0,
            max_bond_execution_time: 0,
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 }),
            fundings: new TokenAmount[](0)
        });
    }
    
    function target_function( ) external pure {
        // Simulate out-of-gas condition by reverting with empty bytes
        // revert(0, 0) simulates OOG since both produce empty return data
        assembly {
            revert(0, 0)
        }
    }
}


contract BondPickingAttacksTest is Test {

    BondRoute bondroute;
    EIP1153Detector detector;
    MockToken token;
    MaliciousContract malicious_contract;
    WrongMagicContract wrong_magic_contract;
    OutOfGasContract oog_contract;
    
    address admin;
    address attacker;
    address treasury;

    function setUp( ) public
    {
        admin = makeAddr( "admin" );
        attacker = makeAddr( "attacker" );
        treasury = makeAddr( "treasury" );
        
        detector = new EIP1153Detector( );
        bondroute = new BondRoute( admin, address(detector) );
        token = new MockToken( );
        
        malicious_contract = new MaliciousContract( IBondRoute(address(bondroute)) );
        wrong_magic_contract = new WrongMagicContract( IBondRoute(address(bondroute)) );
        oog_contract = new OutOfGasContract( IBondRoute(address(bondroute)) );
        
        vm.prank( admin );
        bondroute.set_protocol_treasury( treasury );
        
        token.mint( attacker, 10_000 * 10**18 );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              BOND PICKING ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_multiple_bonds_selective_execution( ) public
    {
        uint256 stake_amount = 1000 * 10**18;
        
        // Attacker creates multiple bonds with different secrets (simulating different strategies)
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: token, amount: stake_amount });
        
        vm.startPrank( attacker );
        token.approve( address(bondroute), stake_amount * 3 );
        
        // Create 3 bonds with different execution data
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(malicious_contract)),
            _calldata: abi.encodeWithSignature("malicious_function()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data1 = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: calls,
            secret: keccak256("strategy1")
        });
        
        ExecutionData memory execution_data2 = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: calls,
            secret: keccak256("strategy2")
        });
        
        ExecutionData memory execution_data3 = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: calls,
            secret: keccak256("strategy3")
        });
        
        // Create 3 bonds
        bytes21 proof1 = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data1 );
        bytes21 proof2 = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data2 );
        bytes21 proof3 = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data3 );
        
        bondroute.create_bond( proof1, stakes, 0 );
        bondroute.create_bond( proof2, stakes, 0 );
        bondroute.create_bond( proof3, stakes, 0 );
        
        uint256 attacker_balance_after_bonds = token.balanceOf( attacker );
        
        vm.roll( block.number + 1 );
        
        // Try to execute only one bond (bond picking)
        bondroute.execute_bond( 1, execution_data1 );
        
        // Attacker gets back stake from executed bond
        uint256 attacker_balance_after_execution = token.balanceOf( attacker );
        assertEq( attacker_balance_after_execution, attacker_balance_after_bonds + stake_amount );
        
        vm.stopPrank( );
        
        // Other bonds remain with stakes locked (attacker loses stakes for non-executed bonds)
        // This is the economic deterrent - attacker pays for bond picking attempts
        
        // Fast forward beyond expiry and liquidate
        vm.warp( block.timestamp + 102 days );
        
        uint64[] memory bond_ids = new uint64[](2);
        bond_ids[0] = 2;
        bond_ids[1] = 3;
        
        vm.prank( admin );
        bondroute.liquidate_defaulted_bonds( bond_ids, treasury );
        
        // Treasury should receive the forfeited stakes
        assertEq( token.balanceOf( treasury ), stake_amount * 2 );
    }

    function test_attack_out_of_gas_prevents_execution( ) public
    {
        uint256 stake_amount = 1000 * 10**18;
        
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: token, amount: stake_amount });
        
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(oog_contract)),
            _calldata: abi.encodeWithSignature("target_function()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: calls,
            secret: keccak256("oog_attack")
        });
        
        vm.startPrank( attacker );
        token.approve( address(bondroute), stake_amount );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data );
        bondroute.create_bond( proof, stakes, 0 );
        
        vm.roll( block.number + 1 );
        
        // This should fail due to bond picking prevention (out of gas gives empty revert data)
        vm.expectRevert( abi.encodeWithSignature("PossiblyBondPicking(string)", "Out of gas or unspecified failure") );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
        
        // Stake should remain locked (attacker doesn't get it back)
        assertEq( token.balanceOf( attacker ), 10_000 * 10**18 - stake_amount );
    }

    function test_attack_malicious_contract_wrong_magic_signature( ) public
    {
        uint256 stake_amount = 1000 * 10**18;
        
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: token, amount: stake_amount });
        
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(wrong_magic_contract)),
            _calldata: abi.encodeWithSignature("malicious_function()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: calls,
            secret: keccak256("wrong_magic")
        });
        
        vm.startPrank( attacker );
        token.approve( address(bondroute), stake_amount );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data );
        bondroute.create_bond( proof, stakes, 0 );
        
        vm.roll( block.number + 1 );
        
        // Should fail due to wrong magic signature (bond picking prevention)
        vm.expectRevert( abi.encodeWithSignature("PossiblyBondPicking(string)", "Out of gas or not BondRouteProtected") );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
    }

    function test_attack_call_entry_point_directly( ) public
    {
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(malicious_contract)),
            _calldata: abi.encodeWithSignature("BondRoute_entry_point(bytes)", "0x"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: calls,
            secret: keccak256("entry_point_attack")
        });
        
        vm.startPrank( attacker );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        // Should fail - cannot call BondRoute_entry_point directly
        vm.expectRevert( abi.encodeWithSignature("BondExecutionForbiddenCall(uint256,uint256,string)", 1, 0, "Calling BondRoute_entry_point") );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
    }

    function test_attack_precompiled_contract_address( ) public
    {
        // Try to call precompiled contract address (e.g., ecrecover at 0x01)
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(0x01)), // ecrecover precompiled
            _calldata: abi.encodeWithSignature("someFunction()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: calls,
            secret: keccak256("precompiled_attack")
        });
        
        vm.startPrank( attacker );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        // Should fail - cannot call precompiled contracts
        vm.expectRevert( abi.encodeWithSignature("BondExecutionForbiddenCall(uint256,uint256,string)", 1, 0, "Invalid contract address") );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
    }

    function test_attack_same_block_execution_prevention( ) public
    {
        ExecutionData memory execution_data = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: new CallEntry[](0),
            secret: keccak256("same_block")
        });
        
        vm.startPrank( attacker );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data );
        bondroute.create_bond( proof );
        
        // Try to execute in same block - should fail
        vm.expectRevert( abi.encodeWithSignature("SameBlockExecute(uint256)", 1) );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
    }

    function test_attack_expired_bond_execution( ) public
    {
        ExecutionData memory execution_data = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: new CallEntry[](0),
            secret: keccak256("expired")
        });
        
        vm.startPrank( attacker );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data );
        bondroute.create_bond( proof );
        
        // Fast forward beyond 101 days
        vm.warp( block.timestamp + 102 days );
        vm.roll( block.number + 1 );
        
        uint256 execution_deadline = block.timestamp - 102 days + 101 days;
        
        // Should fail - bond expired
        vm.expectRevert( abi.encodeWithSignature("BondExpired(uint256,uint256)", 1, execution_deadline) );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
    }

    function test_attack_commitment_proof_mismatch( ) public
    {
        ExecutionData memory execution_data1 = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: new CallEntry[](0),
            secret: keccak256("original")
        });
        
        ExecutionData memory execution_data2 = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: new CallEntry[](0),
            secret: keccak256("modified") // Different secret
        });
        
        vm.startPrank( attacker );
        
        bytes21 proof1 = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data1 );
        bondroute.create_bond( proof1 );
        
        vm.roll( block.number + 1 );
        
        bytes21 expected_proof = proof1;
        bytes21 calculated_proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( attacker, execution_data2 );
        
        // Try to execute with different execution data
        vm.expectRevert( abi.encodeWithSignature("CommitmentProofMismatch(uint256,bytes32,bytes32)", 1, expected_proof, calculated_proof) );
        bondroute.execute_bond( 1, execution_data2 );
        
        vm.stopPrank( );
    }
}