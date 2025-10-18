// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/BondRoute.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";
import "@BondRoute/utils/SignatureValidator.sol";
import "@BondRoute/user/IUser.sol";
import "@BondRoute/integrations/IBondRouteProtected.sol";
import "@OpenZeppelin/interfaces/IERC1271.sol";
import "@OpenZeppelin/token/ERC20/IERC20.sol";


contract MockERC1271Wallet is IERC1271 {
    address public owner;
    bool public should_reject;
    bool public should_revert;
    bytes4 public wrong_magic_value;
    
    constructor( address _owner ) {
        owner = _owner;
    }
    
    function set_rejection_behavior( bool _reject, bool _revert, bytes4 _wrong_magic ) external {
        should_reject = _reject;
        should_revert = _revert;
        wrong_magic_value = _wrong_magic;
    }
    
    function isValidSignature( bytes32 , bytes memory signature ) external view override returns ( bytes4 ) {
        if( should_revert ) {
            revert( "Wallet revert" );
        }
        
        if( should_reject ) {
            return 0xffffffff; // Invalid magic value
        }
        
        if( wrong_magic_value != bytes4(0) ) {
            return wrong_magic_value;
        }
        
        // Simple validation: signature should contain owner address
        if( signature.length >= 20 ) {
            address signer = abi.decode( signature, (address) );
            if( signer == owner ) {
                return IERC1271.isValidSignature.selector;
            }
        }
        
        return 0xffffffff;
    }
}


contract MaliciousContract {
    // Contract that doesn't implement ERC1271 but has code
    function someFunction( ) external pure returns ( uint256 ) {
        return 42;
    }
}


contract SignatureAttacksTest is Test {

    BondRoute bondroute;
    EIP1153Detector detector;
    MockERC1271Wallet wallet;
    MaliciousContract malicious_contract;
    
    address admin;
    address user;
    address attacker;
    uint256 user_private_key;
    uint256 attacker_private_key;

    function setUp( ) public
    {
        admin = makeAddr( "admin" );
        (user, user_private_key) = makeAddrAndKey( "user" );
        (attacker, attacker_private_key) = makeAddrAndKey( "attacker" );
        
        detector = new EIP1153Detector( );
        bondroute = new BondRoute( admin, address(detector) );
        wallet = new MockERC1271Wallet( user );
        malicious_contract = new MaliciousContract( );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              ECDSA SIGNATURE ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_signature_replay_across_bonds( ) public
    {
        // Create execution data
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("replay_test")
        });
        
        // Create bond
        vm.prank( user );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        // Create EIP-712 signature for bond execution
        bytes32 domain_separator = bondroute.DOMAIN_SEPARATOR( );
        bytes32 type_hash = keccak256("BondExecution(uint64 bond_id,TokenAmount[] fundings,CallEntry[] calls,bytes32 secret)CallEntry(address _contract,bytes _calldata,TokenAmount stake)TokenAmount(address token,uint256 amount)");
        
        bytes32 fundings_hash = keccak256( abi.encode( new bytes32[](0) ) );
        bytes32 calls_hash = keccak256( abi.encode( new bytes32[](0) ) );
        
        bytes32 struct_hash = keccak256( abi.encode(
            type_hash,
            uint64(1), // bond_id
            fundings_hash,
            calls_hash,
            execution_data.secret
        ));
        
        bytes32 typed_data_hash = keccak256( abi.encodePacked( "\x19\x01", domain_separator, struct_hash ) );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign( user_private_key, typed_data_hash );
        bytes memory signature = abi.encodePacked( r, s, v );
        
        // Execute bond with signature
        vm.roll( block.number + 1 );
        vm.prank( attacker );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, user, signature, false );
        
        // Try to replay same signature on different bond - should fail
        vm.prank( user );
        bytes21 proof2 = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof2 );
        
        vm.roll( block.number + 2 );
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 2) );
        bondroute.execute_bond_on_behalf_of_user( 2, execution_data, user, signature, false );
    }

    function test_attack_signature_replay_across_chains( ) public
    {
        // Create execution data
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("chain_replay")
        });
        
        // Get domain separator for current chain
        bytes32 domain_separator_chain1 = bondroute.DOMAIN_SEPARATOR( );
        
        // Switch to different chain
        vm.chainId( 137 ); // Polygon
        bytes32 domain_separator_chain2 = bondroute.DOMAIN_SEPARATOR( );
        
        // Domain separators should be different
        assertTrue( domain_separator_chain1 != domain_separator_chain2 );
        
        // Signature valid on chain 1 should be invalid on chain 2
        vm.chainId( 1 ); // Back to mainnet
        
        vm.prank( user );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        // Create signature for chain 1
        bytes32 type_hash = keccak256("BondExecution(uint64 bond_id,TokenAmount[] fundings,CallEntry[] calls,bytes32 secret)CallEntry(address _contract,bytes _calldata,TokenAmount stake)TokenAmount(address token,uint256 amount)");
        bytes32 struct_hash = keccak256( abi.encode(
            type_hash,
            uint64(1),
            keccak256( abi.encode( new bytes32[](0) ) ),
            keccak256( abi.encode( new bytes32[](0) ) ),
            execution_data.secret
        ));
        
        bytes32 typed_data_hash = keccak256( abi.encodePacked( "\x19\x01", domain_separator_chain1, struct_hash ) );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign( user_private_key, typed_data_hash );
        bytes memory signature = abi.encodePacked( r, s, v );
        
        // Switch to chain 2 and try to use same signature
        vm.chainId( 137 );
        
        vm.roll( block.number + 1 );
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, user, signature, false );
    }

    function test_attack_malformed_ecdsa_signature( ) public
    {
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("malformed_sig")
        });
        
        vm.prank( user );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        // Test various malformed signatures
        bytes memory empty_sig = "";
        bytes memory short_sig = hex"1234";
        bytes memory wrong_length_sig = hex"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"; // 33 bytes
        
        vm.startPrank( attacker );
        
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, user, empty_sig, false );
        
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, user, short_sig, false );
        
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, user, wrong_length_sig, false );
        
        vm.stopPrank( );
    }

    function test_attack_zero_signature_values( ) public
    {
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("zero_sig")
        });
        
        vm.prank( user );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        // Test signature with zero values
        bytes memory zero_sig = abi.encodePacked( bytes32(0), bytes32(0), uint8(0) );
        
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, user, zero_sig, false );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              EIP-1271 ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_eip1271_contract_without_interface( ) public
    {
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("no_interface")
        });
        
        vm.prank( address(malicious_contract) );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( address(malicious_contract), execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        bytes memory signature = abi.encode( address(malicious_contract) );
        
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, address(malicious_contract), signature, true );
    }

    function test_attack_eip1271_wrong_magic_value( ) public
    {
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("wrong_magic")
        });
        
        // Set wallet to return wrong magic value
        wallet.set_rejection_behavior( false, false, 0x12345678 );
        
        vm.prank( address(wallet) );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( address(wallet), execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        bytes memory signature = abi.encode( user );
        
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, address(wallet), signature, true );
    }

    function test_attack_eip1271_revert_during_validation( ) public
    {
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("revert_validation")
        });
        
        // Set wallet to revert during validation
        wallet.set_rejection_behavior( false, true, bytes4(0) );
        
        vm.prank( address(wallet) );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( address(wallet), execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        bytes memory signature = abi.encode( user );
        
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, address(wallet), signature, true );
    }

    function test_attack_eip1271_precompiled_contract( ) public
    {
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("precompiled")
        });
        
        address precompiled = address(0x01); // ecrecover
        
        vm.prank( precompiled );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( precompiled, execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        bytes memory signature = abi.encode( precompiled );
        
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, precompiled, signature, true );
    }

    function test_attack_eip1271_zero_address( ) public
    {
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](0);
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("zero_address")
        });
        
        vm.prank( address(0) );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( address(0), execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        bytes memory signature = abi.encode( address(0) );
        
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("InvalidSignature(uint256)", 1) );
        bondroute.execute_bond_on_behalf_of_user( 1, execution_data, address(0), signature, true );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              EIP-712 STRUCTURE ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_eip712_hash_collision( ) public view
    {
        // Try to create two different execution data that hash to same value
        TokenAmount[] memory fundings1 = new TokenAmount[](1);
        fundings1[0] = TokenAmount({ token: IERC20(address(0x01)), amount: 1000 });
        
        TokenAmount[] memory fundings2 = new TokenAmount[](2);
        fundings2[0] = TokenAmount({ token: IERC20(address(0x02)), amount: 500 });
        fundings2[1] = TokenAmount({ token: IERC20(address(0x03)), amount: 500 });
        
        ExecutionData memory execution_data1 = ExecutionData({
            fundings: fundings1,
            calls: new CallEntry[](0),
            secret: keccak256("collision1")
        });
        
        ExecutionData memory execution_data2 = ExecutionData({
            fundings: fundings2,
            calls: new CallEntry[](0),
            secret: keccak256("collision2")
        });
        
        // These should produce different commitment proofs
        bytes21 proof1 = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data1 );
        bytes21 proof2 = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data2 );
        
        assertTrue( proof1 != proof2 );
    }

    function test_attack_eip712_parameter_boundary_manipulation( ) public view
    {
        // Test that abi.encode is used (not abi.encodePacked) to prevent parameter boundary attacks
        
        // These could potentially have same packed encoding but different structured encoding
        TokenAmount[] memory fundings1 = new TokenAmount[](1);
        fundings1[0] = TokenAmount({ token: IERC20(address(0x1234567890123456789012345678901234567890)), amount: 0x1234 });
        
        TokenAmount[] memory fundings2 = new TokenAmount[](1);  
        fundings2[0] = TokenAmount({ token: IERC20(address(0x1234567890123456789012345678901234567800)), amount: 0x901234 });
        
        ExecutionData memory execution_data1 = ExecutionData({
            fundings: fundings1,
            calls: new CallEntry[](0),
            secret: bytes32(0)
        });
        
        ExecutionData memory execution_data2 = ExecutionData({
            fundings: fundings2,
            calls: new CallEntry[](0),
            secret: bytes32(0)
        });
        
        bytes21 proof1 = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data1 );
        bytes21 proof2 = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data2 );
        
        // Should be different due to proper structured encoding
        assertTrue( proof1 != proof2 );
    }

}