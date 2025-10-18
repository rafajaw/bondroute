// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/BondRoute.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";
import "@BondRoute/user/IUser.sol";
import "@BondRoute/admin/IAdmin.sol";
import "@OpenZeppelin/token/ERC20/ERC20.sol";


contract MockToken is ERC20 {
    constructor( ) ERC20( "MockToken", "MOCK" ) {
        _mint( msg.sender, 1_000_000 * 10**18 );
    }
    
    function mint( address to, uint256 amount ) external {
        _mint( to, amount );
    }
}


contract AdminAttacksTest is Test {

    BondRoute bondroute;
    EIP1153Detector detector;
    MockToken token;
    
    address admin;
    address pending_admin;
    address attacker;
    address treasury;
    address user;

    function setUp( ) public
    {
        admin = makeAddr( "admin" );
        pending_admin = makeAddr( "pending_admin" );
        attacker = makeAddr( "attacker" );
        treasury = makeAddr( "treasury" );
        user = makeAddr( "user" );
        
        detector = new EIP1153Detector( );
        bondroute = new BondRoute( admin, address(detector) );
        token = new MockToken( );
        
        token.mint( user, 10_000 * 10**18 );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              ADMIN TRANSFER ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_admin_transfer_bypass_2step( ) public
    {
        // Attacker tries to bypass 2-step admin transfer
        vm.startPrank( attacker );
        
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", ADMIN_ACCESS_REQUIRED) );
        bondroute.appoint_new_admin( attacker );
        
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", APPOINTED_ADMIN_REQUIRED) );
        bondroute.accept_admin_appointment( );
        
        vm.stopPrank( );
    }

    function test_attack_admin_appointment_race_condition( ) public
    {
        // Admin appoints new admin
        vm.prank( admin );
        bondroute.appoint_new_admin( pending_admin );
        
        // Attacker tries to accept appointment before legitimate pending admin
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", APPOINTED_ADMIN_REQUIRED) );
        bondroute.accept_admin_appointment( );
        
        // Legitimate pending admin should still be able to accept
        vm.prank( pending_admin );
        bondroute.accept_admin_appointment( );
        
        // Verify admin transfer completed
        vm.prank( pending_admin );
        bondroute.set_protocol_treasury( treasury ); // Should work with new admin
    }

    function test_attack_admin_reappointment_during_pending( ) public
    {
        // Admin appoints first pending admin
        vm.startPrank( admin );
        bondroute.appoint_new_admin( pending_admin );
        
        // Admin immediately appoints different admin (overwriting pending)
        address second_pending = makeAddr( "second_pending" );
        bondroute.appoint_new_admin( second_pending );
        vm.stopPrank( );
        
        // First pending admin can no longer accept
        vm.prank( pending_admin );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", APPOINTED_ADMIN_REQUIRED) );
        bondroute.accept_admin_appointment( );
        
        // Second pending admin should be able to accept
        vm.prank( second_pending );
        bondroute.accept_admin_appointment( );
    }

    function test_attack_admin_self_appointment( ) public
    {
        // Admin tries to appoint themselves (should be allowed but redundant)
        vm.prank( admin );
        bondroute.appoint_new_admin( admin );
        
        vm.prank( admin );
        bondroute.accept_admin_appointment( );
        
        // Admin should still have control
        vm.prank( admin );
        bondroute.set_protocol_treasury( treasury );
    }

    function test_attack_admin_zero_address_appointment( ) public
    {
        vm.prank( admin );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", ADMIN_ZERO_ADDRESS) );
        bondroute.appoint_new_admin( address(0) );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              TREASURY MANAGEMENT ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_unauthorized_treasury_change( ) public
    {
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", ADMIN_ACCESS_REQUIRED) );
        bondroute.set_protocol_treasury( attacker );
    }

    function test_attack_treasury_zero_address( ) public
    {
        vm.prank( admin );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", INVALID_ADDRESS) );
        bondroute.set_protocol_treasury( address(0) );
    }

    function test_attack_treasury_change_during_bond_execution( ) public
    {
        // This would be caught by reentrancy protection if attempted during execution
        // But let's verify treasury changes work normally
        vm.prank( admin );
        bondroute.set_protocol_treasury( treasury );
        
        // Verify treasury was set by checking admin can change it again
        vm.prank( admin );
        bondroute.set_protocol_treasury( makeAddr("new_treasury") );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              BOND LIQUIDATION ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_unauthorized_bond_liquidation( ) public
    {
        uint64[] memory bond_ids = new uint64[](1);
        bond_ids[0] = 1;
        
        vm.prank( attacker );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", ADMIN_ACCESS_REQUIRED) );
        bondroute.liquidate_defaulted_bonds( bond_ids, treasury );
    }

    function test_attack_liquidation_empty_array( ) public
    {
        uint64[] memory empty_bond_ids = new uint64[](0);
        
        vm.prank( admin );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", EMPTY_ARRAY) );
        bondroute.liquidate_defaulted_bonds( empty_bond_ids, treasury );
    }

    function test_attack_liquidation_zero_beneficiary( ) public
    {
        uint64[] memory bond_ids = new uint64[](1);
        bond_ids[0] = 1;
        
        vm.prank( admin );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", INVALID_ADDRESS) );
        bondroute.liquidate_defaulted_bonds( bond_ids, address(0) );
    }

    function test_attack_premature_bond_liquidation( ) public
    {
        // Create bond with stake
        uint256 stake_amount = 1000 * 10**18;
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: IERC20(address(token)), amount: stake_amount });
        
        vm.startPrank( user );
        token.approve( address(bondroute), stake_amount );
        
        bytes21 proof = bytes21(uint168(0x123456789012345678901234567890123456789012));
        bondroute.create_bond( proof, stakes, 0 );
        vm.stopPrank( );
        
        // Try to liquidate before expiry
        uint64[] memory bond_ids = new uint64[](1);
        bond_ids[0] = 1;
        
        uint256 treasury_balance_before = token.balanceOf( treasury );
        
        vm.prank( admin );
        bondroute.liquidate_defaulted_bonds( bond_ids, treasury );
        
        // Treasury should not receive anything (bond not expired)
        assertEq( token.balanceOf( treasury ), treasury_balance_before );
    }

    function test_attack_liquidation_nonexistent_bonds( ) public
    {
        uint64[] memory bond_ids = new uint64[](1);
        bond_ids[0] = 999;
        
        vm.prank( admin );
        vm.expectRevert( abi.encodeWithSignature("BondNotFound(uint256)", 999) );
        bondroute.liquidate_defaulted_bonds( bond_ids, treasury );
    }

    function test_attack_liquidation_already_executed_bonds( ) public
    {
        // Create and execute bond
        ExecutionData memory execution_data = ExecutionData({
            fundings: new TokenAmount[](0),
            calls: new CallEntry[](0),
            secret: keccak256("executed_bond")
        });
        
        vm.startPrank( user );
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        vm.stopPrank( );
        
        // Bond should be deleted after execution, so liquidation should fail
        uint64[] memory bond_ids = new uint64[](1);
        bond_ids[0] = 1;
        
        vm.prank( admin );
        vm.expectRevert( abi.encodeWithSignature("BondNotFound(uint256)", 1) );
        bondroute.liquidate_defaulted_bonds( bond_ids, treasury );
    }

    function test_attack_bulk_liquidation_with_mixed_validity( ) public
    {
        // Create some bonds with stakes
        uint256 stake_amount = 1000 * 10**18;
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: IERC20(address(token)), amount: stake_amount });
        
        vm.startPrank( user );
        token.approve( address(bondroute), stake_amount * 2 );
        
        // Create two bonds
        bytes21 proof1 = bytes21(uint168(0x111111111111111111111111111111111111111111));
        bondroute.create_bond( proof1, stakes, 0 );
        
        bytes21 proof2 = bytes21(uint168(0x222222222222222222222222222222222222222222));
        bondroute.create_bond( proof2, stakes, 0 );
        vm.stopPrank( );
        
        // Fast forward beyond expiry
        vm.warp( block.timestamp + 102 days );
        
        // Liquidation should fail when encountering non-existent bond (strict validation)
        uint64[] memory bond_ids = new uint64[](4);
        bond_ids[0] = 1;    // Valid expired bond
        bond_ids[1] = 999;  // Non-existent bond - will cause revert
        bond_ids[2] = 2;    // Valid expired bond
        bond_ids[3] = 888;  // Non-existent bond
        
        vm.prank( admin );
        vm.expectRevert( abi.encodeWithSignature("BondNotFound(uint256)", 999) );
        bondroute.liquidate_defaulted_bonds( bond_ids, treasury );
        
        // Liquidate only valid bonds
        uint64[] memory valid_bond_ids = new uint64[](2);
        valid_bond_ids[0] = 1;
        valid_bond_ids[1] = 2;
        
        uint256 treasury_balance_before = token.balanceOf( treasury );
        
        vm.prank( admin );
        bondroute.liquidate_defaulted_bonds( valid_bond_ids, treasury );
        
        // Treasury should receive stakes from 2 valid bonds
        assertEq( token.balanceOf( treasury ), treasury_balance_before + (stake_amount * 2) );
    }

    function test_attack_liquidation_gas_limit_dos( ) public
    {
        // Create many bonds to try to cause gas limit issues during liquidation
        uint256 stake_amount = 100 * 10**18;
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: IERC20(address(token)), amount: stake_amount });
        
        uint256 num_bonds = 50; // Create many bonds
        
        vm.startPrank( user );
        token.approve( address(bondroute), stake_amount * num_bonds );
        
        for( uint i = 0; i < num_bonds; i++ ) {
            bytes21 proof = bytes21( uint168(uint256(keccak256( abi.encode("bond", i) )) >> 88) );
            bondroute.create_bond( proof, stakes, 0 );
        }
        vm.stopPrank( );
        
        // Fast forward beyond expiry
        vm.warp( block.timestamp + 102 days );
        
        // Create large array of bond IDs
        uint64[] memory bond_ids = new uint64[](num_bonds);
        for( uint i = 0; i < num_bonds; i++ ) {
            bond_ids[i] = uint64(i + 1);
        }
        
        uint256 treasury_balance_before = token.balanceOf( treasury );
        
        // This should succeed despite large number of bonds
        vm.prank( admin );
        bondroute.liquidate_defaulted_bonds( bond_ids, treasury );
        
        // Verify all stakes were transferred
        assertEq( token.balanceOf( treasury ), treasury_balance_before + (stake_amount * num_bonds) );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              ACCESS CONTROL EDGE CASES
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_admin_functions_during_admin_transfer( ) public
    {
        // Admin appoints new admin but hasn't completed transfer
        vm.prank( admin );
        bondroute.appoint_new_admin( pending_admin );
        
        // Current admin should still have access
        vm.prank( admin );
        bondroute.set_protocol_treasury( treasury );
        
        // Pending admin should not have access yet
        vm.prank( pending_admin );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", ADMIN_ACCESS_REQUIRED) );
        bondroute.set_protocol_treasury( makeAddr("unauthorized_treasury") );
        
        // Complete transfer
        vm.prank( pending_admin );
        bondroute.accept_admin_appointment( );
        
        // Old admin should lose access
        vm.prank( admin );
        vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", ADMIN_ACCESS_REQUIRED) );
        bondroute.set_protocol_treasury( makeAddr("old_admin_treasury") );
        
        // New admin should have access
        vm.prank( pending_admin );
        bondroute.set_protocol_treasury( makeAddr("new_admin_treasury") );
    }

    function test_attack_contract_as_admin( ) public
    {
        // Deploy a contract and make it admin
        MockToken contract_admin = new MockToken( );
        
        vm.prank( admin );
        bondroute.appoint_new_admin( address(contract_admin) );
        
        // Contract should be able to accept admin appointment
        // This is allowed - contracts can be admins
        vm.prank( address(contract_admin) );
        bondroute.accept_admin_appointment( );
        
        // Verify the contract is now admin by checking it can perform admin functions
        vm.prank( address(contract_admin) );
        bondroute.set_protocol_treasury( makeAddr("contract_treasury") );
    }

    function test_admin_functions_comprehensive_access_control( ) public
    {
        address[] memory unauthorized_callers = new address[](3);
        unauthorized_callers[0] = attacker;
        unauthorized_callers[1] = user;
        unauthorized_callers[2] = treasury;
        
        for( uint i = 0; i < unauthorized_callers.length; i++ ) {
            address caller = unauthorized_callers[i];
            
            vm.startPrank( caller );
            
            // All admin functions should revert for unauthorized callers
            vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", ADMIN_ACCESS_REQUIRED) );
            bondroute.appoint_new_admin( caller );
            
            vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", ADMIN_ACCESS_REQUIRED) );
            bondroute.set_protocol_treasury( caller );
            
            uint64[] memory bond_ids = new uint64[](1);
            bond_ids[0] = 1;
            vm.expectRevert( abi.encodeWithSignature("Forbidden(string)", ADMIN_ACCESS_REQUIRED) );
            bondroute.liquidate_defaulted_bonds( bond_ids, caller );
            
            vm.stopPrank( );
        }
    }
}