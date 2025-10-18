// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/BondRoute.sol";
import "@BondRoute/integrations/BondRouteProtected.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";
import "@BondRoute/user/IUser.sol";
import "@OpenZeppelin/token/ERC20/ERC20.sol";


contract FeeOnTransferToken is ERC20 {
    uint256 public fee_bps = 100; // 1% fee
    address public fee_recipient;
    
    constructor( ) ERC20( "FeeToken", "FEE" ) {
        fee_recipient = msg.sender;
        _mint( msg.sender, 1_000_000 * 10**18 );
    }
    
    function mint( address to, uint256 amount ) external {
        _mint( to, amount );
    }
    
    function set_fee( uint256 _fee_bps ) external {
        fee_bps = _fee_bps;
    }
    
    function _update( address from, address to, uint256 amount ) internal override {
        if( from == address(0) || to == address(0) ) {
            // No fees on mint/burn
            super._update( from, to, amount );
            return;
        }
        
        uint256 fee = (amount * fee_bps) / 10000;
        uint256 net_amount = amount - fee;
        
        super._update( from, to, net_amount );
        if( fee > 0 ) {
            super._update( from, fee_recipient, fee );
        }
    }
}


contract RevertOnTransferToken is ERC20 {
    bool public should_revert = false;
    address public blocked_recipient;
    
    constructor( ) ERC20( "RevertToken", "REVERT" ) {
        _mint( msg.sender, 1_000_000 * 10**18 );
    }
    
    function mint( address to, uint256 amount ) external {
        _mint( to, amount );
    }
    
    function set_revert( bool _should_revert ) external {
        should_revert = _should_revert;
    }
    
    function set_blocked_recipient( address _blocked ) external {
        blocked_recipient = _blocked;
    }
    
    function _update( address from, address to, uint256 amount ) internal override {
        if( (should_revert || to == blocked_recipient) && from != address(0) && to != address(0) ) {
            revert( "Transfer blocked" );
        }
        super._update( from, to, amount );
    }
}


contract HighDecimalToken is ERC20 {
    constructor( ) ERC20( "HighDecimal", "HIGH" ) {
        _mint( msg.sender, 1_000_000 * 10**24 ); // 24 decimals
    }
    
    function decimals( ) public pure override returns ( uint8 ) {
        return 24;
    }
    
    function mint( address to, uint256 amount ) external {
        _mint( to, amount );
    }
}


contract BondRouteProtectedMock is IBondRouteProtected {
    
    IBondRoute immutable actual_bondroute;
    
    constructor( IBondRoute _bondroute ) {
        actual_bondroute = _bondroute;
    }
    
    modifier onlyBondRoute( ) {
        if( msg.sender != address(actual_bondroute) ) {
            revert Unauthorized( msg.sender );
        }
        _;
    }
    
    function BondRoute_is_BondRouteProtected( ) external pure returns ( bytes32 ) {
        return BONDROUTEPROTECTED_MAGIC_SIGNATURE;
    }
    
    function BondRoute_entry_point( bytes calldata target_calldata_with_appended_context ) external onlyBondRoute {
        ( bool success, bytes memory delegatecall_output ) = address(this).delegatecall( target_calldata_with_appended_context );
        
        if( success == false ) {
            assembly ("memory-safe") {
                revert( add( delegatecall_output, 0x20 ), mload( delegatecall_output ) )
            }
        }
    }
    
    function BondRoute_get_execution_constraints( 
        bytes calldata, 
        IERC20, 
        TokenAmount[] memory 
    ) public pure virtual returns ( ExecutionConstraints memory ) {
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
}


contract TestVirtualEscrowContract is BondRouteProtectedMock {
    
    IERC20 public token_to_push;
    uint256 public amount_to_push;
    IERC20 public token_to_pull;
    uint256 public amount_to_pull;
    IERC20 public token_to_send;
    uint256 public amount_to_send;
    address public send_beneficiary;
    
    constructor( IBondRoute _bondroute ) BondRouteProtectedMock( _bondroute ) { }
    
    function set_push_behavior( IERC20 _token, uint256 _amount ) external {
        token_to_push = _token;
        amount_to_push = _amount;
    }
    
    function set_pull_behavior( IERC20 _token, uint256 _amount ) external {
        token_to_pull = _token;
        amount_to_pull = _amount;
    }
    
    function set_send_behavior( IERC20 _token, uint256 _amount, address _beneficiary ) external {
        token_to_send = _token;
        amount_to_send = _amount;
        send_beneficiary = _beneficiary;
    }
    
    function do_push( ) external onlyBondRoute {
        if( address(token_to_push) != address(0) && amount_to_push > 0 ) {
            token_to_push.approve( address(actual_bondroute), type(uint256).max );
            actual_bondroute.push_funds( token_to_push, amount_to_push );
        }
    }
    
    function do_pull( ) external onlyBondRoute {
        if( address(token_to_pull) != address(0) && amount_to_pull > 0 ) {
            actual_bondroute.pull_funds( token_to_pull, amount_to_pull );
        }
    }
    
    function do_send( ) external onlyBondRoute {
        if( address(token_to_send) != address(0) && amount_to_send > 0 && send_beneficiary != address(0) ) {
            actual_bondroute.send_funds( token_to_send, amount_to_send, send_beneficiary );
        }
    }
    
    function do_complex_operations( ) external onlyBondRoute {
        // Push some tokens
        if( address(token_to_push) != address(0) && amount_to_push > 0 ) {
            token_to_push.approve( address(actual_bondroute), type(uint256).max );
            actual_bondroute.push_funds( token_to_push, amount_to_push );
        }
        
        // Pull some tokens
        if( address(token_to_pull) != address(0) && amount_to_pull > 0 ) {
            actual_bondroute.pull_funds( token_to_pull, amount_to_pull );
        }
        
        // Send to beneficiary
        if( address(token_to_send) != address(0) && amount_to_send > 0 && send_beneficiary != address(0) ) {
            actual_bondroute.send_funds( token_to_send, amount_to_send, send_beneficiary );
        }
    }
}


contract VirtualEscrowAttacksTest is Test {

    BondRoute bondroute;
    EIP1153Detector detector;
    FeeOnTransferToken fee_token;
    RevertOnTransferToken revert_token;
    HighDecimalToken high_decimal_token;
    TestVirtualEscrowContract escrow_contract;
    
    address admin;
    address user;
    address attacker;
    address treasury;
    address beneficiary;

    function setUp( ) public
    {
        admin = makeAddr( "admin" );
        user = makeAddr( "user" );
        attacker = makeAddr( "attacker" );
        treasury = makeAddr( "treasury" );
        beneficiary = makeAddr( "beneficiary" );
        
        detector = new EIP1153Detector( );
        bondroute = new BondRoute( admin, address(detector) );
        
        fee_token = new FeeOnTransferToken( );
        revert_token = new RevertOnTransferToken( );
        high_decimal_token = new HighDecimalToken( );
        escrow_contract = new TestVirtualEscrowContract( IBondRoute(address(bondroute)) );
        
        vm.prank( admin );
        bondroute.set_protocol_treasury( treasury );
        
        // Mint tokens to users
        fee_token.mint( user, 10_000 * 10**18 );
        fee_token.mint( attacker, 10_000 * 10**18 );
        revert_token.mint( user, 10_000 * 10**18 );
        revert_token.mint( attacker, 10_000 * 10**18 );
        high_decimal_token.mint( user, 10_000 * 10**24 );
        high_decimal_token.mint( attacker, 10_000 * 10**24 );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              FEE CALCULATION ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_fee_rounding_exploit( ) public
    {
        // Test edge case where fee calculation rounds to zero
        uint256 tiny_amount = 9999; // Less than 10000 (fee divisor)
        uint256 expected_fee = tiny_amount / 10000; // Should round to 0
        
        escrow_contract.set_push_behavior( IERC20(address(fee_token)), tiny_amount );
        escrow_contract.set_pull_behavior( IERC20(address(fee_token)), tiny_amount );
        
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(fee_token)), amount: tiny_amount });
        
        CallEntry[] memory calls = new CallEntry[](2);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_push()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[1] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_pull()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("fee_rounding")
        });
        
        vm.startPrank( user );
        fee_token.approve( address(bondroute), tiny_amount );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        uint256 treasury_balance_before = fee_token.balanceOf( treasury );
        uint256 user_balance_before = fee_token.balanceOf( user );
        
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
        
        // Verify no fee was collected due to rounding
        assertEq( expected_fee, 0 );
        assertEq( fee_token.balanceOf( treasury ), treasury_balance_before );
        
        // No actual transfers occurred, so user balance should be unchanged
        // The virtual escrow system doesn't take funding if no actual pulls happen
        assertEq( fee_token.balanceOf( user ), user_balance_before );
    }

    function test_attack_fee_precision_loss( ) public
    {
        // Test with high decimal token to check for precision issues
        uint256 amount = 10001 * 10**18; // Just above fee threshold
        uint256 expected_bondroute_fee = amount / 10000; // 0.01%
        
        escrow_contract.set_push_behavior( IERC20(address(high_decimal_token)), amount );
        escrow_contract.set_pull_behavior( IERC20(address(high_decimal_token)), amount );
        
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(high_decimal_token)), amount: amount });
        
        CallEntry[] memory calls = new CallEntry[](2);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_push()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[1] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_pull()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("precision_test")
        });
        
        // Give escrow contract tokens so it can push to virtual escrow
        high_decimal_token.mint( address(escrow_contract), amount );
        
        vm.startPrank( user );
        high_decimal_token.approve( address(bondroute), amount );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        uint256 treasury_balance_before = high_decimal_token.balanceOf( treasury );
        
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
        
        // Verify correct fee was collected despite high decimals
        assertEq( high_decimal_token.balanceOf( treasury ), treasury_balance_before + expected_bondroute_fee );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              LIFO ORDERING ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_lifo_manipulation( ) public
    {
        // User tries to manipulate LIFO ordering by creating specific funding pattern
        uint256 amount1 = 1000 * 10**18;
        uint256 amount2 = 2000 * 10**18;
        uint256 pull_amount = 1500 * 10**18;
        
        // Contract 1 pushes first, Contract 2 pushes second, Contract 3 pulls
        TestVirtualEscrowContract contract1 = new TestVirtualEscrowContract( IBondRoute(address(bondroute)) );
        TestVirtualEscrowContract contract2 = new TestVirtualEscrowContract( IBondRoute(address(bondroute)) );
        TestVirtualEscrowContract contract3 = new TestVirtualEscrowContract( IBondRoute(address(bondroute)) );
        
        contract1.set_push_behavior( IERC20(address(fee_token)), amount1 );
        contract2.set_push_behavior( IERC20(address(fee_token)), amount2 );
        contract3.set_pull_behavior( IERC20(address(fee_token)), pull_amount );
        
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(fee_token)), amount: amount1 + amount2 });
        
        CallEntry[] memory calls = new CallEntry[](3);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(contract1)),
            _calldata: abi.encodeWithSignature("do_push()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[1] = CallEntry({
            _contract: IBondRouteProtected(address(contract2)),
            _calldata: abi.encodeWithSignature("do_push()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[2] = CallEntry({
            _contract: IBondRouteProtected(address(contract3)),
            _calldata: abi.encodeWithSignature("do_pull()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("lifo_test")
        });
        
        // Give contracts tokens so they can push to virtual escrow
        fee_token.mint( address(contract1), amount1 );
        fee_token.mint( address(contract2), amount2 );
        
        vm.startPrank( user );
        fee_token.approve( address(bondroute), amount1 + amount2 );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        uint256 contract3_balance_before = fee_token.balanceOf( address(contract3) );
        
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
        
        // LIFO should pull from contract2 first (last pushed), then contract1
        // Contract3 should receive pull_amount minus BondRoute fee
        uint256 expected_bondroute_fee = pull_amount / 10000;
        uint256 fee_token_fee_on_pull = ((pull_amount - expected_bondroute_fee) * 100) / 10000;
        uint256 expected_contract3_balance = pull_amount - expected_bondroute_fee - fee_token_fee_on_pull;
        
        assertEq( fee_token.balanceOf( address(contract3) ), contract3_balance_before + expected_contract3_balance );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              TRANSFER FAILURE ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_transfer_failure_during_pull( ) public
    {
        uint256 amount = 1000 * 10**18;
        
        escrow_contract.set_push_behavior( IERC20(address(revert_token)), amount );
        escrow_contract.set_pull_behavior( IERC20(address(revert_token)), amount );
        
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(revert_token)), amount: amount });
        
        CallEntry[] memory calls = new CallEntry[](2);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_push()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[1] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_pull()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("transfer_fail")
        });
        
        vm.startPrank( user );
        revert_token.approve( address(bondroute), amount );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        // Set token to revert on transfers
        revert_token.set_revert( true );
        
        vm.roll( block.number + 1 );
        
        // Should fail with TokenTransferFailed due to transfer failure (fee collection fails)
        vm.expectRevert( abi.encodeWithSignature("TokenTransferFailed(address,address,address,uint256)", revert_token, user, treasury, amount / 10000) );
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
    }

    function test_attack_selective_transfer_blocking( ) public
    {
        uint256 amount = 1000 * 10**18;
        
        escrow_contract.set_push_behavior( IERC20(address(revert_token)), amount );
        escrow_contract.set_send_behavior( IERC20(address(revert_token)), amount, beneficiary );
        
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(revert_token)), amount: amount });
        
        CallEntry[] memory calls = new CallEntry[](2);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_push()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[1] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_send()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("selective_block")
        });
        
        vm.startPrank( user );
        revert_token.approve( address(bondroute), amount );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        // Block transfers to specific beneficiary
        revert_token.set_blocked_recipient( beneficiary );
        
        vm.roll( block.number + 1 );
        
        // Give the escrow contract some tokens so it can push to virtual escrow
        revert_token.mint( address(escrow_contract), amount );
        
        // Should emit BondExecutionCallFailed due to selective blocking (beneficiary blocked)  
        bytes memory expected_error = abi.encodeWithSignature("TokenTransferFailed(address,address,address,uint256)", revert_token, address(escrow_contract), beneficiary, amount - (amount / 10000));
        vm.expectEmit(true, true, false, true);
        emit BondExecutionCallFailed(1, 1, expected_error); // Second call (index 1) fails
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              STAKE-TO-FUNDING OPTIMIZATION ATTACKS
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_stake_funding_optimization_overflow( ) public
    {
        // Test edge case where stake amount + funding amount could overflow
        uint256 stake_amount = type(uint256).max / 2;
        uint256 funding_amount = type(uint256).max / 2 + 1; // Would overflow if added
        
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: IERC20(address(fee_token)), amount: stake_amount });
        
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(fee_token)), amount: funding_amount });
        
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_pull()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("overflow_test")
        });
        
        // This should fail during bond creation due to insufficient balance
        vm.startPrank( user );
        fee_token.approve( address(bondroute), stake_amount );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        
        // BondRoute wraps the underlying arithmetic overflow in TokenTransferFailed
        vm.expectRevert( abi.encodeWithSignature("TokenTransferFailed(address,address,address,uint256)", fee_token, user, address(bondroute), stake_amount) );
        bondroute.create_bond( proof, stakes, 0 );
        
        vm.stopPrank( );
    }

    function test_attack_stake_funding_mismatch_exploitation( ) public
    {
        // Attacker tries to game the system by staking less than funding requirement
        uint256 stake_amount = 500 * 10**18;
        uint256 funding_amount = 1000 * 10**18;
        
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: IERC20(address(fee_token)), amount: stake_amount });
        
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(fee_token)), amount: funding_amount });
        
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(escrow_contract)),
            _calldata: abi.encodeWithSignature("do_pull()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("mismatch_test")
        });
        
        vm.startPrank( user );
        fee_token.approve( address(bondroute), funding_amount ); // Approve full funding amount
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof, stakes, 0 );
        
        vm.roll( block.number + 1 );
        
        // Should work - user pays the difference between funding and stake
        // User has 9500 tokens after staking 500 (with 1% fee)
        uint256 user_balance_before = fee_token.balanceOf( user );
        assertEq( user_balance_before, 9500 * 10**18 );
        
        bondroute.execute_bond( 1, execution_data );
        
        // User gets back stake (495 actual staked - 1% fee on transfer back = 490.05)
        // Final balance should be 9990.05 tokens (9500 + 490.05)
        uint256 user_balance_after = fee_token.balanceOf( user );
        assertEq( user_balance_after, 9990050000000000000000 );
        
        vm.stopPrank( );
    }

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              PUSH FUNDS OVERFLOW ATTACK
    // ═══════════════════════════════════════════════════════════════════════════════

    function test_attack_push_funds_overflow_protection( ) public
    {
        // Attacker tries to overflow uint256 escrow balance within single execution
        
        uint256 large_amount = type(uint256).max / 2 + 1; // Over half of max uint256
        
        // Create malicious contract that pushes additional funds
        TestVirtualEscrowContract malicious_contract = new TestVirtualEscrowContract( IBondRoute(address(bondroute)) );
        fee_token.mint( address(malicious_contract), large_amount );
        malicious_contract.set_push_behavior( IERC20(address(fee_token)), large_amount );
        
        // Fundings array pushes large_amount first, then contract call tries to push again
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: IERC20(address(fee_token)), amount: large_amount });
        
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(malicious_contract)),
            _calldata: abi.encodeWithSignature("do_push()"), // This push causes overflow
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("overflow_attack")
        });
        
        vm.startPrank( user );
        fee_token.approve( address(bondroute), large_amount );
        
        bytes21 proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( proof );
        
        vm.roll( block.number + 1 );
        
        // Attack fails: contract push overflows and emits BondExecutionCallFailed with PushedFundsOverflow
        bytes memory expected_error = abi.encodeWithSignature("PushedFundsOverflow(address,address,address,uint256)", fee_token, address(malicious_contract), address(malicious_contract), large_amount);
        vm.expectEmit(true, true, false, true);
        emit BondExecutionCallFailed(1, 0, expected_error);
        bondroute.execute_bond( 1, execution_data );
        
        vm.stopPrank( );
    }
}