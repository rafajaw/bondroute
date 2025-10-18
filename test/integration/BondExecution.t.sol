// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/BondRoute.sol";
import "@BondRoute/integrations/BondRouteProtected.sol";
import "@BondRoute/utils/eip1153/EIP1153Detector.sol";
import "@BondRoute/user/IUser.sol";
import "@OpenZeppelin/token/ERC20/ERC20.sol";


contract MockToken is ERC20 {
    constructor( string memory name, string memory symbol ) ERC20( name, symbol ) {
        _mint( msg.sender, 1_000_000 * 10**18 );
    }
    
    function mint( address to, uint256 amount ) external {
        _mint( to, amount );
    }
}

contract MockContract is IBondRouteProtected {
    
    IBondRoute immutable bondroute_instance;
    bool public should_pull_funds;
    IERC20 public token_to_pull;
    uint256 public amount_to_pull;
    
    constructor( IBondRoute _bondroute ) {
        bondroute_instance = _bondroute;
    }
    
    modifier onlyBondRoute( ) {
        if( msg.sender != address(bondroute_instance) ) revert Unauthorized( msg.sender );
        _;
    }
    
    function set_pull_behavior( bool _should_pull, IERC20 _token, uint256 _amount ) external {
        should_pull_funds = _should_pull;
        token_to_pull = _token;
        amount_to_pull = _amount;
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
        bytes calldata /* target_calldata */, 
        IERC20 /* preferred_stake_token */, 
        TokenAmount[] memory /* preferred_fundings */ 
    ) public pure override returns ( ExecutionConstraints memory execution_constraints ) {
        // Allow execution after 1 block delay
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
    
    function _extract_context_from_calldata( ) private pure returns ( BondRouteContext memory context ) {
        if( msg.data.length < 96 ) revert( "Invalid context data" );
        
        bytes calldata encoded_context = msg.data[ msg.data.length - 96 : ];
        
        uint256 packed_user_and_commit_info;
        address staked_token;
        uint256 staked_amount;
        
        assembly {
            packed_user_and_commit_info := calldataload( add( encoded_context.offset, 0x00 ) )
            staked_token := calldataload( add( encoded_context.offset, 0x20 ) )
            staked_amount := calldataload( add( encoded_context.offset, 0x40 ) )
        }

        context.user = address(uint160(packed_user_and_commit_info >> 80));
        context.commit_time = uint40(( packed_user_and_commit_info >> 40 ) & 0xffffffffff);
        context.commit_block = uint40(packed_user_and_commit_info & 0xffffffffff);

        context.stake.token = IERC20(staked_token);
        context.stake.amount = staked_amount;
    }
    
    function do_work( ) external onlyBondRoute {
        BondRouteContext memory ctx = _extract_context_from_calldata( );
        ctx.fundings = bondroute_instance.get_available_funds( );
        
        if( should_pull_funds && address(token_to_pull) != address(0) ) {
            bondroute_instance.pull_funds( token_to_pull, amount_to_pull );
        }
    }
    
    function do_work_without_funds( ) external view onlyBondRoute {
        // BondRouteContext memory ctx = _extract_context_from_calldata( );
        // Just execute without pulling funds
    }
}


contract BondExecutionTest is Test {

    BondRoute bondroute;
    EIP1153Detector detector;
    MockToken usdc;
    MockToken weth;
    MockContract contract1;
    MockContract contract2;
    
    address admin;
    address user;
    address treasury;

    function setUp( ) public
    {
        admin = makeAddr( "admin" );
        user = makeAddr( "user" );
        treasury = makeAddr( "treasury" );
        
        detector = new EIP1153Detector( );
        bondroute = new BondRoute( admin, address(detector) );
        
        usdc = new MockToken( "USDC", "USDC" );
        weth = new MockToken( "WETH", "WETH" );
        
        contract1 = new MockContract( IBondRoute(address(bondroute)) );
        contract2 = new MockContract( IBondRoute(address(bondroute)) );
        
        // Set treasury
        vm.prank( admin );
        bondroute.set_protocol_treasury( treasury );
        
        // Mint tokens to user
        usdc.mint( user, 10_000 * 10**6 ); // 10k USDC
        weth.mint( user, 100 * 10**18 );   // 100 WETH
    }

    function test_bond_execution_one_call_no_stakes( ) public
    {
        // Setup: Contract doesn't pull funds
        contract1.set_pull_behavior( false, IERC20(address(0)), 0 );
        
        // Record initial balances
        uint256 user_usdc_before = usdc.balanceOf( user );
        uint256 treasury_usdc_before = usdc.balanceOf( treasury );
        uint256 contract1_usdc_before = usdc.balanceOf( address(contract1) );
        
        // Create execution data
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(contract1)),
            _calldata: abi.encodeWithSignature("do_work_without_funds()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret1")
        });
        
        // Create bond
        bytes21 commitment_proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        
        vm.prank( user );
        bondroute.create_bond( commitment_proof );
        
        // Execute bond
        vm.roll( block.number + 1 ); // Move to next block
        vm.prank( user );
        bondroute.execute_bond( 1, execution_data );
        
        // Check balances - should be unchanged since no funds moved
        assertEq( usdc.balanceOf( user ), user_usdc_before );
        assertEq( usdc.balanceOf( treasury ), treasury_usdc_before );
        assertEq( usdc.balanceOf( address(contract1) ), contract1_usdc_before );
    }

    function test_bond_execution_two_calls_no_stakes( ) public
    {
        // Setup: Neither contract pulls funds
        contract1.set_pull_behavior( false, IERC20(address(0)), 0 );
        contract2.set_pull_behavior( false, IERC20(address(0)), 0 );
        
        // Record initial balances
        uint256 user_usdc_before = usdc.balanceOf( user );
        uint256 treasury_usdc_before = usdc.balanceOf( treasury );
        
        // Create execution data
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](2);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(contract1)),
            _calldata: abi.encodeWithSignature("do_work_without_funds()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[1] = CallEntry({
            _contract: IBondRouteProtected(address(contract2)),
            _calldata: abi.encodeWithSignature("do_work_without_funds()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret2")
        });
        
        // Create and execute bond
        bytes21 commitment_proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        
        vm.prank( user );
        bondroute.create_bond( commitment_proof );
        
        vm.roll( block.number + 1 );
        vm.prank( user );
        bondroute.execute_bond( 1, execution_data );
        
        // Check balances - should be unchanged
        assertEq( usdc.balanceOf( user ), user_usdc_before );
        assertEq( usdc.balanceOf( treasury ), treasury_usdc_before );
    }

    function test_bond_execution_one_stake_one_call( ) public
    {
        uint256 stake_amount = 1000 * 10**6; // 1000 USDC
        
        // Setup: Contract doesn't pull funds
        contract1.set_pull_behavior( false, IERC20(address(0)), 0 );
        
        // Record initial balances
        uint256 user_usdc_before = usdc.balanceOf( user );
        uint256 treasury_usdc_before = usdc.balanceOf( treasury );
        uint256 bondroute_usdc_before = usdc.balanceOf( address(bondroute) );
        
        // Create execution data
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(contract1)),
            _calldata: abi.encodeWithSignature("do_work_without_funds()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret3")
        });
        
        // Create stakes
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: usdc, amount: stake_amount });
        
        // Approve and create bond with stake
        vm.startPrank( user );
        usdc.approve( address(bondroute), stake_amount );
        
        bytes21 commitment_proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( commitment_proof, stakes, 0 );
        
        // Check stake was transferred
        assertEq( usdc.balanceOf( user ), user_usdc_before - stake_amount );
        assertEq( usdc.balanceOf( address(bondroute) ), bondroute_usdc_before + stake_amount );
        
        // Execute bond
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        vm.stopPrank( );
        
        // Check stake was returned to user
        assertEq( usdc.balanceOf( user ), user_usdc_before );
        assertEq( usdc.balanceOf( address(bondroute) ), bondroute_usdc_before );
        assertEq( usdc.balanceOf( treasury ), treasury_usdc_before );
    }

    function test_bond_execution_one_stake_two_calls( ) public
    {
        uint256 stake_amount = 1000 * 10**6;
        
        // Setup: Neither contract pulls funds
        contract1.set_pull_behavior( false, IERC20(address(0)), 0 );
        contract2.set_pull_behavior( false, IERC20(address(0)), 0 );
        
        // Record initial balances
        uint256 user_usdc_before = usdc.balanceOf( user );
        
        // Create execution data
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](2);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(contract1)),
            _calldata: abi.encodeWithSignature("do_work_without_funds()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[1] = CallEntry({
            _contract: IBondRouteProtected(address(contract2)),
            _calldata: abi.encodeWithSignature("do_work_without_funds()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret4")
        });
        
        // Create and execute with stake
        TokenAmount[] memory stakes = new TokenAmount[](1);
        stakes[0] = TokenAmount({ token: usdc, amount: stake_amount });
        
        vm.startPrank( user );
        usdc.approve( address(bondroute), stake_amount );
        
        bytes21 commitment_proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( commitment_proof, stakes, 0 );
        
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        vm.stopPrank( );
        
        // Check stake was returned
        assertEq( usdc.balanceOf( user ), user_usdc_before );
    }

    function test_bond_execution_two_stakes_one_call( ) public
    {
        uint256 usdc_stake = 1000 * 10**6;
        uint256 weth_stake = 5 * 10**18;
        
        contract1.set_pull_behavior( false, IERC20(address(0)), 0 );
        
        uint256 user_usdc_before = usdc.balanceOf( user );
        uint256 user_weth_before = weth.balanceOf( user );
        
        // Create execution data
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(contract1)),
            _calldata: abi.encodeWithSignature("do_work_without_funds()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret5")
        });
        
        // Create stakes for both tokens
        TokenAmount[] memory stakes = new TokenAmount[](2);
        stakes[0] = TokenAmount({ token: usdc, amount: usdc_stake });
        stakes[1] = TokenAmount({ token: weth, amount: weth_stake });
        
        vm.startPrank( user );
        usdc.approve( address(bondroute), usdc_stake );
        weth.approve( address(bondroute), weth_stake );
        
        bytes21 commitment_proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( commitment_proof, stakes, 0 );
        
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        vm.stopPrank( );
        
        // Check both stakes were returned
        assertEq( usdc.balanceOf( user ), user_usdc_before );
        assertEq( weth.balanceOf( user ), user_weth_before );
    }

    function test_bond_execution_two_stakes_two_calls( ) public
    {
        uint256 usdc_stake = 1000 * 10**6;
        uint256 weth_stake = 5 * 10**18;
        
        contract1.set_pull_behavior( false, IERC20(address(0)), 0 );
        contract2.set_pull_behavior( false, IERC20(address(0)), 0 );
        
        uint256 user_usdc_before = usdc.balanceOf( user );
        uint256 user_weth_before = weth.balanceOf( user );
        
        // Create execution data
        TokenAmount[] memory fundings = new TokenAmount[](0);
        CallEntry[] memory calls = new CallEntry[](2);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(contract1)),
            _calldata: abi.encodeWithSignature("do_work_without_funds()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[1] = CallEntry({
            _contract: IBondRouteProtected(address(contract2)),
            _calldata: abi.encodeWithSignature("do_work_without_funds()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret6")
        });
        
        TokenAmount[] memory stakes = new TokenAmount[](2);
        stakes[0] = TokenAmount({ token: usdc, amount: usdc_stake });
        stakes[1] = TokenAmount({ token: weth, amount: weth_stake });
        
        vm.startPrank( user );
        usdc.approve( address(bondroute), usdc_stake );
        weth.approve( address(bondroute), weth_stake );
        
        bytes21 commitment_proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( commitment_proof, stakes, 0 );
        
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        vm.stopPrank( );
        
        // Check both stakes were returned
        assertEq( usdc.balanceOf( user ), user_usdc_before );
        assertEq( weth.balanceOf( user ), user_weth_before );
    }

    function test_bond_execution_with_funding_and_pull( ) public
    {
        uint256 funding_amount = 2000 * 10**6; // 2000 USDC
        uint256 pull_amount = 1000 * 10**6;    // 1000 USDC
        uint256 expected_fee = pull_amount / 10000; // 0.01% fee
        
        // Setup: Contract1 pulls funds
        contract1.set_pull_behavior( true, usdc, pull_amount );
        
        uint256 user_usdc_before = usdc.balanceOf( user );
        uint256 treasury_usdc_before = usdc.balanceOf( treasury );
        uint256 contract1_usdc_before = usdc.balanceOf( address(contract1) );
        
        // Create execution data with funding
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: usdc, amount: funding_amount });
        
        CallEntry[] memory calls = new CallEntry[](1);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(contract1)),
            _calldata: abi.encodeWithSignature("do_work()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret_pull")
        });
        
        vm.startPrank( user );
        usdc.approve( address(bondroute), funding_amount );
        
        bytes21 commitment_proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( commitment_proof );
        
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        vm.stopPrank( );
        
        // Check balances after execution
        uint256 user_usdc_after = usdc.balanceOf( user );
        uint256 treasury_usdc_after = usdc.balanceOf( treasury );
        uint256 contract1_usdc_after = usdc.balanceOf( address(contract1) );
        
        console.log("User before:", user_usdc_before);
        console.log("User after:", user_usdc_after);
        console.log("Treasury before:", treasury_usdc_before);
        console.log("Treasury after:", treasury_usdc_after);
        console.log("Contract1 before:", contract1_usdc_before);
        console.log("Contract1 after:", contract1_usdc_after);
        console.log("Expected fee:", expected_fee);
        
        // User should pay the funding amount and get back the remainder
        uint256 remaining = funding_amount - pull_amount;
        assertEq( user_usdc_after, user_usdc_before - funding_amount + remaining );
        assertEq( treasury_usdc_after, treasury_usdc_before + expected_fee ); // Treasury gets fee
        assertEq( contract1_usdc_after, contract1_usdc_before + pull_amount - expected_fee ); // Contract gets amount minus fee
    }

    function test_bond_execution_mixed_pull_behavior( ) public
    {
        uint256 funding_amount = 3000 * 10**6;
        uint256 pull_amount = 1000 * 10**6;
        uint256 expected_fee = pull_amount / 10000;
        
        // Setup: Contract1 pulls, Contract2 doesn't
        contract1.set_pull_behavior( true, usdc, pull_amount );
        contract2.set_pull_behavior( false, IERC20(address(0)), 0 );
        
        uint256 user_usdc_before = usdc.balanceOf( user );
        uint256 treasury_usdc_before = usdc.balanceOf( treasury );
        uint256 contract1_usdc_before = usdc.balanceOf( address(contract1) );
        uint256 contract2_usdc_before = usdc.balanceOf( address(contract2) );
        
        // Create execution data
        TokenAmount[] memory fundings = new TokenAmount[](1);
        fundings[0] = TokenAmount({ token: usdc, amount: funding_amount });
        
        CallEntry[] memory calls = new CallEntry[](2);
        calls[0] = CallEntry({
            _contract: IBondRouteProtected(address(contract1)),
            _calldata: abi.encodeWithSignature("do_work()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        calls[1] = CallEntry({
            _contract: IBondRouteProtected(address(contract2)),
            _calldata: abi.encodeWithSignature("do_work()"),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 })
        });
        
        ExecutionData memory execution_data = ExecutionData({
            fundings: fundings,
            calls: calls,
            secret: keccak256("secret_mixed")
        });
        
        vm.startPrank( user );
        usdc.approve( address(bondroute), funding_amount );
        
        bytes21 commitment_proof = bondroute.__OFF_CHAIN__calculate_commitment_proof( user, execution_data );
        bondroute.create_bond( commitment_proof );
        
        vm.roll( block.number + 1 );
        bondroute.execute_bond( 1, execution_data );
        vm.stopPrank( );
        
        // Check balances
        assertEq( usdc.balanceOf( treasury ), treasury_usdc_before + expected_fee );
        assertEq( usdc.balanceOf( address(contract1) ), contract1_usdc_before + pull_amount - expected_fee );
        assertEq( usdc.balanceOf( address(contract2) ), contract2_usdc_before ); // Contract2 didn't pull
        
        // User should get back the remaining funding
        uint256 remaining = funding_amount - pull_amount;
        assertEq( usdc.balanceOf( user ), user_usdc_before - funding_amount + remaining );
    }
}