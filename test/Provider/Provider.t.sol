// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { Provider, Forbidden, ProtocolAnnounced } from "@BondRoute/Provider.sol";
import { Invalid, ExecutionData } from "@BondRoute/Core.sol";
import { IERC20, InsufficientFunding, TokenAmount, BondContext } from "@BondRouteProtected/BondRouteProtected.sol";
import { BondStatus } from "@BondRoute/Definitions.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockProtocol } from "@test/mocks/MockProtocol.sol";
import { HashLib } from "@BondRoute/HashLib.sol";
import { MAX_MESSAGE_LENGTH } from "@BondRoute/Definitions.sol";

contract ProviderHarness is Provider {

    constructor() {}

    function exposed_execute_bond_internal( address user, ExecutionData calldata execution_data ) external payable returns ( BondStatus status, bytes memory output )
    {
        return _execute_bond_internal( user, execution_data );
    }

    function exposed_create_bond_internal( bytes32 commitment_hash, TokenAmount memory stake, uint256 amount_received ) external
    {
        _create_bond_internal( commitment_hash, stake, amount_received );
    }

    function exposed_calc_commitment_hash( address user, ExecutionData calldata execution_data ) external view returns ( bytes32 )
    {
        return HashLib.calc_commitment_hash( user, address(this), execution_data );
    }

    function exposed_get_context_hash() external view returns ( uint256 )
    {
        return __transient__context_hash;
    }

    function exposed_set_context_hash( uint256 value ) external
    {
        __transient__context_hash  =  value;
    }

    function exposed_get_held_stake() external view returns ( uint256 )
    {
        return __transient__held_stake;
    }

    function exposed_set_held_stake( uint256 value ) external
    {
        __transient__held_stake  =  value;
    }

    function exposed_get_held_msg_value() external view returns ( uint256 )
    {
        return __transient__held_msg_value;
    }

    function exposed_set_held_msg_value( uint256 value ) external
    {
        __transient__held_msg_value  =  value;
    }

    function exposed_get_accumulated_airdrops( IERC20 token ) external view returns ( uint256 )
    {
        return _accumulated_airdrops[ token ];
    }
}

contract ProviderTest is Test {

    ProviderHarness public provider_harness;
    MockProtocol public mock_protocol;
    MockERC20 public usdc;
    MockERC20 public dai;
    MockERC20 public weth;

    address public constant USER       =  address(0x1111);
    address public constant RECIPIENT  =  address(0x2222);

    function setUp() public
    {
        provider_harness  =  new ProviderHarness();
        mock_protocol     =  new MockProtocol();
        usdc              =  new MockERC20( "USDC", "USDC" );
        dai               =  new MockERC20( "DAI", "DAI" );
        weth              =  new MockERC20( "WETH", "WETH" );

        usdc.mint( USER, 10000e6 );
        usdc.mint( address(provider_harness), 10000e6 );
        dai.mint( USER, 10000e18 );
        dai.mint( address(provider_harness), 10000e18 );
        weth.mint( USER, 100e18 );
        weth.mint( address(provider_harness), 100e18 );

        vm.deal( USER, 1000 ether );
        vm.deal( address(provider_harness), 1000 ether );

        vm.prank( USER );
        usdc.approve( address(provider_harness), type(uint256).max );

        vm.prank( USER );
        dai.approve( address(provider_harness), type(uint256).max );

        vm.prank( USER );
        weth.approve( address(provider_harness), type(uint256).max );
    }


    // ━━━━  ANNOUNCE_PROTOCOL TESTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_announce_protocol_emits_event() public
    {
        vm.expectEmit( true, false, false, true );
        emit ProtocolAnnounced( address(this), "Test Protocol", "Test Description" );

        provider_harness.announce_protocol( "Test Protocol", "Test Description" );
    }

    function test_announce_protocol_accepts_valid_name() public
    {
        provider_harness.announce_protocol( "Valid Protocol Name", "Description" );
    }

    function test_announce_protocol_accepts_empty_description() public
    {
        provider_harness.announce_protocol( "Protocol", "" );
    }

    function test_announce_protocol_reverts_on_empty_name() public
    {
        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "name.length", 0 ) );
        provider_harness.announce_protocol( "", "Description" );
    }

    function test_announce_protocol_reverts_on_name_too_long() public
    {
        string memory long_name  =  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "name.length", bytes(long_name).length ) );
        provider_harness.announce_protocol( long_name, "Description" );
    }

    function test_announce_protocol_reverts_on_description_too_long() public
    {
        string memory long_description;
        unchecked
        {
            for(  uint256 i = 0  ;  i <= MAX_MESSAGE_LENGTH  ;  i++  )
            {
                long_description  =  string.concat( long_description, "a" );
            }
        }

        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "description.length", bytes(long_description).length ) );
        provider_harness.announce_protocol( "Protocol", long_description );
    }


    // ━━━━  TRANSFER_FUNDING TESTS: BASIC ERC20  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_funding_pulls_erc20_from_user() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: dai, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );

        uint256 user_balance_before      =  usdc.balanceOf( USER );
        uint256 recipient_balance_before =  usdc.balanceOf( RECIPIENT );

        vm.prank( address(mock_protocol) );
        ( uint256 updated_index, uint256 new_available )  =  provider_harness.transfer_funding( RECIPIENT, usdc, 1000e6, context );

        assertEq( updated_index, 0, "Should return index 0" );
        assertEq( new_available, 0, "Should deplete funding" );
        assertEq( usdc.balanceOf( USER ), user_balance_before - 1000e6, "Should pull from user" );
        assertEq( usdc.balanceOf( RECIPIENT ), recipient_balance_before + 1000e6, "Should transfer to recipient" );
    }

    function test_transfer_funding_updates_context_hash() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: dai, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        uint256 initial_hash  =  HashLib.calc_context_hash( mock_protocol, context );
        provider_harness.exposed_set_context_hash( initial_hash );

        vm.prank( address(mock_protocol) );
        ( uint256 updated_index, uint256 new_available )  =  provider_harness.transfer_funding( RECIPIENT, usdc, 1000e6, context );

        context.fundings[ updated_index ].amount  =  new_available;
        uint256 expected_new_hash  =  HashLib.calc_context_hash( mock_protocol, context );
        uint256 actual_new_hash    =  provider_harness.exposed_get_context_hash();

        assertEq( actual_new_hash, expected_new_hash, "Should update context hash" );
        assertTrue( actual_new_hash != initial_hash, "Hash should change" );
    }

    function test_transfer_funding_returns_updated_amounts() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: dai, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );

        vm.prank( address(mock_protocol) );
        ( uint256 updated_index, uint256 new_available )  =  provider_harness.transfer_funding( RECIPIENT, usdc, 600e6, context );

        assertEq( updated_index, 0, "Should return correct index" );
        assertEq( new_available, 400e6, "Should return remaining amount" );
    }


    // ━━━━  TRANSFER_FUNDING TESTS: SMART STAKE CONSUMPTION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_funding_uses_stake_first() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 100e6 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 100e6 );

        uint256 user_balance_before      =  usdc.balanceOf( USER );
        uint256 recipient_balance_before =  usdc.balanceOf( RECIPIENT );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 1000e6, context );

        assertEq( usdc.balanceOf( USER ), user_balance_before - 900e6, "Should pull 900 from user" );
        assertEq( usdc.balanceOf( RECIPIENT ), recipient_balance_before + 1000e6, "Should transfer full 1000 to recipient" );
        assertEq( provider_harness.exposed_get_held_stake(), 0, "Should consume all stake" );
    }

    function test_transfer_funding_erc20_with_matching_stake() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 500e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 1000e6 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 1000e6 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 500e6, context );

        assertEq( usdc.balanceOf( USER ), user_balance_before, "Should not pull from user" );
        assertEq( provider_harness.exposed_get_held_stake(), 500e6, "Should leave 500 in stake" );
    }

    function test_transfer_funding_partial_from_stake_partial_from_user() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 300e6 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 300e6 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 1000e6, context );

        assertEq( usdc.balanceOf( USER ), user_balance_before - 700e6, "Should pull 700 from user" );
        assertEq( provider_harness.exposed_get_held_stake(), 0, "Should consume all stake" );
    }


    // ━━━━  TRANSFER_FUNDING TESTS: NATIVE TOKEN  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_funding_uses_msg_value_for_native() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_msg_value( 1 ether );

        uint256 recipient_balance_before  =  RECIPIENT.balance;

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, IERC20(address(0)), 1 ether, context );

        assertEq( RECIPIENT.balance, recipient_balance_before + 1 ether, "Should transfer native to recipient" );
        assertEq( provider_harness.exposed_get_held_msg_value(), 0, "Should consume all msg.value" );
    }

    function test_transfer_funding_native_with_native_stake() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 2 ether });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: IERC20(address(0)), amount: 1 ether }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 1 ether );
        provider_harness.exposed_set_held_msg_value( 1 ether );

        uint256 recipient_balance_before  =  RECIPIENT.balance;

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, IERC20(address(0)), 2 ether, context );

        assertEq( RECIPIENT.balance, recipient_balance_before + 2 ether, "Should transfer full 2 ETH" );
        assertEq( provider_harness.exposed_get_held_stake(), 0, "Should consume stake first" );
        assertEq( provider_harness.exposed_get_held_msg_value(), 0, "Should consume msg.value" );
    }


    // ━━━━  TRANSFER_FUNDING TESTS: MULTIPLE CALLS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_funding_multiple_calls_same_token() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: dai, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );

        vm.startPrank( address(mock_protocol) );

        ( uint256 updated_index, uint256 new_available )  =  provider_harness.transfer_funding( RECIPIENT, usdc, 400e6, context );
        context.fundings[ updated_index ].amount  =  new_available;

        ( updated_index, new_available )  =  provider_harness.transfer_funding( RECIPIENT, usdc, 300e6, context );
        context.fundings[ updated_index ].amount  =  new_available;

        vm.stopPrank();

        assertEq( new_available, 300e6, "Should have 300 remaining" );
        assertEq( usdc.balanceOf( RECIPIENT ), 700e6, "Should transfer total 700" );
    }

    function test_transfer_funding_depletes_funding_correctly() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: dai, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );

        vm.prank( address(mock_protocol) );
        ( , uint256 new_available )  =  provider_harness.transfer_funding( RECIPIENT, usdc, 1000e6, context );

        assertEq( new_available, 0, "Should fully deplete funding" );
    }


    // ━━━━  TRANSFER_FUNDING TESTS: VALIDATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_funding_reverts_on_context_mismatch() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: dai, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( 0x1234 );

        uint256 calculated_hash  =  HashLib.calc_context_hash( mock_protocol, context );

        vm.expectRevert( abi.encodeWithSelector( Forbidden.selector, address(mock_protocol), calculated_hash, 0x1234 ) );
        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 1000e6, context );
    }

    function test_transfer_funding_reverts_on_insufficient_funding() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: dai, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );

        vm.expectRevert( abi.encodeWithSelector( InsufficientFunding.selector, address(usdc), 1000e6, 1500e6 ) );
        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 1500e6, context );
    }

    function test_transfer_funding_reverts_on_token_not_in_fundings() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: dai, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );

        vm.expectRevert( abi.encodeWithSelector( InsufficientFunding.selector, address(weth), 0, 100e18 ) );
        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, weth, 100e18, context );
    }

    function test_transfer_funding_reverts_on_self_transfer() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );

        // Attempt to transfer to the provider itself (self-transfer).
        vm.expectRevert( abi.encodeWithSelector( Invalid.selector, "to", uint160(address(provider_harness)) ) );
        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( address(provider_harness), usdc, 1000e6, context );
    }

    function test_transfer_funding_zero_amount_returns_early() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );

        // Transfer zero amount - should return early with original available amount.
        vm.prank( address(mock_protocol) );
        ( uint256 updated_index, uint256 new_available )  =  provider_harness.transfer_funding( RECIPIENT, usdc, 0, context );

        assertEq( updated_index, 0, "Should return correct index" );
        assertEq( new_available, 1000e6, "Should return original available amount" );
    }


    // ━━━━  TRANSFER_FUNDING TESTS: HELD STATE UPDATES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_funding_updates_held_state() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 500e6 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 500e6 );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 300e6, context );

        assertEq( provider_harness.exposed_get_held_stake(), 200e6, "Should update held stake" );
    }


    // ━━━━  CRITICAL: STAKE + NATIVE FUNDING COMBINATIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_funding_stake_greater_than_funding_erc20() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 500e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 1000e6 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 1000e6 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 500e6, context );

        assertEq( usdc.balanceOf( USER ), user_balance_before, "Should not pull from user" );
        assertEq( usdc.balanceOf( RECIPIENT ), 500e6, "Should transfer 500 to recipient" );
        assertEq( provider_harness.exposed_get_held_stake(), 500e6, "Should leave 500 stake for refund" );
    }

    function test_transfer_funding_stake_less_than_funding_erc20() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 200e6 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 200e6 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 1000e6, context );

        assertEq( usdc.balanceOf( USER ), user_balance_before - 800e6, "Should pull 800 from user" );
        assertEq( usdc.balanceOf( RECIPIENT ), 1000e6, "Should transfer full 1000 to recipient" );
        assertEq( provider_harness.exposed_get_held_stake(), 0, "Should consume all stake" );
    }

    function test_transfer_funding_consumed_less_than_stake() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 1000e6 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 1000e6 );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 300e6, context );

        assertEq( provider_harness.exposed_get_held_stake(), 700e6, "Should leave 700 stake for refund" );
    }

    function test_transfer_funding_consumed_greater_than_stake() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 2000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 500e6 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 500e6 );

        uint256 user_balance_before  =  usdc.balanceOf( USER );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 1500e6, context );

        assertEq( usdc.balanceOf( USER ), user_balance_before - 1000e6, "Should pull 1000 from user" );
        assertEq( provider_harness.exposed_get_held_stake(), 0, "Should consume all stake" );
    }

    function test_transfer_funding_native_msg_value_fully_consumed() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_msg_value( 1 ether );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, IERC20(address(0)), 1 ether, context );

        assertEq( provider_harness.exposed_get_held_msg_value(), 0, "Should consume all msg.value" );
    }

    function test_transfer_funding_native_msg_value_partially_consumed() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 2 ether });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: usdc, amount: 0 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_msg_value( 2 ether );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, IERC20(address(0)), 0.8 ether, context );

        assertEq( provider_harness.exposed_get_held_msg_value(), 1.2 ether, "Should leave 1.2 ETH for refund" );
    }

    function test_transfer_funding_native_stake_greater_than_funding() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 1 ether });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: IERC20(address(0)), amount: 3 ether }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 3 ether );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, IERC20(address(0)), 1 ether, context );

        assertEq( provider_harness.exposed_get_held_stake(), 2 ether, "Should leave 2 ETH stake for refund" );
        assertEq( RECIPIENT.balance, 1 ether, "Should transfer 1 ETH to recipient" );
    }

    function test_transfer_funding_native_stake_less_than_funding() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 3 ether });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: IERC20(address(0)), amount: 1 ether }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 1 ether );
        provider_harness.exposed_set_held_msg_value( 2 ether );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, IERC20(address(0)), 3 ether, context );

        assertEq( provider_harness.exposed_get_held_stake(), 0, "Should consume all stake" );
        assertEq( provider_harness.exposed_get_held_msg_value(), 0, "Should consume all msg.value" );
        assertEq( RECIPIENT.balance, 3 ether, "Should transfer 3 ETH to recipient" );
    }

    function test_transfer_funding_native_stake_and_msg_value_partial_consumption() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: IERC20(address(0)), amount: 5 ether });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: IERC20(address(0)), amount: 2 ether }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );
        provider_harness.exposed_set_held_stake( 2 ether );
        provider_harness.exposed_set_held_msg_value( 3 ether );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, IERC20(address(0)), 2.5 ether, context );

        assertEq( provider_harness.exposed_get_held_stake(), 0, "Should consume all stake" );
        assertEq( provider_harness.exposed_get_held_msg_value(), 2.5 ether, "Should leave 2.5 ETH msg.value for refund" );
        assertEq( RECIPIENT.balance, 2.5 ether, "Should transfer 2.5 ETH to recipient" );
    }


    // ━━━━  REENTRANCY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_transfer_funding_reverts_on_reentrancy() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[ 0 ]  =  TokenAmount({ token: usdc, amount: 1000e6 });

        BondContext memory context  =  BondContext({
            user:                 USER,
            stake:                TokenAmount({ token: dai, amount: 100e6 }),
            fundings:             fundings,
            creation_block:       block.number,
            creation_timestamp:   block.timestamp
        });

        provider_harness.exposed_set_context_hash( HashLib.calc_context_hash( mock_protocol, context ) );

        bytes memory reentrancy_call  =  abi.encodeCall(
            provider_harness.transfer_funding,
            ( RECIPIENT, usdc, 100e6, context )
        );
        usdc.set_reentrancy_call( address(provider_harness), reentrancy_call );

        vm.prank( USER );
        usdc.approve( address(provider_harness), 1000e6 );

        vm.prank( address(mock_protocol) );
        provider_harness.transfer_funding( RECIPIENT, usdc, 300e6, context );

        assertFalse( usdc.did_reentrancy_succeed(), "Reentrancy attack should fail - missing reentrancy guard!" );
    }
}
