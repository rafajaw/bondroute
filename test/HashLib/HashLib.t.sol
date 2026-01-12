// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { TokenAmount, BondContext, IBondRouteProtected } from "@BondRouteProtected/BondRouteProtected.sol";
import { HashLib } from "@BondRoute/HashLib.sol";
import { ExecutionData } from "@BondRoute/Core.sol";
import { TYPE_HASH_TOKEN_AMOUNT } from "@BondRoute/Definitions.sol";
import { MockERC20 } from "@test/mocks/MockERC20.sol";
import { MockProtocol } from "@test/mocks/MockProtocol.sol";
import { BondRoute } from "@BondRoute/BondRoute.sol";

/**
 * @title HashLibTest
 * @notice Validates assembly pointer math against Solidity reference implementations
 * @dev Implements IHashLibTests from TestManifest.sol
 */
contract HashLibTest is Test {

    MockERC20 public token_a;
    MockERC20 public token_b;
    MockERC20 public token_c;
    MockProtocol public mock_protocol;
    BondRoute public bondroute;

    function setUp() public
    {
        token_a  =  new MockERC20( "TokenA", "TKA" );
        token_b  =  new MockERC20( "TokenB", "TKB" );
        token_c  =  new MockERC20( "TokenC", "TKC" );

        bondroute      =  new BondRoute( address(this) );
        mock_protocol  =  new MockProtocol();
    }


    // ━━━━  hash_fundings VALIDATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_hash_fundings_assembly_matches_solidity_single() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        bytes32 hash_asm  =  HashLib.hash_fundings( fundings );
        bytes32 hash_sol  =  _hash_fundings_sol( fundings );

        assertEq( hash_asm, hash_sol, "Single funding: assembly should match solidity" );
    }

    function test_hash_fundings_assembly_matches_solidity_multiple() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](3);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });
        fundings[1]  =  TokenAmount({ token: token_b, amount: 200e18 });
        fundings[2]  =  TokenAmount({ token: token_c, amount: 300e18 });

        bytes32 hash_asm  =  HashLib.hash_fundings( fundings );
        bytes32 hash_sol  =  _hash_fundings_sol( fundings );

        assertEq( hash_asm, hash_sol, "Multiple fundings: assembly should match solidity" );
    }

    function test_hash_fundings_empty_returns_zero() public pure
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](0);

        bytes32 hash  =  HashLib.hash_fundings( fundings );

        assertEq( hash, bytes32(0), "Empty fundings should return zero" );
    }

    function test_hash_fundings_deterministic() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](2);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });
        fundings[1]  =  TokenAmount({ token: token_b, amount: 200e18 });

        bytes32 hash_1  =  HashLib.hash_fundings( fundings );
        bytes32 hash_2  =  HashLib.hash_fundings( fundings );

        assertEq( hash_1, hash_2, "Same input should produce same hash" );
    }

    function test_hash_fundings_different_order_different_hash() public view
    {
        TokenAmount[] memory fundings_ab  =  new TokenAmount[](2);
        fundings_ab[0]  =  TokenAmount({ token: token_a, amount: 100e18 });
        fundings_ab[1]  =  TokenAmount({ token: token_b, amount: 200e18 });

        TokenAmount[] memory fundings_ba  =  new TokenAmount[](2);
        fundings_ba[0]  =  TokenAmount({ token: token_b, amount: 200e18 });
        fundings_ba[1]  =  TokenAmount({ token: token_a, amount: 100e18 });

        bytes32 hash_ab  =  HashLib.hash_fundings( fundings_ab );
        bytes32 hash_ba  =  HashLib.hash_fundings( fundings_ba );

        assertTrue( hash_ab != hash_ba, "Different order should produce different hash" );
    }


    // ━━━━  calc_bond_key VALIDATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_calc_bond_key_assembly_matches_solidity() public view
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake  =  TokenAmount({ token: token_a, amount: 100e18 });

        bytes32 key_asm  =  HashLib.calc_bond_key( commitment_hash, stake );
        bytes32 key_sol  =  _calc_bond_key_sol( commitment_hash, stake );

        assertEq( key_asm, key_sol, "Bond key: assembly should match solidity" );
    }

    function test_calc_bond_key_deterministic() public view
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");
        TokenAmount memory stake  =  TokenAmount({ token: token_a, amount: 100e18 });

        bytes32 key_1  =  HashLib.calc_bond_key( commitment_hash, stake );
        bytes32 key_2  =  HashLib.calc_bond_key( commitment_hash, stake );

        assertEq( key_1, key_2, "Same input should produce same bond key" );
    }

    function test_calc_bond_key_different_commitment_different_key() public view
    {
        TokenAmount memory stake  =  TokenAmount({ token: token_a, amount: 100e18 });

        bytes32 key_1  =  HashLib.calc_bond_key( keccak256("commitment_1"), stake );
        bytes32 key_2  =  HashLib.calc_bond_key( keccak256("commitment_2"), stake );

        assertTrue( key_1 != key_2, "Different commitment should produce different key" );
    }

    function test_calc_bond_key_different_stake_different_key() public view
    {
        bytes32 commitment_hash  =  keccak256("test_commitment");

        bytes32 key_1  =  HashLib.calc_bond_key( commitment_hash, TokenAmount({ token: token_a, amount: 100e18 }) );
        bytes32 key_2  =  HashLib.calc_bond_key( commitment_hash, TokenAmount({ token: token_a, amount: 200e18 }) );
        bytes32 key_3  =  HashLib.calc_bond_key( commitment_hash, TokenAmount({ token: token_b, amount: 100e18 }) );

        assertTrue( key_1 != key_2, "Different stake amount should produce different key" );
        assertTrue( key_1 != key_3, "Different stake token should produce different key" );
    }


    // ━━━━  calc_context_hash VALIDATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_calc_context_hash_assembly_matches_solidity() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](2);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });
        fundings[1]  =  TokenAmount({ token: token_b, amount: 200e18 });

        BondContext memory context  =  BondContext({
            user: address(0x1234),
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            fundings: fundings,
            creation_block: 100,
            creation_timestamp: 1000
        });

        uint256 hash_asm  =  HashLib.calc_context_hash( mock_protocol, context );
        uint256 hash_sol  =  _calc_context_hash_sol( mock_protocol, context );

        assertEq( hash_asm, hash_sol, "Context hash: assembly should match solidity" );
    }

    function test_calc_context_hash_deterministic() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        BondContext memory context  =  BondContext({
            user: address(0x1234),
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            fundings: fundings,
            creation_block: 100,
            creation_timestamp: 1000
        });

        uint256 hash_1  =  HashLib.calc_context_hash( mock_protocol, context );
        uint256 hash_2  =  HashLib.calc_context_hash( mock_protocol, context );

        assertEq( hash_1, hash_2, "Same input should produce same context hash" );
    }

    function test_calc_context_hash_different_user_different_hash() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        BondContext memory context_1  =  BondContext({
            user: address(0x1111),
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            fundings: fundings,
            creation_block: 100,
            creation_timestamp: 1000
        });

        BondContext memory context_2  =  BondContext({
            user: address(0x2222),
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            fundings: fundings,
            creation_block: 100,
            creation_timestamp: 1000
        });

        uint256 hash_1  =  HashLib.calc_context_hash( mock_protocol, context_1 );
        uint256 hash_2  =  HashLib.calc_context_hash( mock_protocol, context_2 );

        assertTrue( hash_1 != hash_2, "Different user should produce different hash" );
    }

    function test_calc_context_hash_different_protocol_different_hash() public
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        BondContext memory context  =  BondContext({
            user: address(0x1234),
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            fundings: fundings,
            creation_block: 100,
            creation_timestamp: 1000
        });

        MockProtocol other_protocol  =  new MockProtocol();

        uint256 hash_1  =  HashLib.calc_context_hash( mock_protocol, context );
        uint256 hash_2  =  HashLib.calc_context_hash( other_protocol, context );

        assertTrue( hash_1 != hash_2, "Different protocol should produce different hash" );
    }


    // ━━━━  hash_stake_for_eip712 VALIDATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_hash_stake_for_eip712_assembly_matches_solidity() public view
    {
        TokenAmount memory stake  =  TokenAmount({ token: token_a, amount: 100e18 });

        bytes32 hash_asm  =  HashLib.hash_stake_for_eip712( stake );
        bytes32 hash_sol  =  _hash_stake_for_eip712_sol( stake );

        assertEq( hash_asm, hash_sol, "Stake hash: assembly should match solidity" );
    }

    function test_hash_stake_for_eip712_deterministic() public view
    {
        TokenAmount memory stake  =  TokenAmount({ token: token_a, amount: 100e18 });

        bytes32 hash_1  =  HashLib.hash_stake_for_eip712( stake );
        bytes32 hash_2  =  HashLib.hash_stake_for_eip712( stake );

        assertEq( hash_1, hash_2, "Same stake should produce same hash" );
    }

    function test_hash_stake_for_eip712_different_token_different_hash() public view
    {
        bytes32 hash_1  =  HashLib.hash_stake_for_eip712( TokenAmount({ token: token_a, amount: 100e18 }) );
        bytes32 hash_2  =  HashLib.hash_stake_for_eip712( TokenAmount({ token: token_b, amount: 100e18 }) );

        assertTrue( hash_1 != hash_2, "Different token should produce different hash" );
    }

    function test_hash_stake_for_eip712_different_amount_different_hash() public view
    {
        bytes32 hash_1  =  HashLib.hash_stake_for_eip712( TokenAmount({ token: token_a, amount: 100e18 }) );
        bytes32 hash_2  =  HashLib.hash_stake_for_eip712( TokenAmount({ token: token_a, amount: 200e18 }) );

        assertTrue( hash_1 != hash_2, "Different amount should produce different hash" );
    }

    function test_hash_stake_for_eip712_includes_type_hash() public view
    {
        TokenAmount memory stake  =  TokenAmount({ token: token_a, amount: 100e18 });
        bytes32 hash  =  HashLib.hash_stake_for_eip712( stake );

        bytes32 expected  =  keccak256( abi.encode( TYPE_HASH_TOKEN_AMOUNT, address(token_a), 100e18 ) );

        assertEq( hash, expected, "Should match EIP-712 encoding with TYPE_HASH" );
    }


    // ━━━━  hash_fundings_for_eip712 VALIDATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_hash_fundings_for_eip712_assembly_matches_solidity() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](2);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });
        fundings[1]  =  TokenAmount({ token: token_b, amount: 200e18 });

        bytes32 hash_asm  =  HashLib.hash_fundings_for_eip712( fundings );
        bytes32 hash_sol  =  _hash_fundings_for_eip712_sol( fundings );

        assertEq( hash_asm, hash_sol, "EIP-712 fundings hash: assembly should match solidity" );
    }

    function test_hash_fundings_for_eip712_single() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        bytes32 hash_asm  =  HashLib.hash_fundings_for_eip712( fundings );
        bytes32 hash_sol  =  _hash_fundings_for_eip712_sol( fundings );

        assertEq( hash_asm, hash_sol, "Single funding EIP-712 hash should match" );
    }

    function test_hash_fundings_for_eip712_empty() public pure
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](0);

        bytes32 hash  =  HashLib.hash_fundings_for_eip712( fundings );

        assertEq( hash, keccak256(""), "Empty fundings should hash empty bytes" );
    }

    function test_hash_fundings_for_eip712_deterministic() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](2);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });
        fundings[1]  =  TokenAmount({ token: token_b, amount: 200e18 });

        bytes32 hash_1  =  HashLib.hash_fundings_for_eip712( fundings );
        bytes32 hash_2  =  HashLib.hash_fundings_for_eip712( fundings );

        assertEq( hash_1, hash_2, "Same fundings should produce same EIP-712 hash" );
    }

    function test_hash_fundings_for_eip712_different_order_different_hash() public view
    {
        TokenAmount[] memory fundings_ab  =  new TokenAmount[](2);
        fundings_ab[0]  =  TokenAmount({ token: token_a, amount: 100e18 });
        fundings_ab[1]  =  TokenAmount({ token: token_b, amount: 200e18 });

        TokenAmount[] memory fundings_ba  =  new TokenAmount[](2);
        fundings_ba[0]  =  TokenAmount({ token: token_b, amount: 200e18 });
        fundings_ba[1]  =  TokenAmount({ token: token_a, amount: 100e18 });

        bytes32 hash_ab  =  HashLib.hash_fundings_for_eip712( fundings_ab );
        bytes32 hash_ba  =  HashLib.hash_fundings_for_eip712( fundings_ba );

        assertTrue( hash_ab != hash_ba, "Different order should produce different EIP-712 hash" );
    }


    // ━━━━  calc_commitment_hash VALIDATION  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_calc_commitment_hash_deterministic() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        ExecutionData memory exec_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature("someFunction()")
        });

        bytes32 hash_1  =  HashLib.calc_commitment_hash( address(0x1234), address(bondroute), exec_data );
        bytes32 hash_2  =  HashLib.calc_commitment_hash( address(0x1234), address(bondroute), exec_data );

        assertEq( hash_1, hash_2, "Same input should produce same commitment hash" );
    }

    function test_calc_commitment_hash_different_user_different_hash() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        ExecutionData memory exec_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature("someFunction()")
        });

        bytes32 hash_1  =  HashLib.calc_commitment_hash( address(0x1111), address(bondroute), exec_data );
        bytes32 hash_2  =  HashLib.calc_commitment_hash( address(0x2222), address(bondroute), exec_data );

        assertTrue( hash_1 != hash_2, "Different user should produce different commitment hash" );
    }

    function test_calc_commitment_hash_different_salt_different_hash() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        ExecutionData memory exec_data_1  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            salt: 11111,
            protocol: mock_protocol,
            call: abi.encodeWithSignature("someFunction()")
        });

        ExecutionData memory exec_data_2  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            salt: 22222,
            protocol: mock_protocol,
            call: abi.encodeWithSignature("someFunction()")
        });

        bytes32 hash_1  =  HashLib.calc_commitment_hash( address(0x1234), address(bondroute), exec_data_1 );
        bytes32 hash_2  =  HashLib.calc_commitment_hash( address(0x1234), address(bondroute), exec_data_2 );

        assertTrue( hash_1 != hash_2, "Different salt should produce different commitment hash" );
    }

    function test_calc_commitment_hash_includes_chain_id() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        ExecutionData memory exec_data  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature("someFunction()")
        });

        bytes32 hash  =  HashLib.calc_commitment_hash( address(0x1234), address(bondroute), exec_data );

        assertTrue( hash != bytes32(0), "Commitment hash should be non-zero" );
    }

    function test_calc_commitment_hash_different_call_different_hash() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: token_a, amount: 100e18 });

        ExecutionData memory exec_data_1  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature("function1()")
        });

        ExecutionData memory exec_data_2  =  ExecutionData({
            fundings: fundings,
            stake: TokenAmount({ token: token_a, amount: 50e18 }),
            salt: 12345,
            protocol: mock_protocol,
            call: abi.encodeWithSignature("function2()")
        });

        bytes32 hash_1  =  HashLib.calc_commitment_hash( address(0x1234), address(bondroute), exec_data_1 );
        bytes32 hash_2  =  HashLib.calc_commitment_hash( address(0x1234), address(bondroute), exec_data_2 );

        assertTrue( hash_1 != hash_2, "Different call should produce different commitment hash" );
    }


    // ━━━━  REFERENCE IMPLEMENTATIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function _hash_fundings_sol( TokenAmount[] memory fundings ) private pure returns ( bytes32 )
    {
        uint256 length  =  fundings.length;
        if(  length == 0  )  return bytes32(0);

        bytes memory packed  =  new bytes( length * 0x40 );

        for(  uint256 i = 0  ;  i < length  ;  )
        {
            address token   =  address(fundings[i].token);
            uint256 amount  =  fundings[i].amount;

            assembly ("memory-safe")
            {
                let offset  :=  add( add(packed, 0x20), mul(i, 0x40) )
                mstore( offset,              token )
                mstore( add(offset, 0x20),   amount )
            }

            unchecked { i = i + 1; }
        }

        return keccak256( packed );
    }

    function _calc_bond_key_sol( bytes32 commitment_hash, TokenAmount memory stake ) private pure returns ( bytes32 )
    {
        return keccak256( abi.encode( commitment_hash, address(stake.token), stake.amount ) );
    }

    function _calc_context_hash_sol( IBondRouteProtected protocol, BondContext memory context ) private pure returns ( uint256 )
    {
        bytes32 fundings_hash  =  _hash_fundings_sol( context.fundings );
        return uint256( keccak256( abi.encode(
            address(protocol),
            context.user,
            address(context.stake.token),
            context.stake.amount,
            fundings_hash
        )));
    }

    function _hash_stake_for_eip712_sol( TokenAmount memory stake ) private pure returns ( bytes32 )
    {
        return keccak256( abi.encode( TYPE_HASH_TOKEN_AMOUNT, address(stake.token), stake.amount ) );
    }

    function _hash_fundings_for_eip712_sol( TokenAmount[] memory fundings ) private pure returns ( bytes32 )
    {
        bytes32[] memory hashes  =  new bytes32[]( fundings.length );

        for(  uint256 i = 0  ;  i < fundings.length  ;  )
        {
            hashes[i]  =  keccak256( abi.encode( TYPE_HASH_TOKEN_AMOUNT, address(fundings[i].token), fundings[i].amount ) );
            unchecked { i = i + 1; }
        }

        return keccak256( abi.encodePacked( hashes ) );
    }
}
