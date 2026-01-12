// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { ValidationLib, InvalidTypedString } from "@BondRoute/ValidationLib.sol";
import { IERC20, TokenAmount, IBondRouteProtected, PossiblyBondFarming } from "@BondRouteProtected/BondRouteProtected.sol";
import { ExecutionData } from "@BondRoute/Core.sol";
import { TransferFailed } from "@BondRoute/utils/TransferLib.sol";
import { Reentrancy } from "@BondRoute/utils/ReentrancyLock.sol";
import "@BondRoute/Definitions.sol";

/**
 * @title MockProtocolWrongOffset
 * @notice Returns malformed selector array with wrong offset
 */
contract MockProtocolWrongOffset {

    function BondRoute_get_protected_selectors() external pure returns ( bytes memory )
    {
        // Return malformed data: offset should be 32 but we return 64.
        bytes memory malformed  =  new bytes(128);
        assembly {
            mstore( add( malformed, 32 ), 64 )   // Wrong offset (should be 32).
            mstore( add( malformed, 64 ), 1 )    // Length = 1.
            mstore( add( malformed, 96 ), 0xdeadbeef00000000000000000000000000000000000000000000000000000000 )
        }
        return malformed;
    }
}

/**
 * @title MockProtocolSizeMismatch
 * @notice Returns selector array with size mismatch
 */
contract MockProtocolSizeMismatch {

    function BondRoute_get_protected_selectors() external pure returns ( bytes memory )
    {
        // Return data with correct offset but wrong total size.
        bytes memory malformed  =  new bytes(100);  // Should be 96 for 1 selector.
        assembly {
            mstore( add( malformed, 32 ), 32 )   // Correct offset.
            mstore( add( malformed, 64 ), 1 )    // Length = 1.
            mstore( add( malformed, 96 ), 0xdeadbeef00000000000000000000000000000000000000000000000000000000 )
        }
        return malformed;
    }
}

/**
 * @title MockProtocolValidButNoMatch
 * @notice Returns valid selector array but target selector not in list
 */
contract MockProtocolValidButNoMatch {

    function BondRoute_get_protected_selectors() external pure returns ( bytes4[] memory selectors )
    {
        selectors  =  new bytes4[](2);
        selectors[0]  =  bytes4(0xaaaaaaaa);
        selectors[1]  =  bytes4(0xbbbbbbbb);
    }
}

/**
 * @title MockProtocolEmpty
 * @notice Returns empty selector array
 */
contract MockProtocolEmpty {

    function BondRoute_get_protected_selectors() external pure returns ( bytes4[] memory )
    {
        return new bytes4[](0);
    }
}

/**
 * @title ValidationLibHarness
 * @notice Exposes ValidationLib internal functions for testing
 */
contract ValidationLibHarness {

    function exposed_is_valid_execution( ExecutionData memory execution_data ) external view returns ( bool is_valid, string memory invalid_reason )
    {
        return ValidationLib.is_valid_execution( execution_data );
    }

    function exposed_is_valid_fundings( TokenAmount[] memory fundings ) external pure returns ( bool is_valid, string memory invalid_reason )
    {
        return ValidationLib.is_valid_fundings( fundings );
    }

    function exposed_revert_if_possibly_bond_farming( bytes memory call_output ) external pure
    {
        ValidationLib.revert_if_possibly_bond_farming( call_output );
    }

    function exposed_validate_typed_string_prefix( string memory typed_string ) external pure
    {
        ValidationLib.validate_typed_string_prefix( typed_string );
    }

    function exposed_validate_TokenAmount_definition( string memory typed_string, uint256 TokenAmount_offset ) external pure
    {
        ValidationLib.validate_TokenAmount_definition( typed_string, TokenAmount_offset );
    }
}

/**
 * @title ValidationLibTest
 * @notice Tests for ValidationLib library (execution validation, bond farming detection, EIP-712 type validation)
 * @dev Implements IValidationLibTests from TestManifest.sol
 */
contract ValidationLibTest is Test {

    ValidationLibHarness public harness;
    MockProtocolWrongOffset public mock_wrong_offset;
    MockProtocolSizeMismatch public mock_size_mismatch;
    MockProtocolValidButNoMatch public mock_no_match;
    MockProtocolEmpty public mock_empty;

    IERC20 public constant USDC  =  IERC20(address(0x111111));
    IERC20 public constant DAI   =  IERC20(address(0x222222));
    IERC20 public constant WETH  =  IERC20(address(0x333333));
    IERC20 public constant USDT  =  IERC20(address(0x444444));
    IERC20 public constant WBTC  =  IERC20(address(0x555555));

    function setUp() public
    {
        harness            =  new ValidationLibHarness();
        mock_wrong_offset  =  new MockProtocolWrongOffset();
        mock_size_mismatch =  new MockProtocolSizeMismatch();
        mock_no_match      =  new MockProtocolValidButNoMatch();
        mock_empty         =  new MockProtocolEmpty();
    }


    // ━━━━  is_valid_fundings() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_is_valid_fundings_accepts_empty_array() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](0);

        ( bool is_valid, )  =  harness.exposed_is_valid_fundings( fundings );

        assertTrue( is_valid, "Empty fundings array should be valid" );
    }

    function test_is_valid_fundings_accepts_single_funding() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](1);
        fundings[0]  =  TokenAmount({ token: USDC, amount: 100e6 });

        ( bool is_valid, )  =  harness.exposed_is_valid_fundings( fundings );

        assertTrue( is_valid, "Single valid funding should be accepted" );
    }

    function test_is_valid_fundings_accepts_max_fundings() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](MAX_FUNDINGS_PER_BOND);
        fundings[0]  =  TokenAmount({ token: USDC, amount: 100e6 });
        fundings[1]  =  TokenAmount({ token: DAI, amount: 100e18 });
        fundings[2]  =  TokenAmount({ token: WETH, amount: 1e18 });
        fundings[3]  =  TokenAmount({ token: USDT, amount: 100e6 });

        ( bool is_valid, )  =  harness.exposed_is_valid_fundings( fundings );

        assertTrue( is_valid, "Max fundings (4) should be accepted" );
    }

    function test_is_valid_fundings_rejects_too_many_fundings() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](MAX_FUNDINGS_PER_BOND + 1);
        fundings[0]  =  TokenAmount({ token: USDC, amount: 100e6 });
        fundings[1]  =  TokenAmount({ token: DAI, amount: 100e18 });
        fundings[2]  =  TokenAmount({ token: WETH, amount: 1e18 });
        fundings[3]  =  TokenAmount({ token: USDT, amount: 100e6 });
        fundings[4]  =  TokenAmount({ token: WBTC, amount: 1e8 });

        ( bool is_valid, string memory reason )  =  harness.exposed_is_valid_fundings( fundings );

        assertFalse( is_valid, "More than MAX_FUNDINGS_PER_BOND should be rejected" );
        assertEq( reason, INVALID_TOO_MANY_FUNDINGS, "Should return correct reason" );
    }

    function test_is_valid_fundings_rejects_zero_amount() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](2);
        fundings[0]  =  TokenAmount({ token: USDC, amount: 100e6 });
        fundings[1]  =  TokenAmount({ token: DAI, amount: 0 });

        ( bool is_valid, string memory reason )  =  harness.exposed_is_valid_fundings( fundings );

        assertFalse( is_valid, "Zero amount funding should be rejected" );
        assertEq( reason, INVALID_ZERO_AMOUNT, "Should return correct reason" );
    }

    function test_is_valid_fundings_rejects_duplicate_tokens() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](2);
        fundings[0]  =  TokenAmount({ token: USDC, amount: 100e6 });
        fundings[1]  =  TokenAmount({ token: USDC, amount: 200e6 });

        ( bool is_valid, string memory reason )  =  harness.exposed_is_valid_fundings( fundings );

        assertFalse( is_valid, "Duplicate tokens should be rejected" );
        assertEq( reason, INVALID_DUPLICATE_FUNDING_TOKEN, "Should return correct reason" );
    }

    function test_is_valid_fundings_detects_duplicate_at_end() public view
    {
        TokenAmount[] memory fundings  =  new TokenAmount[](4);
        fundings[0]  =  TokenAmount({ token: USDC, amount: 100e6 });
        fundings[1]  =  TokenAmount({ token: DAI, amount: 100e18 });
        fundings[2]  =  TokenAmount({ token: WETH, amount: 1e18 });
        fundings[3]  =  TokenAmount({ token: USDC, amount: 50e6 });  // Duplicate of first.

        ( bool is_valid, string memory reason )  =  harness.exposed_is_valid_fundings( fundings );

        assertFalse( is_valid, "Duplicate at end should be detected" );
        assertEq( reason, INVALID_DUPLICATE_FUNDING_TOKEN, "Should return correct reason" );
    }


    // ━━━━  is_valid_execution() - Protocol Validation  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_is_valid_execution_rejects_precompile_protocol() public view
    {
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 }),
            salt: 0,
            protocol: IBondRouteProtected(address(0x01)),
            call: abi.encodeWithSelector(bytes4(0xdeadbeef))
        });

        ( bool is_valid, string memory reason )  =  harness.exposed_is_valid_execution( execution_data );

        assertFalse( is_valid, "Precompile address should be rejected" );
        assertEq( reason, INVALID_PROTOCOL_OR_CALL, "Should return correct reason" );
    }

    function test_is_valid_execution_rejects_malformed_offset() public view
    {
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 }),
            salt: 0,
            protocol: IBondRouteProtected(address(mock_wrong_offset)),
            call: abi.encodeWithSelector(bytes4(0xdeadbeef))
        });

        ( bool is_valid, string memory reason )  =  harness.exposed_is_valid_execution( execution_data );

        assertFalse( is_valid, "Malformed offset should be rejected" );
        assertEq( reason, INVALID_PROTOCOL_OR_CALL, "Should return correct reason" );
    }

    function test_is_valid_execution_rejects_size_mismatch() public view
    {
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 }),
            salt: 0,
            protocol: IBondRouteProtected(address(mock_size_mismatch)),
            call: abi.encodeWithSelector(bytes4(0xdeadbeef))
        });

        ( bool is_valid, string memory reason )  =  harness.exposed_is_valid_execution( execution_data );

        assertFalse( is_valid, "Size mismatch should be rejected" );
        assertEq( reason, INVALID_PROTOCOL_OR_CALL, "Should return correct reason" );
    }

    function test_is_valid_execution_rejects_selector_not_found() public view
    {
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 }),
            salt: 0,
            protocol: IBondRouteProtected(address(mock_no_match)),
            call: abi.encodeWithSelector(bytes4(0xdeadbeef))  // Not in mock's list.
        });

        ( bool is_valid, string memory reason )  =  harness.exposed_is_valid_execution( execution_data );

        assertFalse( is_valid, "Selector not in list should be rejected" );
        assertEq( reason, INVALID_PROTOCOL_OR_CALL, "Should return correct reason" );
    }

    function test_is_valid_execution_rejects_empty_selector_list() public view
    {
        ExecutionData memory execution_data  =  ExecutionData({
            fundings: new TokenAmount[](0),
            stake: TokenAmount({ token: IERC20(address(0)), amount: 0 }),
            salt: 0,
            protocol: IBondRouteProtected(address(mock_empty)),
            call: abi.encodeWithSelector(bytes4(0xdeadbeef))
        });

        ( bool is_valid, string memory reason )  =  harness.exposed_is_valid_execution( execution_data );

        assertFalse( is_valid, "Empty selector list should be rejected" );
        assertEq( reason, INVALID_PROTOCOL_OR_CALL, "Should return correct reason" );
    }


    // ━━━━  revert_if_possibly_bond_farming() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_revert_if_possibly_bond_farming_reverts_on_empty_output() public
    {
        bytes memory empty_output  =  "";

        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, OUT_OF_GAS_OR_UNSPECIFIED_FAILURE, bytes32(0) ) );
        harness.exposed_revert_if_possibly_bond_farming( empty_output );
    }

    function test_revert_if_possibly_bond_farming_passes_short_output() public view
    {
        // 1-3 bytes: not empty, not >= 4, should pass (no selector to check).
        bytes memory short_output  =  hex"aabbcc";

        harness.exposed_revert_if_possibly_bond_farming( short_output );
        // No revert = pass.
    }

    function test_revert_if_possibly_bond_farming_reverts_on_transfer_failed() public
    {
        bytes memory transfer_failed_output  =  abi.encodeWithSelector(
            TransferFailed.selector,
            address(0x1111),  // from
            address(0x2222),  // token
            100e6,            // amount
            address(0x3333)   // to
        );

        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, "Transfer failed", bytes32(uint256(uint160(address(0x2222)))) ) );
        harness.exposed_revert_if_possibly_bond_farming( transfer_failed_output );
    }

    function test_revert_if_possibly_bond_farming_reverts_on_reentrancy() public
    {
        bytes memory reentrancy_output  =  abi.encodeWithSelector( Reentrancy.selector );

        vm.expectRevert( abi.encodeWithSelector( PossiblyBondFarming.selector, "Reentrancy", bytes32(0) ) );
        harness.exposed_revert_if_possibly_bond_farming( reentrancy_output );
    }

    function test_revert_if_possibly_bond_farming_propagates_possibly_bond_farming() public
    {
        bytes memory pbf_output  =  abi.encodeWithSelector( PossiblyBondFarming.selector, "Custom reason", bytes32(uint256(123)) );

        vm.expectRevert( pbf_output );
        harness.exposed_revert_if_possibly_bond_farming( pbf_output );
    }

    function test_revert_if_possibly_bond_farming_passes_unknown_selector() public view
    {
        // Unknown error selector should pass through (not bond farming related).
        bytes memory unknown_output  =  abi.encodeWithSelector( bytes4(0x12345678), "some data" );

        harness.exposed_revert_if_possibly_bond_farming( unknown_output );
        // No revert = pass.
    }


    // ━━━━  validate_typed_string_prefix() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_validate_typed_string_prefix_accepts_valid() public view
    {
        string memory valid_prefix  =  "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,bytes call)";

        harness.exposed_validate_typed_string_prefix( valid_prefix );
        // No revert = pass.
    }

    function test_validate_typed_string_prefix_rejects_too_short() public
    {
        string memory short_string  =  "ExecuteBondAs(TokenAmount[] fund";  // < 96 chars.

        vm.expectRevert( InvalidTypedString.selector );
        harness.exposed_validate_typed_string_prefix( short_string );
    }

    function test_validate_typed_string_prefix_rejects_wrong_word1() public
    {
        // Wrong first word (first 32 bytes).
        string memory wrong_word1  =  "WrongBondAsXX(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,bytes call)";

        vm.expectRevert( InvalidTypedString.selector );
        harness.exposed_validate_typed_string_prefix( wrong_word1 );
    }

    function test_validate_typed_string_prefix_rejects_wrong_word2() public
    {
        // Correct first word, wrong second word.
        string memory wrong_word2  =  "ExecuteBondAs(TokenAmount[] fundXXXX,TokenAmount stake,uint256 salt,address protocol,bytes call)";

        vm.expectRevert( InvalidTypedString.selector );
        harness.exposed_validate_typed_string_prefix( wrong_word2 );
    }

    function test_validate_typed_string_prefix_rejects_wrong_word3() public
    {
        // Correct first two words, wrong third word (protocol part).
        string memory wrong_word3  =  "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 sXXX,address protocolX,bytes call)";

        vm.expectRevert( InvalidTypedString.selector );
        harness.exposed_validate_typed_string_prefix( wrong_word3 );
    }


    // ━━━━  validate_TokenAmount_definition() Tests  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_validate_TokenAmount_definition_accepts_valid() public view
    {
        // Valid type string with TokenAmount definition.
        string memory valid  =  "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,bytes call)TokenAmount(address token,uint256 amount)";
        uint256 offset  =  96;  // Position where "TokenAmount(address..." starts (0-indexed).

        harness.exposed_validate_TokenAmount_definition( valid, offset );
        // No revert = pass.
    }

    function test_validate_TokenAmount_definition_rejects_too_short() public
    {
        string memory short_string  =  "ExecuteBondAs()TokenAmount(address token,uint25";  // Truncated.
        uint256 offset  =  16;

        vm.expectRevert( InvalidTypedString.selector );
        harness.exposed_validate_TokenAmount_definition( short_string, offset );
    }

    function test_validate_TokenAmount_definition_rejects_zero_offset() public
    {
        string memory valid  =  "TokenAmount(address token,uint256 amount)";

        vm.expectRevert( InvalidTypedString.selector );
        harness.exposed_validate_TokenAmount_definition( valid, 0 );
    }

    function test_validate_TokenAmount_definition_rejects_wrong_word1() public
    {
        // Wrong TokenAmount definition (missing closing paren before - 'X' instead of ')').
        string memory wrong  =  "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,bytes callXTokenAmount(address token,uint256 amount)";
        uint256 offset  =  96;

        vm.expectRevert( InvalidTypedString.selector );
        harness.exposed_validate_TokenAmount_definition( wrong, offset );
    }

    function test_validate_TokenAmount_definition_rejects_wrong_word2() public
    {
        // Wrong amount part ("56 amountX" instead of "56 amount)").
        string memory wrong  =  "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,bytes call)TokenAmount(address token,uint256 amountX";
        uint256 offset  =  96;

        vm.expectRevert( InvalidTypedString.selector );
        harness.exposed_validate_TokenAmount_definition( wrong, offset );
    }
}
