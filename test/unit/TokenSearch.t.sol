// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "@BondRoute/utils/TokenSearch.sol";
import "@OpenZeppelin/token/ERC20/ERC20.sol";


contract MockToken is ERC20 {
    constructor( string memory name, string memory symbol ) ERC20( name, symbol ) { }
}


contract TokenSearchTest is Test {

    using TokenSearch for TokenAmount[];
    
    MockToken token1;
    MockToken token2;
    MockToken token3;

    function setUp( ) public
    {
        token1 = new MockToken( "Token1", "TK1" );
        token2 = new MockToken( "Token2", "TK2" );
        token3 = new MockToken( "Token3", "TK3" );
    }

    function test_index_of_returns_correct_index( ) public view
    {
        TokenAmount[] memory tokens = new TokenAmount[](3);
        tokens[0] = TokenAmount({ token: token1, amount: 100 });
        tokens[1] = TokenAmount({ token: token2, amount: 200 });
        tokens[2] = TokenAmount({ token: token3, amount: 300 });
        
        uint256 index = tokens.index_of( token2 );
        assertEq( index, 1 );
    }

    function test_index_of_returns_first_occurrence( ) public view
    {
        TokenAmount[] memory tokens = new TokenAmount[](3);
        tokens[0] = TokenAmount({ token: token1, amount: 100 });
        tokens[1] = TokenAmount({ token: token2, amount: 200 });
        tokens[2] = TokenAmount({ token: token2, amount: 300 }); // Duplicate
        
        uint256 index = tokens.index_of( token2 );
        assertEq( index, 1 ); // First occurrence
    }

    function test_index_of_returns_not_found_for_missing_token( ) public view
    {
        TokenAmount[] memory tokens = new TokenAmount[](2);
        tokens[0] = TokenAmount({ token: token1, amount: 100 });
        tokens[1] = TokenAmount({ token: token2, amount: 200 });
        
        uint256 index = tokens.index_of( token3 );
        assertEq( index, TokenSearch.INDEX_NOT_FOUND );
    }

    function test_index_of_returns_not_found_for_empty_array( ) public view
    {
        TokenAmount[] memory tokens = new TokenAmount[](0);
        
        uint256 index = tokens.index_of( token1 );
        assertEq( index, TokenSearch.INDEX_NOT_FOUND );
    }

    function test_index_not_found_constant( ) public pure
    {
        assertEq( TokenSearch.INDEX_NOT_FOUND, type(uint256).max );
    }

    function test_index_of_handles_zero_amounts( ) public view
    {
        TokenAmount[] memory tokens = new TokenAmount[](2);
        tokens[0] = TokenAmount({ token: token1, amount: 0 }); // Zero amount
        tokens[1] = TokenAmount({ token: token2, amount: 200 });
        
        uint256 index = tokens.index_of( token1 );
        assertEq( index, 0 ); // Should still find it even with zero amount
    }
}