// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { ERC20 } from "@OpenZeppelin/token/ERC20/ERC20.sol";

/**
 * @title ERC20MockOZ
 * @notice Proper ERC20 mock based on OpenZeppelin for realistic gas benchmarking
 * @dev Uses OZ ERC20 for accurate gas characteristics in benchmarks
 */
contract ERC20MockOZ is ERC20 {

    uint8 private immutable _decimals;

    constructor( string memory name, string memory symbol, uint8 decimals_ )
    ERC20( name, symbol )
    {
        _decimals  =  decimals_;
    }

    function decimals( ) public view override returns ( uint8 )
    {
        return _decimals;
    }

    function mint( address to, uint256 amount ) external
    {
        _mint( to, amount );
    }

    function burn( address from, uint256 amount ) external
    {
        _burn( from, amount );
    }
}
