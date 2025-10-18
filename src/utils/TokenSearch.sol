// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20 } from "@OpenZeppelin/token/ERC20/IERC20.sol";
import { TokenAmount } from "@BondRoute/integrations/IBondRouteProtected.sol";


library TokenSearch {

    uint256 constant INDEX_NOT_FOUND       =   type(uint256).max;

    function index_of( TokenAmount[] memory tokens, IERC20 token ) internal pure returns ( uint256 )
    {
        for(  uint i = 0  ;  i < tokens.length  ;  i++  )
        {
            if(  address(tokens[ i ].token) == address(token)  )  return i;
        }
        return INDEX_NOT_FOUND;
    }
}