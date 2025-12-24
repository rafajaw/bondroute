// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { SignatureValidator } from "@BondRoute/utils/SignatureValidator.sol";

contract MockEIP1271Wallet {

    address public owner;

    bytes4 constant internal MAGICVALUE  =  0x1626ba7e;

    constructor( address owner_ )
    {
        owner  =  owner_;
    }

    function isValidSignature( bytes32 hash, bytes calldata signature ) external view returns ( bytes4 magicValue )
    {
        bool is_valid  =  SignatureValidator.is_valid_signature( owner, hash, signature, false );

        if(  is_valid  )
        {
            return MAGICVALUE;
        }

        return bytes4(0);
    }

    receive() external payable {}
}
