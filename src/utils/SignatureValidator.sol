// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC1271 } from "@OpenZeppelin/interfaces/IERC1271.sol";
import { ECDSA } from "@OpenZeppelin/utils/cryptography/ECDSA.sol";


/**
 * @title SignatureValidator
 * @notice Library for validating signatures with EIP-1271 and ECDSA support.
 * @dev Provides clean separation between EIP-712 logic (in Core) and signature validation.
 */
library SignatureValidator {

    // *SECURITY*  -  Define a max contract address to prevent a potential precompiled contract exploitation.
    //             -  Ethereum mainnet has precompiled contracts 0x01-0x09, but other chains may have higher numbers.
    //             -  Using 1000 as safe threshold - no valid contract address exists within this range. Even if someone 
    //                manages to craft one, it would only prevent that specific contract from signature validation (fail-safe).
    uint160 private constant _MAX_PRECOMPILED_CONTRACT_ADDRESS  =  1_000;

    /**
     * @notice Validates signature with support for ECDSA and EIP-1271
     * @param signer The address that should have signed the hash
     * @param _hash The data hash to verify
     * @param signature The signature to validate
     * @param is_eip1271 true for EIP-1271 contract validation, false for direct ECDSA validation
     * @return bool True if signature is valid, false otherwise
     */
    function is_valid_signature( address signer, bytes32 _hash, bytes calldata signature, bool is_eip1271 ) internal view returns ( bool )
    {
        // *SECURITY*  -  Reject zero/empty values that could lead to signature validation bypasses.
        if(  _hash == bytes32(0)  )        return false;  // Zero hash should never validate.
        if(  signer == address(0)  )       return false;  // Zero address cannot be a valid signer.
        // *NOTE*  -  Empty signatures are allowed for EIP-1271 contracts that do hash-based validation.

        if(  is_eip1271  )  return is_valid_contract_signature( signer, _hash, signature );  // EIP-1271 validation.

        return is_valid_ecdsa_signature( signer, _hash, signature );  // Direct ECDSA validation for EOAs and EIP-7702 delegated accounts.
    }

    /**
     * @notice Validates ECDSA signature for EOAs and EIP-7702 delegated accounts
     * @param signer The expected signer address
     * @param _hash The data hash to verify
     * @param signature The signature to validate
     * @return bool True if signature is valid, false otherwise
     */
    function is_valid_ecdsa_signature( address signer, bytes32 _hash, bytes calldata signature ) internal pure returns ( bool )
    {
        ( address recovered_signer, ECDSA.RecoverError _error, )  =  ECDSA.tryRecover( _hash, signature );  // *SECURITY*  - `ECDSA.tryRecover` checks signature length.
        return  (  _error == ECDSA.RecoverError.NoError  &&  recovered_signer == signer  );
    }

    /**
     * @notice Validates contract signatures with EIP-1271 and precompiled protection
     * @param signer The expected signer contract address
     * @param _hash The data hash to verify
     * @param signature The signature to validate
     * @return bool True if signature is valid, false otherwise
     */
    function is_valid_contract_signature( address signer, bytes32 _hash, bytes calldata signature ) internal view returns ( bool )
    {
        // *SECURITY*  -  Block precompiled contract addresses to prevent potential exploitation.
        if(  uint160(signer) <= _MAX_PRECOMPILED_CONTRACT_ADDRESS  )  return false;
        
        // *SECURITY*  -  Only validate signatures for contracts that have code deployed.
        if(  signer.code.length == 0  )  return false;
        
        // *SECURITY*  -  Try EIP-1271 validation.
        try IERC1271(signer).isValidSignature( _hash, signature ) returns ( bytes4 magic_value )
        {
            return  ( magic_value == IERC1271.isValidSignature.selector );
        }
        catch
        {
            return false;  // Contract doesn't support EIP-1271 or validation failed.
        }
    }

}