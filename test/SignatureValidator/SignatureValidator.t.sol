// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import { SignatureValidator } from "@BondRoute/utils/SignatureValidator.sol";
import { IERC1271 } from "@OpenZeppelin/interfaces/IERC1271.sol";

/**
 * @title MockEIP1271ValidWallet
 * @notice Mock wallet that always returns valid for any signature
 */
contract MockEIP1271ValidWallet is IERC1271 {

    function isValidSignature( bytes32, bytes calldata ) external pure returns ( bytes4 )
    {
        return IERC1271.isValidSignature.selector;
    }
}

/**
 * @title MockEIP1271InvalidWallet
 * @notice Mock wallet that always returns invalid
 */
contract MockEIP1271InvalidWallet is IERC1271 {

    function isValidSignature( bytes32, bytes calldata ) external pure returns ( bytes4 )
    {
        return bytes4(0xdeadbeef);
    }
}

/**
 * @title MockEIP1271RevertingWallet
 * @notice Mock wallet that reverts on isValidSignature
 */
contract MockEIP1271RevertingWallet is IERC1271 {

    function isValidSignature( bytes32, bytes calldata ) external pure returns ( bytes4 )
    {
        revert( "Not supported" );
    }
}

/**
 * @title SignatureValidatorTest
 * @notice Tests for SignatureValidator library (ECDSA and EIP-1271 signature validation)
 * @dev Implements ISignatureValidatorTests from TestManifest.sol
 */
contract SignatureValidatorTest is Test {

    MockEIP1271ValidWallet public valid_wallet;
    MockEIP1271InvalidWallet public invalid_wallet;
    MockEIP1271RevertingWallet public reverting_wallet;

    uint256 internal constant SIGNER_PRIVATE_KEY  =  0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    address internal signer;

    function setUp() public
    {
        valid_wallet      =  new MockEIP1271ValidWallet();
        invalid_wallet    =  new MockEIP1271InvalidWallet();
        reverting_wallet  =  new MockEIP1271RevertingWallet();

        signer  =  vm.addr( SIGNER_PRIVATE_KEY );
    }


    // ━━━━  is_valid_signature() - Input Validation  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_is_valid_signature_rejects_zero_hash() public view
    {
        bytes32 zero_hash  =  bytes32(0);
        bytes memory signature  =  _sign_hash( keccak256("test") );

        bool is_valid  =  SignatureValidator.is_valid_signature( signer, zero_hash, signature, false );

        assertFalse( is_valid, "Zero hash should always be rejected" );
    }

    function test_is_valid_signature_rejects_zero_signer() public view
    {
        bytes32 hash  =  keccak256("test");
        bytes memory signature  =  _sign_hash( hash );

        bool is_valid  =  SignatureValidator.is_valid_signature( address(0), hash, signature, false );

        assertFalse( is_valid, "Zero signer should always be rejected" );
    }

    function test_is_valid_signature_rejects_zero_hash_even_with_eip1271() public view
    {
        bytes32 zero_hash  =  bytes32(0);

        bool is_valid  =  SignatureValidator.is_valid_signature( address(valid_wallet), zero_hash, "", true );

        assertFalse( is_valid, "Zero hash should be rejected even for EIP-1271" );
    }

    function test_is_valid_signature_rejects_zero_signer_even_with_eip1271() public view
    {
        bytes32 hash  =  keccak256("test");

        bool is_valid  =  SignatureValidator.is_valid_signature( address(0), hash, "", true );

        assertFalse( is_valid, "Zero signer should be rejected even for EIP-1271" );
    }


    // ━━━━  is_valid_ecdsa_signature()  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_is_valid_ecdsa_signature_accepts_valid_signature() public view
    {
        bytes32 hash  =  keccak256("test message");
        bytes memory signature  =  _sign_hash( hash );

        bool is_valid  =  SignatureValidator.is_valid_ecdsa_signature( signer, hash, signature );

        assertTrue( is_valid, "Valid ECDSA signature should be accepted" );
    }

    function test_is_valid_ecdsa_signature_rejects_wrong_signer() public pure
    {
        bytes32 hash  =  keccak256("test message");
        bytes memory signature  =  _sign_hash( hash );
        address wrong_signer  =  address(0x9999);

        bool is_valid  =  SignatureValidator.is_valid_ecdsa_signature( wrong_signer, hash, signature );

        assertFalse( is_valid, "Signature from wrong signer should be rejected" );
    }

    function test_is_valid_ecdsa_signature_rejects_wrong_hash() public view
    {
        bytes32 hash  =  keccak256("test message");
        bytes32 wrong_hash  =  keccak256("different message");
        bytes memory signature  =  _sign_hash( hash );

        bool is_valid  =  SignatureValidator.is_valid_ecdsa_signature( signer, wrong_hash, signature );

        assertFalse( is_valid, "Signature for wrong hash should be rejected" );
    }

    function test_is_valid_ecdsa_signature_rejects_malformed_signature() public view
    {
        bytes32 hash  =  keccak256("test message");
        bytes memory malformed_signature  =  hex"deadbeef";

        bool is_valid  =  SignatureValidator.is_valid_ecdsa_signature( signer, hash, malformed_signature );

        assertFalse( is_valid, "Malformed signature should be rejected" );
    }

    function test_is_valid_ecdsa_signature_rejects_empty_signature() public view
    {
        bytes32 hash  =  keccak256("test message");
        bytes memory empty_signature  =  "";

        bool is_valid  =  SignatureValidator.is_valid_ecdsa_signature( signer, hash, empty_signature );

        assertFalse( is_valid, "Empty signature should be rejected for ECDSA" );
    }


    // ━━━━  is_valid_contract_signature() - Precompile Protection  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_is_valid_contract_signature_rejects_precompile_address() public view
    {
        bytes32 hash  =  keccak256("test");
        address precompile  =  address(0x01);  // ecrecover precompile

        bool is_valid  =  SignatureValidator.is_valid_contract_signature( precompile, hash, "" );

        assertFalse( is_valid, "Precompile address (0x01) should be rejected" );
    }

    function test_is_valid_contract_signature_rejects_high_precompile_address() public view
    {
        bytes32 hash  =  keccak256("test");
        address high_precompile  =  address(0xFFFF);  // Just below threshold

        bool is_valid  =  SignatureValidator.is_valid_contract_signature( high_precompile, hash, "" );

        assertFalse( is_valid, "High precompile address (0xFFFF) should be rejected" );
    }

    function test_is_valid_contract_signature_accepts_address_at_threshold() public
    {
        bytes32 hash  =  keccak256("test");

        // Deploy a valid wallet at an address >= 0x10000.
        MockEIP1271ValidWallet wallet  =  new MockEIP1271ValidWallet();
        assertTrue( uint160(address(wallet)) >= 0x10000, "Wallet should be deployed above threshold" );

        bool is_valid  =  SignatureValidator.is_valid_contract_signature( address(wallet), hash, "" );

        assertTrue( is_valid, "Address at or above threshold with valid contract should be accepted" );
    }


    // ━━━━  is_valid_contract_signature() - Code Check  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_is_valid_contract_signature_rejects_eoa() public view
    {
        bytes32 hash  =  keccak256("test");
        address eoa  =  address(0x123456789);  // Above threshold but no code

        bool is_valid  =  SignatureValidator.is_valid_contract_signature( eoa, hash, "" );

        assertFalse( is_valid, "EOA (no code) should be rejected for EIP-1271" );
    }

    function test_is_valid_contract_signature_rejects_destroyed_contract() public view
    {
        bytes32 hash  =  keccak256("test");

        // Deploy and then simulate destroyed contract by using an address with no code.
        address no_code_address  =  address(uint160(0x20000));

        bool is_valid  =  SignatureValidator.is_valid_contract_signature( no_code_address, hash, "" );

        assertFalse( is_valid, "Address with no code should be rejected" );
    }


    // ━━━━  is_valid_contract_signature() - EIP-1271 Validation  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_is_valid_contract_signature_accepts_valid_eip1271() public view
    {
        bytes32 hash  =  keccak256("test");

        bool is_valid  =  SignatureValidator.is_valid_contract_signature( address(valid_wallet), hash, "" );

        assertTrue( is_valid, "Valid EIP-1271 wallet should be accepted" );
    }

    function test_is_valid_contract_signature_rejects_invalid_magic_value() public view
    {
        bytes32 hash  =  keccak256("test");

        bool is_valid  =  SignatureValidator.is_valid_contract_signature( address(invalid_wallet), hash, "" );

        assertFalse( is_valid, "Invalid magic value should be rejected" );
    }

    function test_is_valid_contract_signature_rejects_reverting_contract() public view
    {
        bytes32 hash  =  keccak256("test");

        bool is_valid  =  SignatureValidator.is_valid_contract_signature( address(reverting_wallet), hash, "" );

        assertFalse( is_valid, "Reverting contract should be rejected" );
    }

    function test_is_valid_contract_signature_passes_signature_to_contract() public view
    {
        bytes32 hash  =  keccak256("test");
        bytes memory signature  =  hex"cafebabe";

        // The valid_wallet accepts any signature, so this just verifies no revert.
        bool is_valid  =  SignatureValidator.is_valid_contract_signature( address(valid_wallet), hash, signature );

        assertTrue( is_valid, "Signature should be passed to contract correctly" );
    }


    // ━━━━  is_valid_signature() - Integration (ECDSA Path)  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_is_valid_signature_ecdsa_path_accepts_valid() public view
    {
        bytes32 hash  =  keccak256("test message");
        bytes memory signature  =  _sign_hash( hash );

        bool is_valid  =  SignatureValidator.is_valid_signature( signer, hash, signature, false );

        assertTrue( is_valid, "Valid ECDSA signature via is_valid_signature should be accepted" );
    }

    function test_is_valid_signature_ecdsa_path_rejects_invalid() public view
    {
        bytes32 hash  =  keccak256("test message");
        bytes memory signature  =  hex"deadbeef";

        bool is_valid  =  SignatureValidator.is_valid_signature( signer, hash, signature, false );

        assertFalse( is_valid, "Invalid ECDSA signature via is_valid_signature should be rejected" );
    }


    // ━━━━  is_valid_signature() - Integration (EIP-1271 Path)  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function test_is_valid_signature_eip1271_path_accepts_valid() public view
    {
        bytes32 hash  =  keccak256("test");

        bool is_valid  =  SignatureValidator.is_valid_signature( address(valid_wallet), hash, "", true );

        assertTrue( is_valid, "Valid EIP-1271 wallet via is_valid_signature should be accepted" );
    }

    function test_is_valid_signature_eip1271_path_rejects_invalid() public view
    {
        bytes32 hash  =  keccak256("test");

        bool is_valid  =  SignatureValidator.is_valid_signature( address(invalid_wallet), hash, "", true );

        assertFalse( is_valid, "Invalid EIP-1271 wallet via is_valid_signature should be rejected" );
    }

    function test_is_valid_signature_eip1271_path_rejects_reverting() public view
    {
        bytes32 hash  =  keccak256("test");

        bool is_valid  =  SignatureValidator.is_valid_signature( address(reverting_wallet), hash, "", true );

        assertFalse( is_valid, "Reverting EIP-1271 wallet via is_valid_signature should be rejected" );
    }


    // ━━━━  HELPER FUNCTIONS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    function _sign_hash( bytes32 hash ) internal pure returns ( bytes memory )
    {
        ( uint8 v, bytes32 r, bytes32 s )  =  vm.sign( SIGNER_PRIVATE_KEY, hash );
        return abi.encodePacked( r, s, v );
    }
}
