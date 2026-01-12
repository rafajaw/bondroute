// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

error Reentrancy( );

/**
 * @title ReentrancyLock
 * @dev Transient storage reentrancy protection with custom lock keys.
 *      Uses EIP-1153 TLOAD/TSTORE for gas-efficient locking.
 */
abstract contract ReentrancyLock {

    // *SECURITY*  -  Base slot for key to avoid colliding with compiler defined storage.
    uint256 private constant _BASE_SLOT  =  0x80e9dd96894090741e1b73e1f4f4099d2c83e03352e9eb9f6e4a38f5c1379e10;  // `uint256(keccak256("ReentrancyLock.base_slot")) - 1`

    modifier nonReentrant( bytes20 key )
    {
        bytes32 slot  =  bytes32(_BASE_SLOT) ^ bytes32(key);
        assembly ("memory-safe") {
            if tload( slot ) {
                mstore( 0x00, 0xab143c06 )  // Reentrancy()
                revert( 0x1c, 0x04 )
            }
            tstore( slot, 1 )
        }
        _;
        assembly ("memory-safe") {
            tstore( slot, 0 )
        }
    }

    modifier nonReentrantView( bytes20 key )
    {
        bytes32 slot  =  bytes32(_BASE_SLOT) ^ bytes32(key);
        assembly ("memory-safe") {
            if tload( slot ) {
                mstore( 0x00, 0xab143c06 )  // Reentrancy()
                revert( 0x1c, 0x04 )
            }
        }
        _;
    }

}
