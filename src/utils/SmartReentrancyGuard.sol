// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IEIP1153Detector, SUPPORTED, NOT_SUPPORTED } from "./eip1153/IEIP1153Detector.sol";

error Reentrancy( );

/**
 * @title SmartReentrancyGuard
 * @dev Smart reentrancy protection that automatically uses transient storage when available,
 *      falls back to persistent storage otherwise. Detection happens at deployment time.
 */
abstract contract SmartReentrancyGuard {

    bool private immutable _HAS_TRANSIENT_STORAGE_SUPPORT;

    // *SECURITY*  -  Base slot for key to avoid a user entering an invalid key like 0 and colliding with compiler defined storage.
    uint256 private constant _SMART_REENTRANCY_GUARD_BASE_SLOT  =  0x2ed53bc8675797c841da097b8f0c0baeba938f15b15be5ded2f2463c27f14c7e; // `uint256( keccak256( "SmartReentrancyGuard.base_slot" ) - 1 )`

    // *GAS SAVING*  -  Use 1/2 instead of 0/1 to avoid more expensive zero-to-nonzero storage writes.
    uint256 private constant _NOT_ENTERED   =  1;
    uint256 private constant _ENTERED       =  2;

    constructor( address eip1153_detector ) 
    {
        if(  eip1153_detector == address(0)  )        revert( "Missing eip1153_detector" );
        if(  eip1153_detector.code.length == 0  )     revert( "eip1153_detector not deployed" );

        try IEIP1153Detector(eip1153_detector).get_transient_storage_support( ) returns ( uint256 code )
        {
            if(  code == SUPPORTED  )
            {
                _HAS_TRANSIENT_STORAGE_SUPPORT  =  true;

                return;
            }
            else if(  code == NOT_SUPPORTED  )
            {
                _HAS_TRANSIENT_STORAGE_SUPPORT  =  false;
                
                return;
            }
        }
        catch
        {
        }

        // Revert if the `get_transient_storage_support` call failed or if the result code is anything other than SUPPORTED or NOT_SUPPORTED.
        
        revert ( "Bad eip1153_detector" );
    }

    modifier nonReentrant( bytes20 key )
    {
        _smart_enter_or_revert( key );

        _;

        _smart_exit( key );
    }

    function _smart_enter_or_revert( bytes20 key )
    private
    {
        bytes32 slot  =  bytes32(_SMART_REENTRANCY_GUARD_BASE_SLOT) ^ bytes32(key);

        if( _HAS_TRANSIENT_STORAGE_SUPPORT )
        {
            assembly ("memory-safe") {
                let current_state  :=  tload( slot )
                if eq( current_state, _ENTERED ) {
                    mstore( 0x00, 0xab143c06 )  // Reentrancy() selector
                    revert( 0x1c, 0x04 )
                }
                tstore( slot, _ENTERED )
            }
        }
        else
        {
            assembly ("memory-safe") {
                let current_state  :=  sload( slot )
                if eq( current_state, _ENTERED ) {
                    mstore( 0x00, 0xab143c06 )  // Reentrancy() selector
                    revert( 0x1c, 0x04 )
                }
                sstore( slot, _ENTERED )
            }
        }
    }

    function _smart_exit( bytes20 key )
    private
    {
        bytes32 slot  =  bytes32(_SMART_REENTRANCY_GUARD_BASE_SLOT) ^ bytes32(key);
        
        if( _HAS_TRANSIENT_STORAGE_SUPPORT )
        {
            assembly ("memory-safe") {
                tstore( slot, _NOT_ENTERED )
            }
        }
        else
        {
            assembly ("memory-safe") {
                sstore( slot, _NOT_ENTERED )
            }
        }
    }

    modifier nonReentrantView( bytes20 key )
    {
        _smart_revert_if_entered( key );

        _;
    }

    function _smart_revert_if_entered( bytes20 key )
    private view
    {
        bytes32 slot  =  bytes32(_SMART_REENTRANCY_GUARD_BASE_SLOT) ^ bytes32(key);

        if( _HAS_TRANSIENT_STORAGE_SUPPORT )
        {
            assembly ("memory-safe") {
                let current_state  :=  tload( slot )
                if eq( current_state, _ENTERED ) {
                    mstore( 0x00, 0xab143c06 )  // Reentrancy() selector
                    revert( 0x1c, 0x04 )
                }
            }
        }
        else
        {
            assembly ("memory-safe") {
                let current_state  :=  sload( slot )
                if eq( current_state, _ENTERED ) {
                    mstore( 0x00, 0xab143c06 )  // Reentrancy() selector
                    revert( 0x1c, 0x04 )
                }
            }
        }
    }

    // *UTILITY* - Check if reentrancy guard is currently entered.
    function _has_entered_reentrancy_guard( bytes20 key )
    internal view returns ( bool )
    {
        bytes32 slot  =  bytes32(_SMART_REENTRANCY_GUARD_BASE_SLOT) ^ bytes32(key);
        
        if( _HAS_TRANSIENT_STORAGE_SUPPORT )
        {
            assembly ("memory-safe") {
                let current_state  :=  tload( slot )
                let is_entered  :=  eq( current_state, _ENTERED )
                mstore( 0x00, is_entered )
                return( 0x00, 0x20 )
            }
        }
        
        assembly ("memory-safe") {
            let current_state  :=  sload( slot )
            let is_entered  :=  eq( current_state, _ENTERED )
            mstore( 0x00, is_entered )
            return( 0x00, 0x20 )
        }
    }

    // *UTILITY* - internal getter for transient storage support (EIP-1153) detection.
    function _has_transient_storage_support( )
    internal view returns ( bool )
    {
        return _HAS_TRANSIENT_STORAGE_SUPPORT;
    }

}