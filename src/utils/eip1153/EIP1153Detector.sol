// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;
import { IEIP1153Detector, SUPPORTED, NOT_SUPPORTED } from "./IEIP1153Detector.sol";


/**
 * @title EIP1153Detector
 * @notice Minimal contract for detecting EIP-1153 transient storage support
 */
contract EIP1153Detector is IEIP1153Detector {
    
    uint256 private constant _TEST_SLOT  =  uint256(keccak256( "EIP1153Detector.slot" )) - 1;
    // Final value:  0x356bfc17936158ccd057484b575f38b4293e757266bbd55b6e12fd5ccf067c06

    /**
     * @notice Tests if transient storage opcodes are supported
     * @dev Returns SUPPORTED if TLOAD/TSTORE workS and NOT_SUPPORTED if it does not.
     * @return code - either SUPPORTED or NOT_SUPPORTED.
     */
    function get_transient_storage_support( ) external returns ( uint256 code )
    {
        try this._issue_tstore_internal( )
        {
            return SUPPORTED;
        }
        catch
        {
            return NOT_SUPPORTED;
        }
    }
    
    /**
     * @notice Internal function.
     * @dev To be called by EIP1153Detector itself.
     */
    function _issue_tstore_internal( ) external
    {
        uint256 slot        =   _TEST_SLOT;
        assembly ("memory-safe") {
            tstore( slot, slot )
        }
    }

    /**
     * @notice Reject possibly accidental native token deposits
     */
    receive( ) external payable
    {
        revert( "Possibly accidental deposit" );
    }
    
}