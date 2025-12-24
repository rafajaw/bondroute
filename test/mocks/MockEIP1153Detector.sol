// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title MockEIP1153Detector
 * @notice Mock EIP-1153 detector that can be configured to return SUPPORTED or NOT_SUPPORTED
 */
contract MockEIP1153Detector {

    uint256 private immutable _SUPPORT_CODE;

    constructor( bool should_support_transient_storage )
    {
        _SUPPORT_CODE  =  should_support_transient_storage  ?  0x1153  :  0x404;
    }

    function get_transient_storage_support( ) external view returns ( uint256 code )
    {
        return _SUPPORT_CODE;
    }
}
