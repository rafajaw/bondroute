// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;


uint256 constant SUPPORTED          =   0x1153;
uint256 constant NOT_SUPPORTED      =   0x404;

/**
 * @title IEIP1153Detector
 * @notice Interface for detecting EIP-1153 transient storage support on the current chain
 * @dev Used by SmartReentrancyGuard to determine whether to use transient storage (gas efficient)
 *      or fall back to persistent storage for reentrancy protection.
 *      
 *      Detection Process:
 *      1. Contract attempts to execute TSTORE opcode
 *      2. Returns SUPPORTED (0x1153) if successful
 *      3. Returns NOT_SUPPORTED (0x404) if opcodes unavailable
 *      
 *      This enables BondRoute to automatically optimize for each chain's capabilities
 *      without requiring manual configuration or chain-specific deployments.
 */
interface IEIP1153Detector {
    /**
     * @notice Tests if transient storage opcodes (TLOAD/TSTORE) are supported on this chain
     * @return code Either SUPPORTED (0x1153) or NOT_SUPPORTED (0x404)
     * @dev This function modifies state by attempting to use TSTORE, so it cannot be view/pure.
     *      The detection is performed at deployment time by SmartReentrancyGuard constructor.
     */
    function get_transient_storage_support( )
    external returns ( uint256 code );
}
