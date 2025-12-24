// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/*

        ██████╗  ██████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗   ██╗████████╗███████╗
        ██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
        ██████╔╝██║   ██║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║   ██║   ██║   █████╗  
        ██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  
        ██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗
        ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
                              CREATE • EXECUTE • OR GET REKT

*/

import { Sweeper } from "./Sweeper.sol";

/**
 * @title BondRoute
 * @notice Main BondRoute contract - minimal entry point
 * @dev Inherits complete layered architecture: Storage -> Core -> User -> Provider -> Sweeper -> BondRoute
 */
contract BondRoute is Sweeper {

    /**
     * @notice Initialize BondRoute with sweeper and EIP-1153 detector
     * @param sweeper Address that will manage expired bonds and accumulated tips
     * @param eip1153_detector Contract address to detect EIP-1153 support for gas optimization
     * @dev Reverts with `Invalid("sweeper", 0)` if sweeper is zero address
     * @dev Reverts with `"Bad eip1153_detector"` if eip1153_detector is invalid or doesn't implement the detection interface
     */
    constructor( address sweeper, address eip1153_detector )
    Sweeper( sweeper, eip1153_detector ) { }

    /**
     * @notice Returns the domain separator for EIP-712 signature verification
     * @dev Standard EIP-712 interface
     */
    function DOMAIN_SEPARATOR( )
    external view returns ( bytes32 )
    {
        return _domainSeparatorV4( );
    }

    /**
     * @notice Reject accidental native token deposits - use tip() to donate
     */
    receive( )
    external  payable
    {
        revert( "Use tip() to donate" );
    }
}