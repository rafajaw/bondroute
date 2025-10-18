// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/*


        ██████╗  ██████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗   ██╗████████╗███████╗
        ██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
        ██████╔╝██║   ██║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║   ██║   ██║   █████╗  
        ██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  
        ██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗
        ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝

        01000010 01101111 01101110 01100100 01010010 01101111 01110101 01110100 01100101

*/

import { User } from "./user/User.sol";


/**
 * @title BondRoute
 * @notice The main BondRoute contract providing MEV protection through commit-reveal bonds
 * @dev This contract combines all layers: Storage -> Core -> Admin -> Provider -> User
 */
contract BondRoute is User {

    /**
     * @notice Initialize BondRoute with admin and EIP-1153 detector
     * @param initial_admin Address that will have administrative privileges
     * @param eip1153_detector Address of contract to detect EIP-1153 transient storage support
     */
    constructor( address initial_admin, address eip1153_detector ) User( initial_admin, eip1153_detector ) { }

    /**
     * @notice Returns the domain separator for EIP-712 signature verification
     * @return bytes32 The domain separator hash
     */
    function DOMAIN_SEPARATOR( ) external view returns ( bytes32 )
    {
        return _domainSeparatorV4( );
    }

    /**
     * @notice Reject possibly accidental native token deposits
     */
    receive( ) external payable
    {
        revert( "Possibly accidental deposit" );
    }

}