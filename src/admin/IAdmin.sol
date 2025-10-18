// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;


// ═══════════════════════════════════════════════════════════════════════════════
//                                    EVENTS
// ═══════════════════════════════════════════════════════════════════════════════

/// @notice Emitted when admin successfully changes (completes 2-step process)
/// @param new_admin The address of the new admin
/// @param old_admin The address of the previous admin
event AdminChanged( address new_admin, address old_admin );

/// @notice Emitted when a new admin is appointed (starts 2-step process)
/// @param pending_admin The address appointed as pending admin
/// @param current_admin The address of the current admin who made the appointment
event AdminAppointed( address pending_admin, address current_admin );

/// @notice Emitted when protocol treasury address is changed
/// @param new_treasury The new treasury address
/// @param old_treasury The previous treasury address
event ProtocolTreasuryChanged( address new_treasury, address old_treasury );

/// @notice Emitted when expired bonds are liquidated by admin
/// @param liquidated_bond_ids Array of bond IDs that were liquidated
/// @param beneficiary_address Address that received the forfeited stakes
event BondsLiquidated( uint64[] liquidated_bond_ids, address beneficiary_address );


// ═══════════════════════════════════════════════════════════════════════════════
//                                  STRING CONSTANTS
// ═══════════════════════════════════════════════════════════════════════════════

string constant ADMIN_ZERO_ADDRESS          =   "Admin cannot be zero address";
string constant ADMIN_ACCESS_REQUIRED       =   "Admin access required";
string constant APPOINTED_ADMIN_REQUIRED    =   "Must be the appointed admin";
string constant INVALID_ADDRESS             =   "Invalid address";
string constant EMPTY_ARRAY                 =   "Empty array";

// ═══════════════════════════════════════════════════════════════════════════════
//                                    ERRORS
// ═══════════════════════════════════════════════════════════════════════════════

error Forbidden( string reason );
error TokenTransferFailed( address token, address from, address to, uint256 amount );


/**
 * @title IAdmin
 * @notice Interface for BondRoute administrative operations
 * @dev This interface handles admin management, treasury configuration, and bond liquidation.
 *      
 *      Admin Functions:
 *      - 2-step admin transfer process for security (appoint → accept)
 *      - Protocol treasury management for fee collection
 *      - Liquidation of expired bonds to claim forfeited stakes
  */
interface IAdmin {

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              ADMIN MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Appoint a new admin (2-step process for security)
     * @param new_admin Address of the proposed new admin
     * @dev Only current admin can call this. New admin must accept appointment.
     *      
     *      Reverts with error `Forbidden` if caller is not the current admin.
     *      Reverts with error `Forbidden` if `new_admin` is zero address.
     */
    function appoint_new_admin( address new_admin ) external;

    /**
     * @notice Accept admin appointment (completes 2-step process)
     * @dev Only the pending admin can call this to complete the transfer.
     *      
     *      Reverts with error `Forbidden` if caller is not the pending admin.
     */
    function accept_admin_appointment( ) external;

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              TREASURY MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Set the protocol treasury address
     * @param new_treasury Address to receive protocol fees
     * @dev Only admin can call this.
     *      
     *      Reverts with error `Forbidden` if caller is not the current admin.
     *      Reverts with error `Forbidden` if `new_treasury` is zero address.
     */
    function set_protocol_treasury( address new_treasury ) external;

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              BOND MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Liquidate expired bonds and transfer forfeited stakes to beneficiary
     * @param bond_ids Array of bond IDs to liquidate (must be expired beyond hard cap)
     * @param beneficiary_address Address to receive forfeited stakes
     * @dev Only admin can call this. Bonds must be expired beyond the hard cap.
     *      
     *      Reverts with error `BondNotFound` if `bond_id` does not exist.
     *      Reverts with error `Forbidden` if caller is not the current admin.
     *      Reverts with error `Forbidden` if `bond_ids` array is empty.
     *      Reverts with error `Forbidden` if `beneficiary_address` is zero address.
     *      Reverts with error `TokenTransferFailed` if any stake transfer fails.
     *      
     *      NOTE: Bond IDs that cannot be liquidated are silently ignored (not expired, no stake, etc.).
     */
    function liquidate_defaulted_bonds( uint64[] calldata bond_ids, address beneficiary_address ) external;

}