// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IAdmin } from "./admin/IAdmin.sol";
import { IProvider } from "./provider/IProvider.sol";
import { IUser } from "./user/IUser.sol";


/**
 * @title IBondRoute
 * @notice Complete interface for the BondRoute MEV protection protocol
 * @dev This is the main protocol singleton that combines all BondRoute functionality.
 *      
 *      How BondRoute Works:
 *      BondRoute provides MEV protection through a commit-reveal scheme where users:
 *      1. Create bonds with cryptographic commitment proofs (optionally with staked tokens)
 *      2. Execute bonds by revealing the commitment data and calling protected contracts
 *      3. Protected contracts receive execution context and can pull/push funds during execution
 *      
 *      MEV Protection Mechanisms:
 *      The protocol prevents front-running, sandwich attacks, and other MEV exploitation by:
 *      - Requiring pre-commitment to transaction parameters before execution
 *      - Enforcing time delays between commitment and execution
 *      - Validating that execution matches the original commitment proof
 *      - Detecting and preventing selective execution (bond-picking) attacks
 *      
 *      Key Technical Features:
 *      - Cross-chain deterministic deployments using vanity addresses
 *      - Smart reentrancy protection with EIP-1153 transient storage support
 *      - Optimized for low gas usage
 *      - Comprehensive signature validation (ECDSA + EIP-1271)
 *      - Virtual escrow system with LIFO fund management
 *      
 *      For Integrators:
 *      To integrate your contract with BondRoute protection, create a contract that inherits
 *      from the `BondRouteProtected` abstract contract (BondRouteProtected.sol), which provides
 *      all the necessary wrappers and helper functions. Do not interact with this interface
 *      directly. This interface is for the main BondRoute singleton that users interact with.
 *      
 *      Deployment:
 *      BondRoute is deployed to the same vanity address across all supported chains using
 *      identical bytecode, enabling deterministic cross-chain contract addresses.
 *      
 * @author BondRoute Protocol Team
 */
interface IBondRoute is IAdmin, IProvider, IUser {
    
    // ═══════════════════════════════════════════════════════════════════════════════
    //                              INHERITED INTERFACES
    // ═══════════════════════════════════════════════════════════════════════════════
    //
    // This interface inherits all functions from three specialized interfaces:
    //
    // 👤 IUser: Bond lifecycle operations (end-user functions)
    //    - `create_bond()` (with/without staking) (commitment phase)
    //    - `execute_bond()` / `execute_bond_on_behalf_of_user()` (reveal phase + execution)
    //    - `__OFF_CHAIN__get_bond()` / `__OFF_CHAIN__calculate_commitment_proof()` (utilities)
    //
    // 💰 IProvider: Funding operations (protected contract use)
    //    - `get_available_funds()` / `get_available_amount_for_token()` (query virtual escrow)
    //    - `pull_funds()` / `push_funds()` / `send_funds()` (virtual escrow operations)
    //    
    //    ⚠️  NOTE: Provider functions are only callable by the current called contract during bond execution
    //
    // 📋 IAdmin: Administrative operations
    //    - `appoint_new_admin()` / `accept_admin_appointment()` (2-step process)
    //    - `set_protocol_treasury()` (fee collection destination)
    //    - `liquidate_defaulted_bonds()` (claim forfeited stakes)
    //
    // Architecture Benefits:
    // The layered design ensures clear separation of concerns while providing a unified
    // interface. Each layer has specific access controls and use cases, preventing
    // unauthorized access to sensitive operations while maintaining usability.
    //

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              PROTOCOL UTILITIES
    // ═══════════════════════════════════════════════════════════════════════════════

    /**
     * @notice Returns the domain separator for EIP-712 signature verification
     * @return bytes32 The domain separator hash used for typed data signing
     * @dev Required for off-chain signature generation when using `execute_bond_on_behalf_of_user()`.
     *      This value is used to construct the EIP-712 typed data hash for user authorization signatures.
     */
    function DOMAIN_SEPARATOR( ) external view returns ( bytes32 );

}