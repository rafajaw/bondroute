// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { IERC20 } from "@OpenZeppelin/token/ERC20/IERC20.sol";
import { TokenAmount } from "../integrations/IBondRouteProtected.sol";



// ═══════════════════════════════════════════════════════════════════════════════
//                                    ERRORS
// ═══════════════════════════════════════════════════════════════════════════════

error Unauthorized( address requester );
error InsufficientFunds( address requester, address token, uint256 requested, uint256 available );
error TokenTransferFailed( address token, address from, address to, uint256 amount );
error PushedFundsOverflow( address token, address msg_sender, address source, uint256 tried_to_push_amount );



/**
 * @title IProvider
 * @notice Interface for BondRoute funding and context operations
 * @dev This interface provides funding operations during bond execution and context variable
 *      management for inter-call communication within the same bond execution.
 *      
 *      Funding Operations:
 *      - Get available funds
 *      - Pull/push/send tokens with transfer validation
 *      - All operations are context-aware and execution-scoped
 */
interface IProvider {

    /**
     * @notice Get available funds for the current execution
     * @return TokenAmount (tuple of `token` and `amount`) array with all available funds to be pulled or sent
     * @dev Shows net available amount (fees already deducted when funds were pushed)
     *      
     *      Reverts with error `Unauthorized` if called by any address other than the current called contract.
     */
    function get_available_funds( ) external view returns ( TokenAmount[] memory );

    /**
     * @notice Get available funds for a specific token during current execution
     * @param token The token address to check available funds for
     * @return amount The total amount of the specified token available for pulling
     * @dev Shows net available amount (fees already deducted when funds were pushed)
     *      
     *      Reverts with error `Unauthorized` if called by any address other than the current called contract.
     */
    function get_available_amount_for_token( IERC20 token ) external view returns ( uint256 amount );

    // ═══════════════════════════════════════════════════════════════════════════════
    //                              FUNDING OPERATIONS
    // ═══════════════════════════════════════════════════════════════════════════════
    //
    // IMPORTANT: BondRoute works as a VIRTUAL ESCROW with automatic fee collection!
    //
    // How it works:
    // 1. push_funds() - Records full amount in virtual escrow (no fee charged)
    // 2. pull_funds() - Performs actual transfers from sources using LIFO, charges 0.01% fee  
    // 3. send_funds() - Same as pull but sends to specified beneficiary, charges 0.01% fee
    // 4. At settlement - Accumulated fees are collected from original sources
    //
    // Fee and Escrow Example:
    // - ContractA pushes 1000 USDC → Full 1000 USDC available in virtual escrow
    // - ContractB pushes 500 USDC → Full 500 USDC available in virtual escrow  
    // - ContractC pulls 700 USDC → pays 0.01% fee (0.07 USDC), receives 699.93 USDC
    // - At settlement → 0.07 USDC fee collected from escrow
    //
    // CRITICAL: You MUST approve BondRoute when pushing! BondRoute will transferFrom you later.
    // Recommendation: Use infinite approval or carefully manage multiple push operations.
    //

    /**
     * @notice Add tokens to virtual escrow (no fee charged on push)
     * @param token The token to add to virtual escrow
     * @param amount The full amount to push (available for pulling/sending)
     * @dev NO PROTOCOL FEE: BondRoute records the full `amount` in virtual escrow.
     *      The entire `amount` becomes available for pulling/sending. Fees are only
     *      charged later during pull_funds() or send_funds() operations (0.01% each).
     *      
     *      CRITICAL: This does NOT transfer tokens immediately! It only records that you
     *      have committed this amount to the virtual escrow. The actual transfer happens later
     *      when another contract calls pull_funds() or send_funds(), or when remaining funds
     *      are sent to the user at the end of bond execution.
     *      
     *      EXAMPLE: push_funds(1000 USDC) makes full 1000 USDC available for pulling
     *      
     *      GAS EFFICIENCY: This design avoids unnecessary intermediate transfers, saving gas
     *      when multiple contracts need to coordinate token movements within the same bond.
     *      
     *      REQUIREMENTS:
     *      - You MUST approve BondRoute for at least 'amount' before calling this
     *      - Recommended: Use infinite approval to avoid approval overwrites
     *      - BondRoute will call transferFrom(msg.sender, recipient, amount) later
     *      
     *      Reverts with error `Unauthorized` if called by any address other than the current called contract.
     */
    function push_funds( IERC20 token, uint256 amount ) external;

    /**
     * @notice Pull tokens from virtual escrow (PERFORMS ACTUAL TRANSFERS)
     * @param token The token to pull from virtual escrow
     * @param amount The exact amount to pull (BondRoute charges 0.01% fee on this amount)
     * @return net_amount The calculated net amount after BondRoute's 0.01% fee deduction
     * @dev This performs actual token transfers using LIFO (last in, first out) from
     *      all sources that previously called push_funds() for this token.
     *      
     *      Fee Model: 0.01% fee is charged on the pulled amount and accumulated for later collection.
     *      You receive (amount - BondRoute fee) tokens from BondRoute's perspective.
     *      
     *      IMPORTANT: If the token has additional transfer fees, the actual amount
     *      received may be less than net_amount. This return value only reflects
     *      BondRoute's fee calculation, not the token's transfer behavior.
     *      
     *      Transfer Order Example:
     *      - SourceA pushed 300 USDC
     *      - SourceB pushed 700 USDC  
     *      - pull_funds(1000 USDC) → transfers 999.9 USDC (1000 - 0.1 fee), accumulates 0.1 USDC fee debt
     *      
     *      The net tokens are transferred directly to msg.sender (the calling contract).
     *      
     *      Reverts with error `Unauthorized` if called by any address other than the current called contract.
     *      Reverts with error `InsufficientFunds` if requested amount exceeds available virtual escrow balance.
     *      Reverts with error `TokenTransferFailed` if any underlying transferFrom call fails.
     */
    function pull_funds( IERC20 token, uint256 amount ) external returns ( uint256 net_amount );

    /**
     * @notice Send tokens from virtual escrow to beneficiary (PERFORMS ACTUAL TRANSFERS)
     * @param token The token to send from virtual escrow
     * @param amount The exact amount to send (BondRoute charges 0.01% fee on this amount)
     * @param beneficiary The address to receive the tokens
     * @return net_amount The calculated net amount after BondRoute's 0.01% fee deduction
     * @dev Same as pull_funds() but sends tokens to the specified beneficiary instead
     *      of msg.sender. Uses the same LIFO transfer mechanism from push_funds() sources.
     *      
     *      Fee Model: 0.01% fee is charged on the sent amount and accumulated for later collection.
     *      Beneficiary receives (amount - BondRoute fee) tokens from BondRoute's perspective.
     *      
     *      IMPORTANT: If the token has additional transfer fees, the actual amount
     *      received by beneficiary may be less than net_amount. This return value only reflects
     *      BondRoute's fee calculation, not the token's transfer behavior.
     *      
     *      SPECIAL FEATURE: This is the ONLY function that can be called directly from the 
     *      `calls` array in ExecutionData. This enables paying relayers or other beneficiaries
     *      sequentially during a bond execution.
     *      
     *      Example relayer payment:
     *      - send_funds(USDC, 100 USDC, relayer) → transfers 99.99 USDC (100 - 0.01 fee), accumulates 0.01 USDC fee debt
     *      
     *      Reverts with error `Unauthorized` if called by any address other than the current called contract.
     *      Reverts with error `InsufficientFunds` if requested amount exceeds available virtual escrow balance.
     *      Reverts with error `TokenTransferFailed` if any underlying transferFrom call fails.
     */
    function send_funds( IERC20 token, uint256 amount, address beneficiary ) external returns ( uint256 net_amount );

}