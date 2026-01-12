// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/**
 * @title TestManifest
 * @notice Central registry of ALL test functions across the test suite
 * @dev This file provides a bird's-eye view of test coverage without implementation pollution.
 *      Each test contract implements a subset of these tests as documented in their sections.
 *
 *      NAMING CONVENTION:
 *      - test_<function>_<scenario>_<expected_outcome>
 *      - testFuzz_<function>_<property>
 *      - testInvariant_<property>
 */


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// STORAGE.SOL - Bond state management and gas optimization
// Implemented in: test/Storage/Storage.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IStorageTests {
    // ─── Bond Creation ────────────────────────────────────────────────────────────
    function test_create_bond_basic() external;
    function test_create_bond_stores_correct_data() external;
    function test_create_bond_fee_on_transfer() external;
    function test_create_bond_bonus_on_transfer() external;
    function test_create_bond_reverts_if_already_exists() external;
    function test_create_bond_reverts_on_excessive_fee() external;
    function test_create_bond_reverts_on_excessive_bonus() external;
    function test_create_bond_zero_stake_allowed() external;
    function test_create_bond_with_native_token() external;
    function test_create_bond_different_tokens_same_commitment() external;

    // ─── Bond Retrieval ───────────────────────────────────────────────────────────
    function test_get_bond_info_reverts_if_not_found() external;
    function test_get_bond_info_different_stakes_different_bonds() external;
    function test_get_bond_info_returns_accurate_delta() external;
    function test_get_bond_info_zero_delta_reconstruction() external;

    // ─── Bond State Management ────────────────────────────────────────────────────
    function test_set_bond_as_executed() external;
    function test_set_bond_as_failed() external;
    function test_set_bond_as_liquidated() external;
    function test_bond_status_persist_across_reads() external;

    // ─── Bit Packing Validation ───────────────────────────────────────────────────
    function test_bit_packing_max_timestamp() external;
    function test_bit_packing_max_block_number() external;
    function test_bit_packing_max_delta_positive() external;
    function test_bit_packing_max_delta_negative() external;
    function test_bit_packing_no_collision_between_fields() external;
    function test_bond_key_unaffected_by_dirty_address_upper_bits() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// HASHLIB.SOL - Optimized hashing utilities with assembly
// Implemented in: test/HashLib/HashLib.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IHashLibTests {
    // ─── hash_fundings (Assembly Validation) ─────────────────────────────────────
    function test_hash_fundings_assembly_matches_solidity_single() external;
    function test_hash_fundings_assembly_matches_solidity_multiple() external;
    function test_hash_fundings_empty_returns_zero() external;
    function test_hash_fundings_deterministic() external;
    function test_hash_fundings_different_order_different_hash() external;

    // ─── calc_bond_key ───────────────────────────────────────────────────────────
    function test_calc_bond_key_assembly_matches_solidity() external;
    function test_calc_bond_key_deterministic() external;
    function test_calc_bond_key_different_commitment_different_key() external;
    function test_calc_bond_key_different_stake_different_key() external;

    // ─── calc_context_hash ───────────────────────────────────────────────────────
    function test_calc_context_hash_assembly_matches_solidity() external;
    function test_calc_context_hash_deterministic() external;
    function test_calc_context_hash_different_user_different_hash() external;
    function test_calc_context_hash_different_protocol_different_hash() external;

    // ─── hash_stake_for_eip712 ───────────────────────────────────────────────────
    function test_hash_stake_for_eip712_assembly_matches_solidity() external;
    function test_hash_stake_for_eip712_deterministic() external;
    function test_hash_stake_for_eip712_different_token_different_hash() external;
    function test_hash_stake_for_eip712_different_amount_different_hash() external;
    function test_hash_stake_for_eip712_includes_type_hash() external;

    // ─── hash_fundings_for_eip712 ────────────────────────────────────────────────
    function test_hash_fundings_for_eip712_assembly_matches_solidity() external;
    function test_hash_fundings_for_eip712_single() external;
    function test_hash_fundings_for_eip712_empty() external;
    function test_hash_fundings_for_eip712_deterministic() external;
    function test_hash_fundings_for_eip712_different_order_different_hash() external;

    // ─── calc_commitment_hash ────────────────────────────────────────────────────
    function test_calc_commitment_hash_deterministic() external;
    function test_calc_commitment_hash_different_user_different_hash() external;
    function test_calc_commitment_hash_different_salt_different_hash() external;
    function test_calc_commitment_hash_includes_chain_id() external;
    function test_calc_commitment_hash_different_call_different_hash() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// CORE.SOL - Bond execution logic and EIP-712 signing
// Implemented in: test/Core/Core.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface ICoreTests {
    // ─── Bond Execution: Success Paths ────────────────────────────────────────────
    function test_execute_bond_basic_success() external;
    function test_execute_bond_with_native_stake() external;
    function test_execute_bond_with_native_funding() external;
    function test_execute_bond_with_multiple_fundings() external;
    function test_execute_bond_stake_refunded_correctly() external;
    function test_execute_bond_unused_msg_value_refunded() external;
    function test_execute_bond_protocol_called_correctly() external;

    // ─── Bond Execution: Validation Failures ──────────────────────────────────────
    function test_execute_bond_reverts_if_bond_not_found() external;
    function test_execute_bond_reverts_if_already_executed() external;
    function test_execute_bond_reverts_if_already_liquidated() external;
    function test_execute_bond_reverts_if_same_block() external;
    function test_execute_bond_reverts_if_expired() external;
    function test_execute_bond_reverts_on_insufficient_native_funding() external;
    function test_execute_bond_handles_invalid_validation_gracefully() external;
    function test_execute_bond_graceful_on_duplicate_fundings() external;
    function test_execute_bond_graceful_on_zero_amount_funding() external;
    function test_execute_bond_graceful_on_unsupported_protocol() external;
    function test_execute_bond_invalid_validation_returns_native_stake() external;
    function test_execute_bond_invalid_validation_returns_msg_value() external;

    // ─── Bond Execution: Protocol Interactions ────────────────────────────────────
    function test_execute_bond_protocol_revert_handled() external;
    function test_execute_bond_protocol_out_of_gas_detected() external;
    function test_execute_bond_protocol_empty_revert_handled() external;
    function test_execute_bond_context_cleared_after_success() external;
    function test_execute_bond_context_cleared_after_protocol_revert() external;

    // ─── Bond Execution: Return Value Testing ────────────────────────────────────
    function test_execute_bond_returns_executed_status_on_success() external;
    function test_execute_bond_returns_invalid_bond_on_validation_failure() external;
    function test_execute_bond_returns_protocol_reverted_on_revert() external;
    function test_execute_bond_returns_protocol_output_on_success() external;
    function test_execute_bond_returns_error_data_on_protocol_revert() external;
    function test_execute_bond_returns_validation_reason_on_invalid_bond() external;
    function test_execute_bond_output_composability_with_abi_decode() external;

    // ─── EIP-712 Signature Validation ─────────────────────────────────────────────
    function test_get_signing_data_uses_default_type_when_no_custom_info() external;
    function test_get_signing_data_uses_custom_type_when_provided() external;
    function test_signing_data_validates_typed_string_prefix() external;
    function test_signing_data_validates_TokenAmount_definition() external;
    function test_signing_data_rejects_malicious_prefix() external;
    function test_signing_data_rejects_malicious_TokenAmount() external;
    function test_signing_data_handles_protocol_revert_gracefully() external;
    function test_signing_data_domain_separator_updates_on_chain_fork() external;

    // ─── Edge Cases ───────────────────────────────────────────────────────────────
    function test_execute_bond_exactly_at_expiration() external;
    function test_execute_bond_one_second_before_expiration() external;
    function test_execute_bond_max_fundings_allowed() external;
    function test_execute_bond_commitment_hash_collision_resistant() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// USER.SOL - User-facing bond operations
// Implemented in: test/User/User.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IUserTests {
    // ─── create_bond() ────────────────────────────────────────────────────────────
    function test_create_bond_with_erc20_stake() external;
    function test_create_bond_with_native_stake() external;
    function test_create_bond_emits_correct_event() external;
    function test_create_bond_stores_correct_data() external;
    function test_create_bond_transfers_stake_from_user() external;
    function test_create_bond_handles_fee_on_transfer_tokens() external;
    function test_create_bond_reverts_on_zero_commitment_hash() external;
    function test_create_bond_reverts_on_native_amount_mismatch() external;
    function test_create_bond_reverts_on_zero_erc20_stake() external;
    function test_create_bond_reverts_on_native_sent_with_erc20_stake() external;
    function test_create_bond_reverts_on_reentrancy() external;

    // ─── execute_bond() ───────────────────────────────────────────────────────────
    function test_execute_bond_success_path() external;
    function test_execute_bond_with_msg_value() external;
    function test_execute_bond_delegates_to_internal() external;
    function test_execute_bond_reverts_on_reentrancy() external;

    // ─── execute_bond() Return Values ─────────────────────────────────────────────
    function test_execute_bond_returns_status_and_output() external;
    function test_execute_bond_output_matches_protocol_return() external;

    // ─── execute_bond_as() (Relayer Flow) ────────────────────────────────────────
    function test_execute_bond_as_with_valid_signature() external;
    function test_execute_bond_as_with_eip1271_signature() external;
    function test_execute_bond_as_refunds_to_user_not_relayer() external;
    function test_execute_bond_as_relayer_fronts_stake() external;
    function test_execute_bond_as_relayer_fronts_native_funding() external;
    function test_execute_bond_as_reverts_on_invalid_signature() external;
    function test_execute_bond_as_reverts_on_wrong_signer() external;
    function test_execute_bond_as_reverts_on_reentrancy() external;

    // ─── execute_bond_as() Return Values ──────────────────────────────────────────
    function test_execute_bond_as_returns_status_and_output() external;
    function test_execute_bond_as_output_composable_for_smart_wallets() external;

    // ─── Off-Chain Helper Functions ───────────────────────────────────────────────
    function test_calc_commitment_hash_deterministic() external;
    function test_calc_commitment_hash_different_users_different_hash() external;
    function test_calc_commitment_hash_different_salt_different_hash() external;
    function test_calc_commitment_hash_reverts_on_zero_user() external;
    function test_calc_commitment_hash_reverts_on_invalid_execution() external;
    function test_get_bond_info_helper_matches_internal() external;
    function test_get_signing_info_returns_complete_data() external;
    function test_get_signing_info_domain_matches_deployed() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// PROVIDER.SOL - Service layer for BondRoute-protected contracts
// Implemented in: test/Provider/Provider.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IProviderTests {
    // ─── announce_protocol() ──────────────────────────────────────────────────────
    function test_announce_protocol_emits_event() external;
    function test_announce_protocol_accepts_valid_name() external;
    function test_announce_protocol_accepts_empty_description() external;
    function test_announce_protocol_reverts_on_empty_name() external;
    function test_announce_protocol_reverts_on_name_too_long() external;
    function test_announce_protocol_reverts_on_description_too_long() external;

    // ─── transfer_funding() - Basic ERC20 ─────────────────────────────────────────
    function test_transfer_funding_pulls_erc20_from_user() external;
    function test_transfer_funding_updates_context_hash() external;
    function test_transfer_funding_returns_updated_amounts() external;

    // ─── transfer_funding() - Smart Stake Consumption ─────────────────────────────
    function test_transfer_funding_uses_stake_first() external;
    function test_transfer_funding_erc20_with_matching_stake() external;
    function test_transfer_funding_partial_from_stake_partial_from_user() external;

    // ─── transfer_funding() - Native Token ────────────────────────────────────────
    function test_transfer_funding_uses_msg_value_for_native() external;
    function test_transfer_funding_native_with_native_stake() external;

    // ─── transfer_funding() - Multiple Calls ──────────────────────────────────────
    function test_transfer_funding_multiple_calls_same_token() external;
    function test_transfer_funding_depletes_funding_correctly() external;

    // ─── transfer_funding() - Validation ──────────────────────────────────────────
    function test_transfer_funding_reverts_on_context_mismatch() external;
    function test_transfer_funding_reverts_on_insufficient_funding() external;
    function test_transfer_funding_reverts_on_token_not_in_fundings() external;
    function test_transfer_funding_reverts_on_self_transfer() external;
    function test_transfer_funding_zero_amount_returns_early() external;

    // ─── transfer_funding() - Held State Updates ──────────────────────────────────
    function test_transfer_funding_updates_held_state() external;

    // ─── transfer_funding() - Stake + Native Combinations ─────────────────────────
    function test_transfer_funding_stake_greater_than_funding_erc20() external;
    function test_transfer_funding_stake_less_than_funding_erc20() external;
    function test_transfer_funding_consumed_less_than_stake() external;
    function test_transfer_funding_consumed_greater_than_stake() external;
    function test_transfer_funding_native_msg_value_fully_consumed() external;
    function test_transfer_funding_native_msg_value_partially_consumed() external;
    function test_transfer_funding_native_stake_greater_than_funding() external;
    function test_transfer_funding_native_stake_less_than_funding() external;
    function test_transfer_funding_native_stake_and_msg_value_partial_consumption() external;

    // ─── Reentrancy ───────────────────────────────────────────────────────────────
    function test_transfer_funding_reverts_on_reentrancy() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// COLLECTOR.SOL - Expired bond liquidation and airdrop management
// Implemented in: test/Collector/Collector.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface ICollectorTests {
    // ─── Collector Role Management ──────────────────────────────────────────────────
    function test_constructor_sets_initial_collector() external;
    function test_constructor_reverts_on_zero_collector() external;
    function test_appoint_new_collector_success() external;
    function test_appoint_new_collector_emits_event() external;
    function test_appoint_new_collector_reverts_if_not_collector() external;
    function test_appoint_new_collector_reverts_on_zero_address() external;
    function test_claim_collector_role_success() external;
    function test_claim_collector_role_emits_event() external;
    function test_claim_collector_role_reverts_if_not_pending() external;
    function test_claim_collector_role_clears_pending() external;

    // ─── liquidate_expired_bonds() ────────────────────────────────────────────────
    function test_liquidate_expired_bonds_single_bond() external;
    function test_liquidate_expired_bonds_with_native_stake() external;
    function test_liquidate_expired_bonds_multiple_bonds() external;
    function test_liquidate_expired_bonds_emits_events() external;
    function test_liquidate_expired_bonds_transfers_stakes() external;
    function test_liquidate_expired_bonds_marks_as_liquidated() external;
    function test_liquidate_expired_bonds_reverts_if_not_collector() external;
    function test_liquidate_expired_bonds_reverts_on_zero_recipient() external;
    function test_liquidate_expired_bonds_reverts_on_array_mismatch() external;
    function test_liquidate_expired_bonds_reverts_if_not_expired() external;
    function test_liquidate_expired_bonds_reverts_if_already_executed() external;
    function test_liquidate_expired_bonds_reverts_if_already_liquidated() external;
    function test_liquidate_expired_bonds_reverts_on_reentrancy() external;
    function test_liquidate_expired_bonds_exactly_at_expiration() external;
    function test_liquidate_expired_bonds_one_second_after_expiration() external;

    // ─── airdrop() ─────────────────────────────────────────────────────────────────
    function test_airdrop_with_erc20() external;
    function test_airdrop_with_native() external;
    function test_airdrop_with_message() external;
    function test_airdrop_without_message() external;
    function test_airdrop_emits_event() external;
    function test_airdrop_accumulates_correctly() external;
    function test_airdrop_handles_fee_on_transfer() external;
    function test_airdrop_gracefully_handles_zero_amount() external;
    function test_airdrop_truncates_long_message() external;
    function test_airdrop_reverts_on_native_amount_mismatch() external;
    function test_airdrop_reverts_on_reentrancy() external;

    // ─── notify_protocol_airdrop() ────────────────────────────────────────────────────────
    function test_notify_protocol_airdrop_success() external;
    function test_notify_protocol_airdrop_with_message() external;
    function test_notify_protocol_airdrop_emits_event() external;
    function test_notify_protocol_airdrop_silent_mode_no_event() external;
    function test_notify_protocol_airdrop_accumulates_correctly() external;
    function test_notify_protocol_airdrop_gracefully_handles_zero_amount() external;

    // ─── get_claimable_airdrop_amount() ─────────────────────────────────────────────────────
    function test_get_claimable_airdrop_amount_returns_zero_when_none() external;
    function test_get_claimable_airdrop_returns_zero_when_only_dust() external;
    function test_get_claimable_airdrop_excludes_dust() external;
    function test_get_claimable_airdrop_multiple_tokens() external;

    // ─── claim_airdrops() ─────────────────────────────────────────────────
    function test_claim_airdrops_single_token() external;
    function test_claim_airdrops_multiple_tokens() external;
    function test_claim_airdrops_leaves_dust() external;
    function test_claim_airdrops_emits_events() external;
    function test_claim_airdrops_transfers_correctly() external;
    function test_claim_airdrops_reverts_if_not_collector() external;
    function test_claim_airdrops_reverts_on_zero_recipient() external;
    function test_claim_airdrops_reverts_on_empty_array() external;
    function test_claim_airdrops_reverts_on_reentrancy() external;
    function test_claim_airdrops_skips_tokens_with_no_airdrops() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// BONDROUTE.SOL - Main entry point and integration
// Implemented in: test/BondRoute/BondRoute.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IBondRouteTests {
    // ─── Deployment ───────────────────────────────────────────────────────────────
    function test_constructor_success() external;
    function test_constructor_reverts_on_zero_collector() external;

    // ─── DOMAIN_SEPARATOR() ───────────────────────────────────────────────────────
    function test_domain_separator_returns_correct_value() external;
    function test_domain_separator_matches_eip712_domain() external;

    // ─── receive() ────────────────────────────────────────────────────────────────
    function test_receive_reverts() external;

    // ─── Full Integration: Happy Path ─────────────────────────────────────────────
    function test_integration_create_and_execute_basic() external;
    function test_integration_create_and_execute_with_funding() external;
    function test_integration_create_wait_execute() external;
    function test_integration_create_expire_liquidate() external;
    function test_integration_multiple_bonds_same_user() external;
    function test_integration_multiple_bonds_different_users() external;

    // ─── Full Integration: Relayer Flow ───────────────────────────────────────────
    function test_integration_relayer_fronts_stake() external;
    function test_integration_relayer_fronts_native() external;
    function test_integration_relayer_user_receives_refunds() external;
    function test_integration_relayer_gasless_execution() external;

    // ─── Full Integration: Return Value Verification ──────────────────────────────
    function test_integration_execute_returns_protocol_output() external;
    function test_integration_failed_bond_returns_error_data() external;
    function test_integration_smart_wallet_can_decode_output() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// BONDROUTE_PROTECTED.SOL - Integration library for protocols
// Implemented in: test/BondRouteProtected/BondRouteProtected.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IBondRouteProtectedTests {
    // ─── Constructor ──────────────────────────────────────────────────────────────
    function test_constructor_announces_protocol() external;
    function test_constructor_skips_announcement_on_empty_name() external;

    // ─── BondRoute_entry_point() ──────────────────────────────────────────────────
    function test_entry_point_only_callable_by_bondroute() external;
    function test_entry_point_validates_context() external;
    function test_entry_point_delegates_to_target() external;
    function test_entry_point_propagates_reverts() external;
    function test_entry_point_preserves_msg_sender() external;

    // ─── BondRoute_initialize() ───────────────────────────────────────────────────
    function test_initialize_extracts_context() external;
    function test_initialize_only_callable_by_bondroute() external;

    // ─── BondRoute_validate() ─────────────────────────────────────────────────────
    function test_validate_enforces_min_creation_time() external;
    function test_validate_enforces_max_creation_time() external;
    function test_validate_enforces_min_execution_delay() external;
    function test_validate_enforces_max_execution_delay() external;
    function test_validate_enforces_min_execution_time() external;
    function test_validate_enforces_max_execution_time() external;
    function test_validate_enforces_stake_token() external;
    function test_validate_enforces_stake_amount() external;
    function test_validate_enforces_funding_requirements() external;
    function test_validate_reverts_when_funding_token_not_found() external;
    function test_validate_allows_excess_stake() external;
    function test_validate_allows_excess_funding() external;
    function test_validate_reverts_with_PossiblyBondFarming() external;

    // ─── Multi-Function Support ───────────────────────────────────────────────────
    function test_multiple_protected_functions_registered() external;
    function test_protected_add_liquidity_pulls_both_tokens() external;
    function test_protected_add_liquidity_context_extraction() external;

    // ─── FundingsLib ──────────────────────────────────────────────────────────────
    function test_fundings_lib_send() external;
    function test_fundings_lib_pull() external;
    function test_fundings_lib_send_zero_amount_no_op() external;

    // ─── BondRoute_airdrop() ─────────────────────────────────────────────────────
    function test_BondRoute_airdrop_with_erc20() external;
    function test_BondRoute_airdrop_with_native() external;
    function test_BondRoute_airdrop_zero_amount_no_op() external;

    // ─── BondRoute_entry_point() Return Values ────────────────────────────────────
    function test_entry_point_returns_delegatecall_output() external;
    function test_entry_point_output_preserved_through_bondroute() external;
    function test_entry_point_returns_empty_bytes_on_void_function() external;
    function test_entry_point_returns_single_uint256() external;
    function test_validate_allows_execution_within_absolute_time_window() external;
    function test_validate_allows_execution_exactly_at_min_time() external;
    function test_validate_allows_execution_exactly_at_max_time() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// REENTRANCYLOCK.SOL - Transient-storage reentrancy protection
// Implemented in: test/ReentrancyLock/ReentrancyLock.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IReentrancyLockTests {
    // ─── nonReentrant() Tests ──────────────────────────────────────────────────────
    function test_nonReentrant_allows_single_call() external;
    function test_nonReentrant_reverts_on_same_lock_reentry() external;
    function test_nonReentrant_allows_different_lock_reentry() external;
    function test_nonReentrant_clears_lock_after_execution() external;
    function test_nonReentrant_allows_sequential_calls() external;

    // ─── nonReentrantView() Tests ──────────────────────────────────────────────────
    function test_nonReentrantView_allows_call_when_unlocked() external;
    function test_nonReentrantView_reverts_when_same_lock_held() external;
    function test_nonReentrantView_allows_different_lock() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// VALIDATIONLIB.SOL - Execution validation, bond farming detection, EIP-712 type validation
// Implemented in: test/ValidationLib/ValidationLib.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IValidationLibTests {
    // ─── is_valid_fundings() ─────────────────────────────────────────────────────
    function test_is_valid_fundings_accepts_empty_array() external;
    function test_is_valid_fundings_accepts_single_funding() external;
    function test_is_valid_fundings_accepts_max_fundings() external;
    function test_is_valid_fundings_rejects_too_many_fundings() external;
    function test_is_valid_fundings_rejects_zero_amount() external;
    function test_is_valid_fundings_rejects_duplicate_tokens() external;
    function test_is_valid_fundings_detects_duplicate_at_end() external;

    // ─── is_valid_execution() - Protocol Validation ──────────────────────────────
    function test_is_valid_execution_rejects_precompile_protocol() external;
    function test_is_valid_execution_rejects_malformed_offset() external;
    function test_is_valid_execution_rejects_size_mismatch() external;
    function test_is_valid_execution_rejects_selector_not_found() external;
    function test_is_valid_execution_rejects_empty_selector_list() external;

    // ─── revert_if_possibly_bond_farming() ───────────────────────────────────────
    function test_revert_if_possibly_bond_farming_reverts_on_empty_output() external;
    function test_revert_if_possibly_bond_farming_passes_short_output() external;
    function test_revert_if_possibly_bond_farming_reverts_on_transfer_failed() external;
    function test_revert_if_possibly_bond_farming_reverts_on_reentrancy() external;
    function test_revert_if_possibly_bond_farming_propagates_possibly_bond_farming() external;
    function test_revert_if_possibly_bond_farming_passes_unknown_selector() external;

    // ─── validate_typed_string_prefix() ──────────────────────────────────────────
    function test_validate_typed_string_prefix_accepts_valid() external;
    function test_validate_typed_string_prefix_rejects_too_short() external;
    function test_validate_typed_string_prefix_rejects_wrong_word1() external;
    function test_validate_typed_string_prefix_rejects_wrong_word2() external;
    function test_validate_typed_string_prefix_rejects_wrong_word3() external;

    // ─── validate_TokenAmount_definition() ───────────────────────────────────────
    function test_validate_TokenAmount_definition_accepts_valid() external;
    function test_validate_TokenAmount_definition_rejects_too_short() external;
    function test_validate_TokenAmount_definition_rejects_zero_offset() external;
    function test_validate_TokenAmount_definition_rejects_wrong_word1() external;
    function test_validate_TokenAmount_definition_rejects_wrong_word2() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SIGNATUREVALIDATOR.SOL - ECDSA and EIP-1271 signature validation
// Implemented in: test/SignatureValidator/SignatureValidator.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface ISignatureValidatorTests {
    // ─── is_valid_signature() - Input Validation ─────────────────────────────────
    function test_is_valid_signature_rejects_zero_hash() external;
    function test_is_valid_signature_rejects_zero_signer() external;
    function test_is_valid_signature_rejects_zero_hash_even_with_eip1271() external;
    function test_is_valid_signature_rejects_zero_signer_even_with_eip1271() external;

    // ─── is_valid_ecdsa_signature() ──────────────────────────────────────────────
    function test_is_valid_ecdsa_signature_accepts_valid_signature() external;
    function test_is_valid_ecdsa_signature_rejects_wrong_signer() external;
    function test_is_valid_ecdsa_signature_rejects_wrong_hash() external;
    function test_is_valid_ecdsa_signature_rejects_malformed_signature() external;
    function test_is_valid_ecdsa_signature_rejects_empty_signature() external;

    // ─── is_valid_contract_signature() - Precompile Protection ───────────────────
    function test_is_valid_contract_signature_rejects_precompile_address() external;
    function test_is_valid_contract_signature_rejects_high_precompile_address() external;
    function test_is_valid_contract_signature_accepts_address_at_threshold() external;

    // ─── is_valid_contract_signature() - Code Check ──────────────────────────────
    function test_is_valid_contract_signature_rejects_eoa() external;
    function test_is_valid_contract_signature_rejects_destroyed_contract() external;

    // ─── is_valid_contract_signature() - EIP-1271 Validation ─────────────────────
    function test_is_valid_contract_signature_accepts_valid_eip1271() external;
    function test_is_valid_contract_signature_rejects_invalid_magic_value() external;
    function test_is_valid_contract_signature_rejects_reverting_contract() external;
    function test_is_valid_contract_signature_passes_signature_to_contract() external;

    // ─── is_valid_signature() - Integration (ECDSA Path) ─────────────────────────
    function test_is_valid_signature_ecdsa_path_accepts_valid() external;
    function test_is_valid_signature_ecdsa_path_rejects_invalid() external;

    // ─── is_valid_signature() - Integration (EIP-1271 Path) ──────────────────────
    function test_is_valid_signature_eip1271_path_accepts_valid() external;
    function test_is_valid_signature_eip1271_path_rejects_invalid() external;
    function test_is_valid_signature_eip1271_path_rejects_reverting() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// TRANSFERLIB.SOL - Native and ERC20 token transfer utilities
// Implemented in: test/TransferLib/TransferLib.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface ITransferLibTests {
    // ─── transfer_native() Tests ───────────────────────────────────────────────────
    function test_transfer_native_zero_amount_no_op() external;
    function test_transfer_native_success() external;
    function test_transfer_native_reverts_on_failed_transfer() external;

    // ─── transfer_erc20() Tests ────────────────────────────────────────────────────
    function test_transfer_erc20_zero_amount_no_op() external;
    function test_transfer_erc20_from_self() external;
    function test_transfer_erc20_from_external() external;
    function test_transfer_erc20_reverts_on_failed_transfer() external;

    // ─── transfer_erc20_and_get_amount_delivered() Tests ───────────────────────────
    function test_transfer_erc20_and_get_amount_delivered_zero_returns_zero() external;
    function test_transfer_erc20_and_get_amount_delivered_from_self() external;
    function test_transfer_erc20_and_get_amount_delivered_from_external() external;
    function test_transfer_erc20_and_get_amount_delivered_reverts_on_failed_transfer() external;

    // ─── transfer() Tests ──────────────────────────────────────────────────────────
    function test_transfer_routes_native_token() external;
    function test_transfer_routes_erc20_token() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// FUZZ TESTS - Property-based testing for meaningful invariants
// Implemented in: test/Fuzz/Fuzz.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IFuzzTests {
    // ─── Stake Invariant ──────────────────────────────────────────────────────────
    function testFuzz_execute_bond_stake_always_refunded( uint256 stake_amount ) external;

    // ─── Funding Conservation Invariant ───────────────────────────────────────────
    function testFuzz_execute_bond_funding_conservation( uint256 amount ) external;

    // ─── Liquidation Boundary ─────────────────────────────────────────────────────
    function testFuzz_liquidate_only_after_expiration( uint256 time_warp ) external;

    // ─── Airdrop Accounting ───────────────────────────────────────────────────────────
    function testFuzz_airdrop_accumulation( uint8 airdrop_count ) external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// INVARIANT TESTS - System-wide properties that must always hold
// Implemented in: test/Invariants/Invariants.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IInvariantTests {
    // ─── Stake Conservation ───────────────────────────────────────────────────────
    function invariant_total_stakes_equal_contract_balance() external;
    function invariant_stake_never_lost() external;
    function invariant_executed_bond_stake_always_refunded() external;

    // ─── Bond State Machine ───────────────────────────────────────────────────────
    function invariant_bond_never_both_executed_and_liquidated() external;
    function invariant_executed_bond_cannot_be_liquidated() external;
    function invariant_liquidated_bond_cannot_be_executed() external;

    // ─── Return Value Invariants ──────────────────────────────────────────────────
    function invariant_executed_status_matches_bond_state() external;
    function invariant_status_never_active_after_execution() external;

    // ─── Meaningful Stateful Properties ───────────────────────────────────────────
    function invariant_no_double_refund() external;
    function invariant_fundings_pass_through() external;
    function invariant_bond_uniqueness() external;
    function invariant_total_supply_conservation() external;
    function invariant_no_stuck_funds() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// GAS BENCHMARKS - Validate gas optimization
// Implemented in: test/GasBenchmarks/GasBenchmarks.t.sol
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

interface IGasBenchmarkTests {
    // ─── Core Operations ──────────────────────────────────────────────────────────
    function test_gas_create_bond_erc20() external;
    function test_gas_create_bond_native() external;
    function test_gas_execute_bond_minimal() external;
    function test_gas_execute_bond_with_funding() external;
    function test_gas_liquidate_single_bond() external;
    function test_gas_liquidate_batch_10_bonds() external;
    function test_gas_claim_airdrops_single_token() external;
    function test_gas_claim_airdrops_multiple_tokens() external;

    // ─── Micro-Airdrop Benchmarks ─────────────────────────────────────────────────
    function test_gas_notify_protocol_airdrop() external;
    function test_gas_notify_protocol_airdrop_silent_vs_event() external;

    // ─── Storage Optimizations ────────────────────────────────────────────────────
    function test_gas_airdrop_dust_optimization() external;
    function test_gas_bit_packing_effectiveness() external;

    // ─── Overhead Benchmarks (Warm vs Cold Protocol) ───────────────────────────────
    function test_gas_overhead_zero_stake_protocol_warm() external;
    function test_gas_overhead_zero_stake_protocol_cold() external;
    function test_gas_overhead_native_stake_protocol_warm() external;
    function test_gas_overhead_native_stake_protocol_cold() external;
    function test_gas_overhead_erc20_stake_protocol_warm() external;
    function test_gas_overhead_erc20_stake_protocol_cold() external;
}


// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// SUMMARY STATISTICS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//
// Total Tests Declared:      381
// Implemented & Passing:     381 (✓)
//
// Coverage by Contract:
// - Storage.sol:             100% (24/24)
// - HashLib.sol:             100% (28/28)
// - Core.sol:                100% (43/43)
// - User.sol:                100% (35/35)
// - Provider.sol:            100% (32/32)
// - Collector.sol:           100% (56/56)
// - BondRoute.sol:           100% (18/18)
// - BondRouteProtected.sol:  100% (38/38)
// - ReentrancyLock.sol:      100% (8/8)
// - ValidationLib.sol:       100% (28/28)
// - SignatureValidator.sol:  100% (23/23)
// - TransferLib.sol:         100% (13/13)
// - Fuzz Tests:              100% (4/4)
// - Invariant Tests:         100% (13/13)
// - Gas Benchmarks:          100% (18/18)
//
// Pure BondRoute overhead (create_bond + execute_bond):
//    - Zero stake, warm protocol:   39,450 gas
//    - Zero stake, cold protocol:   43,450 gas
//    - Native stake, warm protocol: 53,035 gas
//    - Native stake, cold protocol: 57,035 gas
//    - ERC20 stake, warm protocol:  62,186 gas
//    - ERC20 stake, cold protocol:  66,186 gas
//
// Micro-airdrop (notify_protocol_airdrop):
//    - Cold slot, warm address:     5,911 gas
//    - Warm slot, warm address:     1,105 gas (silent) / 2,792 gas (with event)
//
