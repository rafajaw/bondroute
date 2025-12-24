// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;


// ━━━━  BOND STATUS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

enum BondStatus {   // *UPDATE GUARD* / *GAS SAVING* -  Current implementation relies on `ACTIVE` being `0`.
    ACTIVE,              // 0: Bond created, awaiting execution (or liquidation if expired).
    EXECUTED,            // 1: Bond settled and executed successfully.
    INVALID_BOND,        // 2: Bond settled - invalid bond structure (invalid fundings, unsupported protocol, etc.), stake refunded.
    PROTOCOL_REVERTED,   // 3: Bond settled - protocol reverted (non-farming revert), stake refunded.
    LIQUIDATED           // 4: Bond settled - expired and liquidated by sweeper.
}


// ━━━━  BOND HARD CAPS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Maximum bond lifetime before sweeper can liquidate stakes.
// Set conservatively long (111 days) because BondRoute is immutable infrastructure:
// - Known use cases: Quarterly prediction markets, extended sealed-bid auctions;
// - Unknown use cases: Future protocols may need longer windows;
// - No downside: Users execute normally, protocols set their own shorter windows;
// - Minor cost: Sweeper waits longer for liquidation (acceptable trade-off);
uint256 constant MAX_BOND_LIFETIME                      =   111 days;

// Maximum 4 funding tokens per bond enables powerful use cases while maintaining UX clarity:
// - Multi-token liquidity provision (e.g., USDC + WETH + DAI + LINK for LP operations);
// - Best-rate selection (provide USDC/USDT/DAI, contract picks most favorable during execution);
// - Complex DeFi operations requiring multiple asset types;
// - Users can easily review and verify 4 fundings during signing (UX-friendly);
// - Keeps gas costs and complexity manageable for both users and integrators;
uint256 constant MAX_FUNDINGS_PER_BOND                  =   4;


// ━━━━  PROTOCOL DISCOVERABILITY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Maximum protocol name length for on-chain announcements (DNS-inspired limit).
uint256 constant MAX_NAME_LENGTH                        =   64;

// Maximum message length for announcements and tips (tweet size).
uint256 constant MAX_MESSAGE_LENGTH                     =   280;


// ━━━━  ERROR MESSAGES  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

string constant INVALID_PROTOCOL_OR_CALL                =   "Invalid protocol or call";
string constant INVALID_TOO_MANY_FUNDINGS               =   "Too many fundings";
string constant INVALID_ZERO_AMOUNT                     =   "Funding amount cannot be zero";
string constant INVALID_DUPLICATE_FUNDING_TOKEN         =   "Duplicate funding token";

string constant OUT_OF_GAS_OR_UNSPECIFIED_FAILURE       =   "Out of gas or unspecified";


// ━━━━  EIP-712  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

string constant EIP712_DOMAIN_NAME                      =   "BondRoute";
string constant EIP712_DOMAIN_VERSION                   =   "1";

// Default ExecuteBondAs type - uses generic `calldata_hash` when integrator doesn't provide custom types.
string  constant TYPE_STRING_EXECUTE_BOND_AS            =   "ExecuteBondAs(TokenAmount[] fundings,TokenAmount stake,uint256 salt,address protocol,bytes32 calldata_hash)TokenAmount(address token,uint256 amount)";
bytes32 constant TYPE_HASH_EXECUTE_BOND_AS              =   keccak256( bytes(TYPE_STRING_EXECUTE_BOND_AS) );
bytes32 constant TYPE_HASH_TOKEN_AMOUNT                 =   keccak256( "TokenAmount(address token,uint256 amount)" );


// ━━━━  STORAGE SLOTS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

uint256 constant SLOT_CURRENT_CONTEXT_HASH              =   uint256(keccak256( "BondRoute.slot.current_context_hash" )) - 1;

// Tracks remaining stake held by BondRoute during execution. Starts at `actual_stake_received`,
// decrements as stake is consumed via `transfer_funding()`. Read at cleanup to return unused portion.
uint256 constant SLOT_HELD_STAKE                        =   uint256(keccak256( "BondRoute.slot.held_stake" )) - 1;

// Tracks remaining native token from `msg.value` during execution. Starts at `msg.value`,
// decrements as native is consumed via `transfer_funding()`. Read at cleanup to return unused portion.
uint256 constant SLOT_HELD_MSG_VALUE                    =   uint256(keccak256( "BondRoute.slot.held_msg_value" )) - 1;


// ━━━━  SECURITY  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

// Minimum gas required before querying protocol's protected selectors during bond execution.
// Prevents OOG attacks where attacker supplies minimal gas hoping the query OOGs,
// triggering stake refund instead of proper execution.
uint256 constant MIN_GAS_FOR_SELECTOR_QUERY             =   100_000;


// ━━━━  REENTRANCY LOCK KEYS  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

bytes20 constant LOCK_BONDS                             =   bytes20(keccak256( "BondRoute.lock.bonds" ));
bytes20 constant LOCK_TRANSFER_FUNDING                  =   bytes20(keccak256( "BondRoute.lock.transfer_funding" ));
bytes20 constant LOCK_TIPPING                           =   bytes20(keccak256( "BondRoute.lock.tipping" ));


