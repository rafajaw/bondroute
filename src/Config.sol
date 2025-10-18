// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;


library Config {

    // Bond execution timing.
    uint256 internal constant HARD_CAP_EXECUTION_WINDOW                 =   101 days;   // Over 3 months - ample time for varied use cases.

    // Fee system constants.
    uint256 internal constant BONDROUTE_FEE_DIVISOR                     =   10_000;     // 0.01% on each pull_funds/send_funds operation (for $100.00 pulled/sent it is $0.01).

    // Bond limits.
    uint256 internal constant MAX_STAKES_PER_BOND                       =   9;          // Maximum different tokens that can be staked per bond.
    // *NOTE*  -  We limit stakes because they write to persistent storage (expensive SSTORE operations).
    //         -  Fundings and calls arrays don't need limits as they only use memory/calldata (cheap).
    //         -  Gas limits naturally cap memory arrays, and users pay for their own execution costs.

    // EIP-712 Domain Parameters.
    string internal constant EIP712_DOMAIN_NAME                         =   "BondRoute";
    string internal constant EIP712_DOMAIN_VERSION                      =   "1";

    // EIP-712 type hashes.
    bytes32 internal constant TOKEN_AMOUNT_TYPEHASH                     =   keccak256(
        "TokenAmount(address token,uint256 amount)"
    );
    bytes32 internal constant CALL_ENTRY_TYPEHASH                       =   keccak256(
        "CallEntry(address _contract,bytes _calldata,TokenAmount stake)TokenAmount(address token,uint256 amount)"
    );
    bytes32 internal constant EXECUTE_BOND_ON_BEHALF_OF_USER_TYPEHASH   =   keccak256(
        "BondExecution(uint64 bond_id,TokenAmount[] fundings,CallEntry[] calls,bytes32 secret)CallEntry(address _contract,bytes _calldata,TokenAmount stake)TokenAmount(address token,uint256 amount)"
    );
    
}
