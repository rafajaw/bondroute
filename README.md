# BondRoute

[![CI](https://github.com/rafajaw/BondRoute/actions/workflows/test.yml/badge.svg)](https://github.com/rafajaw/BondRoute/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

```
██████╗  ██████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
██████╔╝██║   ██║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║   ██║   ██║   █████╗
██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝
██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗
╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
```

**A cryptographic bond primitive.**
Binding commitments for adversarial environments.

A staked commitment to fixed parameters. Execute to recover stake — or forfeit. Speculators who bet on multiple outcomes get trapped: bonds that "work" at bad terms force execution or loss.

> [!WARNING]
> **Security Status: Public Adversarial Review.** This code is under review prior to mainnet deployment. See [Security](#security).

---

## TL;DR

**The problem:** Your users are getting frontrun, sandwiched, and sniped. Auctions get gamed. Votes get manipulated. Users blame your protocol.

**The fix:** BondRoute-protected protocols reject naked calls and make bond farming unprofitable.

- **For protocols:** Integrate one file. Implement two functions. You define stake requirements and timing.
- **For users:** Intent hidden, execution protected, stake returned on completion.
- **Trust model:** Fully on-chain. Immutable. No intermediaries. No fees.

---

## Quick Start

> [!TIP]
> **5 minutes to protected deposits.** Copy this example and customize for your protocol.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./BondRouteProtected.sol";

string constant PROTOCOL_NAME         =  "YourToken";    // Set to empty string to opt-out of discoverability.
string constant PROTOCOL_DESCRIPTION  =  "Early depositor bonus mints";
IERC20 constant DEPOSIT_TOKEN         =  NATIVE_TOKEN;   // Could be native like ETH or any ERC20 token address.

contract YourToken is ERC20, BondRouteProtected {
    using FundingsLib for BondContext;

    uint256 private _total_deposits;

    constructor()
    ERC20( PROTOCOL_NAME, "TOKEN" )
    BondRouteProtected( PROTOCOL_NAME, PROTOCOL_DESCRIPTION ) { }

    function deposit( ) external
    {
        BondContext memory ctx  =  BondRoute_initialize( );
        uint256 amount  =  ctx.fundings[0].amount;
        ctx.pull( DEPOSIT_TOKEN, amount );

        // Early depositors get 2x tokens. Decreases to 1x after 100 ETH total.
        uint256 multiplier   =  _total_deposits < 100 ether  ?  2  :  1;
        uint256 mint_amount  =  amount * multiplier;

        _total_deposits  +=  amount;
        _mint( ctx.user, mint_amount );
    }

    function BondRoute_quote_call( bytes calldata call, IERC20, TokenAmount[] memory preferred_fundings )
    public pure override returns ( BondConstraints memory constraints )
    {
        if(  bytes4(call) != this.deposit.selector  )  revert( "Unknown selector" );

        uint256 amount                              =  preferred_fundings[0].amount;
        constraints.min_stake                       =  TokenAmount({ token: DEPOSIT_TOKEN, amount: amount / 100 });  // 1% stake.
        constraints.min_fundings                    =  new TokenAmount[](1);
        constraints.min_fundings[0]                 =  TokenAmount({ token: DEPOSIT_TOKEN, amount: amount });
        constraints.min_execution_delay_in_blocks   =  amount >= 10 ether  ?  3  :  2;  // Reorg protection scales with value.
        constraints.max_execution_delay_in_seconds  =  2 hours;  // Sensible security/UX balance.
    }

    function BondRoute_get_protected_selectors() external pure override returns ( bytes4[] memory selectors )
    {
        selectors     =  new bytes4[](1);
        selectors[0]  =  this.deposit.selector;
    }
}
```

**That's it. Early depositors are protected from frontrunning.**

---

## Table of Contents

- [Why Cryptographic Bonds](#why-cryptographic-bonds)
- [How BondRoute Works](#how-bondroute-works)
- [Understanding Constraints](#understanding-constraints)
- [User Flow](#user-flow)
- [Integration Deep Dive](#integration-deep-dive)
- [Wallet Signing UX](#wallet-signing-ux)
- [Composability](#composability)
- [Technical Highlights](#technical-highlights)
- [Trust Model](#trust-model)
- [Deployment](#deployment)
- [Security](#security)
- [FAQ](#faq)
- [Start Building](#start-building)
- [License](#license)

---

## Why Cryptographic Bonds

If you're building a protocol, you've seen these problems:

- **Users getting frontrun** — bots see pending transactions and act first
- **Users getting sandwiched** — attackers wrap user trades for guaranteed profit
- **Auction gaming** — in sealed-bid auctions, commit to $100, $200... $900, reveal only the winner
- **Liquidation frontrunning** — bots see pending liquidations and steal them with higher gas
- **Governance manipulation** — votes timed strategically, outcomes don't reflect genuine intent
- **Users blaming you** — when they get worse execution, it's your protocol's reputation

These aren't user errors. They're structural problems with how blockchains work: everyone can see pending transactions, and failing costs almost nothing.

Existing solutions don't fix this — they introduce trust assumptions and move extraction one level up.

### What BondRoute Does

BondRoute gives your protocol two properties that eliminate these attacks:

**Reserved execution** — Protected functions reject naked calls. Every action requires a bond created in advance. Attackers can't frontrun at reveal — they don't have bonds, and couldn't have known what to bond for.

**Binding economics** — Bonds lock stake with fixed parameters. Execute to recover stake, or forfeit. Bonds that "succeed" at unfavorable terms trap you: execute a bad trade or lose stake. Bond farming doesn't pay.

The result: no frontrunning without a bond, and speculating on bonds is unprofitable.

### Concrete Examples

#### Swaps

| Without bonds | With BondRoute |
|---------------|----------------|
| Bot sees pending swap | Intent hidden until execution |
| Bot frontruns with higher gas | No bond = rejected |
| Bots speculate freely, failure is cheap | Bots get trapped — execute bad trade or forfeit stake |
| User gets worse price | User gets expected price |

#### Blind Auctions

| Without bonds | With BondRoute |
|---------------|----------------|
| Bot commits to $100, $200... $900 | Each bid requires stake |
| Reveals only the winner, abandons rest free | No bond = can't bid |
| Overbids abandoned at zero cost | Overbids get trapped — overpay or forfeit stake |
| Gaming auctions is free | Gaming auctions is unprofitable |

#### Liquidations

| Without bonds | With BondRoute |
|---------------|----------------|
| Bot A finds liquidatable position, submits tx | Liquidation intent hidden until execution |
| Bot B sees pending tx, frontruns with higher gas | No bond = can't liquidate. Can't frontrun what they can't see. |
| Bot A did the work, Bot B stole the profit | Whoever finds the opportunity keeps it |

#### Governance

| Without bonds | With BondRoute |
|---------------|----------------|
| Voters wait to see others' positions before voting | Blind voting window — no peeking |
| Vote or abstain strategically at zero cost | Each position requires stake — commitment has weight |
| Outcomes reflect strategy, not preference | Outcomes reflect genuine intent |

### Integration

You control the security model. Your protocol defines:

- **Stake requirements** — proportional to value at risk
- **Execution windows** — appropriate for the action's time sensitivity
- **Validation logic** — what counts as legitimate failure vs. abuse

Integrate one file. Implement two functions. See [Quick Start](#quick-start).

### Why This Must Live at Your Layer

Infrastructure can't price these protections correctly. A stake appropriate for a $10 swap is dangerously low for a $10M auction bid. An execution window safe for a token transfer may be exploitable for a liquidation.

Only your protocol knows the economics. BondRoute provides the primitive for binding commitments — you define what "binding" means.

### Infrastructure Benefits

When spam becomes expensive, it stops. Blockspace currently filled with speculative garbage — failed arbitrage attempts, racing bots, reverted probes — clears out. Gas prices drop. Infrastructure provisioning serves real users instead of absorbing spam.

---

## How BondRoute Works

### The Three-Step Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  1. COMMIT                                                                  │
│     create_bond( commitment_hash, stake )                                   │
│     → Hash hides: protocol + call + fundings + salt                         │
│     → Stake deposited to BondRoute                                          │
│                                                                             │
│  2. WAIT                                                                    │
│     Minimum one block between commit and reveal                             │
│     → Protocols can require longer delays                                   │
│     → Protocols can require specific execution windows                      │
│                                                                             │
│  3. REVEAL                                                                  │
│     execute_bond( execution_data )                                          │
│     → Execution data revealed                                               │
│     → Protocol validates and executes                                       │
│     → Protocol pulls authorized funds via BondRoute                         │
│     → Stake returned to user                                                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### What Attackers See

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  OBSERVABLE:                                                                │
│  create_bond( 0x7a3f...commitment_hash, stake )                             │
│                                                                             │
│  HIDDEN:                                                                    │
│  ├── Protocol:   ???                                                        │
│  ├── Function:   ???                                                        │
│  ├── Parameters: ???                                                        │
│  ├── Tokens:     ???                                                        │
│  └── Amounts:    ???                                                        │
│                                                                             │
│  All bonds go through the BondRoute singleton.                              │
│  Attackers can't even tell which protocol is being used.                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Understanding Constraints

Protocols define execution requirements by implementing `BondRoute_quote_call()`. This function receives the full calldata and returns constraints — meaning **each call can have different requirements**.

You can vary constraints based on:
- **Function selector** — different functions have different risk profiles
- **Decoded parameters** — a $100 swap vs a $100,000 swap, token ID #1 vs #999, etc.

Constraints are not fixed per contract. They're computed per call.

The return type is `BondConstraints`:

```solidity
struct BondConstraints {
    TokenAmount min_stake;                      // Required stake (token + amount)
    TokenAmount[] min_fundings;                 // Required funding tokens (max 4)
    uint256 min_execution_delay_in_blocks;      // BondRoute enforces 1 - can require more to deter chain reorgs
    uint256 max_execution_delay_in_seconds;     // Constrains sitting on a bond for opportunistic execution
    Range valid_creation_timestamp_range;       // Absolute timestamp window for bond creation
    Range valid_execution_timestamp_range;      // Absolute timestamp window for bond execution
}

struct Range {
    uint256 min;    // 0 = no minimum constraint
    uint256 max;    // 0 = no maximum constraint
}
```

### Field Reference

| Field | Purpose | Zero means |
|-------|---------|------------|
| `min_stake` | Required stake (refunded on execution) | No stake required |
| `min_fundings` | Tokens user must provide | No funding required |
| `min_execution_delay_in_blocks` | Minimum blocks before execution | BondRoute default (1 block) |
| `max_execution_delay_in_seconds` | Maximum seconds until execution | BondRoute hardcap (111 days) |
| `valid_creation_timestamp_range` | Absolute creation window | No creation constraint |
| `valid_execution_timestamp_range` | Absolute execution window | No execution constraint |

### Understanding Fundings

Fundings are tokens the user commits to providing for the bond execution.

Users approve BondRoute once, then each bond declares funding limits.

Fundings never touch BondRoute — they stay in the user's wallet. During execution, protocols transfer funds via BondRoute, which enforces user-specified fundings as the maximum the protocol can pull. Protocols can pull less, but never more.

Stakes are different: held by BondRoute at creation, refunded at execution.

Max 4 fundings for clean wallet signatures.

**Use cases:**
- Simple swap: Single funding (USDC in, ETH out)
- LP deposit: Two fundings (ETH + USDC to add liquidity)
- Multi-stablecoin routing: Four fundings (USDC, USDT, USDE, DAI — protocol picks best rate at execution, pulls only the winner)

### Smart Stake Consumption

When funding token matches stake token, BondRoute uses staked funds first:

```
Swap 1,000 USDC with 100 USDC stake
├── User has: 1,000 USDC total
├── Create bond: 100 USDC staked (900 USDC remains in wallet)
└── Execute: BondRoute uses 100 USDC stake + pulls 900 USDC from wallet
    → Full 1,000 USDC swap executed
```

### Common Patterns

**Liquidation** — minimum delay:
```solidity
constraints.min_stake                        =  TokenAmount({ token: NATIVE_TOKEN, amount: 0.1 ether });  // Fixed stake.
constraints.min_execution_delay_in_blocks    =  5;  // Ensure finality of bond creation.
constraints.max_execution_delay_in_seconds   =  1 hours;
```

**Simple swap** — stake + fundings:
```solidity
constraints.min_stake                        =  TokenAmount({ token: USDC, amount: amount / 100 });  // 1% stake.
constraints.min_fundings                     =  new TokenAmount[](1);
constraints.min_fundings[0]                  =  TokenAmount({ token: USDC, amount: amount });
constraints.max_execution_delay_in_seconds   =  3 hours;
```

**Blind auction** — absolute time windows:
```solidity
constraints.min_stake                        =  TokenAmount({ token: WETH, amount: bid_amount / 10 });  // 10% stake.
constraints.min_fundings                     =  new TokenAmount[](1);
constraints.min_fundings[0]                  =  TokenAmount({ token: WETH, amount: bid_amount });
constraints.valid_creation_timestamp_range   =  Range({ min: auction_start, max: auction_end });  // Bidding window.
constraints.valid_execution_timestamp_range  =  Range({ min: reveal_start, max: reveal_end });  // Reveal window.
```

---

## User Flow

### 1. Discover Protected Protocols

**On-chain discovery** — fully trustless:

Protocols announce themselves at deployment:
```solidity
constructor() BondRouteProtected( "YourDEX", "Protected decentralized exchange" ) {}
```

This emits:
```solidity
event ProtocolAnnounced( address indexed protocol, string name, string description );
```

Discover protected functions:
```javascript
// Fetch ABI from bytecode metadata (content-addressed, trustless)
const abi = await fetch_abi_from_bytecode_metadata( protocol_address );

// Get protected selectors
const selectors = await protocol.BondRoute_get_protected_selectors();

// Filter to protected functions
const protected_functions = abi.filter( fn => selectors.includes( fn.selector ) );
```

### 2. Query Constraints

```javascript
const calldata = encode_function_call( "swap", [token_out, min_amount_out] );

const constraints = await protocol.BondRoute_quote_call(
    calldata,
    USDC,                       // Preferred stake token
    [{ token: USDC, amount }]   // Preferred fundings (amount to swap)
);
```

### 3. Create Bond

> [!CAUTION]
> **If you lose your salt, you cannot execute your bond and your stake is forfeited.** Use 32-bit (~4 billion) for recoverability — you can brute-force it in minutes if you know your other parameters. Use 256-bit only if secrecy is paramount. Bots must also guess protocol, call, amounts, and tokens — the salt is just one factor in the commitment hash.

```javascript
const salt = random_uint32();  // 32-bit recommended for recoverability

const execution_data = {
    fundings: constraints.min_fundings,
    stake: constraints.min_stake,
    salt: salt,
    protocol: protocol_address,
    call: encoded_call
};

const commitment_hash = await BondRoute.__OFF_CHAIN__calc_commitment_hash( user_address, execution_data );

// Create bond (wait for tx to be mined)
const tx = await BondRoute.create_bond( commitment_hash, execution_data.stake );
await tx.wait();
```

### 4. Execute Bond

```javascript
// Wait for minimum block delay (if any)
// Note: BondRoute enforces 1 block minimum; protocol may require more via min_execution_delay_in_blocks
await wait_for_blocks( constraints.min_execution_delay_in_blocks );

// Execute
// TIP: Use a slightly higher gas price to ensure quick confirmation,
// minimizing the window between bond creation and execution.
const { status, output } = await BondRoute.execute_bond( execution_data );
// Stake refunded on execution (success or graceful revert)
```

### 5. Gasless Option

> [!TIP]
> For users who don't hold gas tokens — one off-chain signature, zero gas required.

```javascript
// User signs once off-chain
const { domain, type_string } = await BondRoute.__OFF_CHAIN__get_signing_info( execution_data );
const types = parse_eip712_types( type_string );
const signature = await user.signTypedData( domain, types, execution_data );

// Relayer submits both transactions
await BondRoute.create_bond( commitment_hash, stake );                // Relayer pays gas
await BondRoute.execute_bond_as( execution_data, user, signature );   // Relayer pays gas
// Stake and native ETH always returns to USER, not relayer
```

---

## Integration Deep Dive

### Protocol-Defined Constraints

You control the security model. Each protocol defines its own constraints via `BondRoute_quote_call()`:

- **Stake requirements** — token and amount, proportional to value at risk
- **Accepted fundings** — which tokens, how much
- **Timing windows** — execution delays, absolute creation/execution windows

See Quick Start for a complete example.

### Validation Behavior

| Outcome | What happens |
|---------|--------------|
| Execution succeeds | Stake refunded |
| Protocol reverts with custom error | Stake refunded |
| `PossiblyBondFarming` revert | Transaction reverts, stake remains locked, user can retry |
| Bond expires without execution | Stake forfeited |

> [!IMPORTANT]
> **Why `PossiblyBondFarming` keeps stake locked:**
> Certain failures suggest bond farming — creating bonds for mutually exclusive outcomes and executing only the most profitable one. These failures include timing violations, transfer failures (missing approval, insufficient balance), and out-of-gas conditions. Reverting the transaction prevents attackers from recovering stake on bonds they intended to abandon, while allowing legitimate users to fix the issue and retry.

### Optional: Airdrops & Distribution

BondRoute exposes optional airdrop hooks. **These are entirely opt-in and do not affect how bonds are created, executed, or settled.**

Two patterns:

```solidity
// Bulk: launches, campaigns
BondRoute.airdrop( token, amount, "YourProtocol launch" );

// Micro: gas-efficient drips during on-chain activity (skips approve/transferFrom)
_mint( address(BondRoute), small_amount );
BondRoute.notify_protocol_airdrop( small_amount, bytes32("YourProtocol") );
```

Airdrop once to BondRoute, let the collector handle fan-out. More gas-efficient and less sybil-prone than one-off airdrops to large static address lists.

**Where do airdrops go?**

A dedicated collector address claims accumulated airdrops (and forfeited stakes). The collector can be an EOA, multisig, or contract with its own distribution logic.

From an integrator's perspective, airdrops are optional one-way contributions with no protocol-level guarantee about downstream routing. BondRoute core does not prescribe how collected tokens are used — the collector design is intentionally outside scope of the core primitive.

---

## Wallet Signing UX

EIP-712 signatures typically show users an unreadable hash. BondRoute lets protocols override this.

**Default experience:**
```
Sign this message?
Data: 0x7a3f9b2c...
```

**With protocol customization:**
```
Sign this message?
Swap 1,000 USDC for ETH
Minimum output: 0.5 ETH
```

Protocols implement `BondRoute_get_signing_info()` to provide human-readable signing data. Users see exactly what they're committing to — not a hash.

This is optional. If not implemented, wallets display the default calldata hash.

---

## Composability

BondRoute is forward-compatible with ERC-4337, EIP-7702, and the emerging smart wallet ecosystem.

Traditional composability chains contract calls dynamically:
```solidity
result = dex.swap(amount);
vault.deposit(result);  // Dynamic input from previous output
```

BondRoute moves composability to the orchestration layer:
```solidity
// Smart wallet executes pre-committed bonds
result1 = BondRoute.execute_bond(swap_bond);
result2 = BondRoute.execute_bond(deposit_bond);
// Return values available for orchestration logic
doSomething(result1, result2);
```

**Bond parameters are binding.** Outputs from one bond cannot feed as inputs to another bond — this is intentional.

Why? If parameters were dynamic, bonds would not be commitments. An attacker could create a bond for an X-USDC swap, then execute with 1 wei solely to recover stake. Stake recovery becomes free. Free stake recovery removes deterrence. No deterrence brings back spam, multi-optionality abuse, and bond farming.

Fixed parameters are the mechanism that turns stakes from deposits into deterrents.

**Flash loans work perfectly.** Execute bonds inside flash loan callbacks — borrowed capital funds executions, atomicity preserved.

**The orchestration layer moves up to where the user controls it.**

---

## Technical Highlights

- One signature: gasless execution + up to 4 funding tokens
- Smart stake-first consumption
- Protocol-customizable wallet signing
- Gas-optimized: assembly, packed storage, dust retention
- Same address on all EVM chains

---

## Trust Model

**Trustless design.** Everything lives on-chain: protocol discovery, protected selector queries, call quoting. No off-chain dependencies.

- **No admin keys** — nobody can pause, freeze, or modify
- **No upgrades or proxies** — deployed bytecode is final
- **No fees** — free primitive, no rent extraction
- **Minimal collector role** — can only claim expired bonds + airdrops
- **Deterministic address** — same address across all EVM chains

Verify the code once. Trust the deployed bytecode.

### Relayers and Censorship

BondRoute does not require or privilege any relayer.
Any party may submit bond creation or execution transactions.

Relayers:
- Are permissionless
- Cannot steal funds (stake and execution refunds go to the user)
- Can be bypassed by users at any time by submitting directly

Gasless execution is an optional UX layer, not a trust assumption.

---

## Deployment

BondRoute has not yet been deployed.

Deployment will be:
- Deterministic (CREATE2)
- Immutable (no upgrade paths)
- Identical address across all EVM chains

The final deployment transaction, contract address, and verification links will be published here prior to launch.

---

## Security

**Status: Public Adversarial Review**

BondRoute is under public adversarial review prior to mainnet deployment.

This is not a beta. The code under review is the code that will be deployed.

**Commit under review:** `0x2573d08a3d6343e8f99d4a04e56ad7f3280a4455`

### Bounty

We're offering bounties for responsibly disclosed vulnerabilities:

| Severity | Reward |
|----------|--------|
| Critical | up to $5,000 |
| High | up to $2,000 |

**What qualifies:**
- Loss of user funds
- Loss of stake funds
- Bypass of commit-reveal protection
- Griefing vectors with material impact

**Reporting:** security@bondroute.xyz

Please include a proof-of-concept or minimal reproduction where applicable.

All valid submissions acknowledged and credited.

### Improvements

Not a vulnerability, but a better approach? Gas optimization? Design insight that meaningfully improves the primitive?

We compensate valuable contributions - not just bugs.

**Contact:** hello@bondroute.xyz

This is pre-deployment. Everything is on the table.

---

## FAQ

### For Decision Makers

<details>
<summary><strong>Why should I integrate BondRoute?</strong></summary>

Without BondRoute, your protocol is unprotected — like running a webapp on HTTP instead of HTTPS. Bots can easily extract value from every user action: worse swap prices, sniped auctions, frontrun liquidations. BondRoute stops the extraction and keeps that value for your users. Fairer for them. Competitive edge for you.
</details>

<details>
<summary><strong>What's the integration effort?</strong></summary>

One file. Two functions. Most teams integrate in an afternoon. See Quick Start.
</details>

<details>
<summary><strong>Does this create vendor lock-in?</strong></summary>

No. BondRoute is immutable — no admin keys, no fees, no one to negotiate with. It can't be turned off or paywalled. Zero vendor risk.
</details>

<details>
<summary><strong>What's the regulatory profile?</strong></summary>

BondRoute is a commit-reveal primitive. No custody, no intermediaries, no orderflow. Same regulatory profile as any other on-chain library.
</details>

### For Devs

<details>
<summary><strong>How hard is integration?</strong></summary>

One file. Two functions. You choose which functions to protect — only selectors returned by `BondRoute_get_protected_selectors()` require bonds. Everything else works normally.
</details>

<details>
<summary><strong>Can I integrate if my contract is already deployed?</strong></summary>

- **Upgradeable**: Yes — add `BondRouteProtected` to your implementation
- **Immutable**: Deploy a new protected version
</details>

<details>
<summary><strong>What if my function reverts?</strong></summary>

The bond settles gracefully and stake is refunded. Suspected bond farming reverts the transaction — legit users can fix the issue and retry.
</details>

<details>
<summary><strong>What happens to forfeited stakes?</strong></summary>

Unexecuted bonds expire after 111 days and can be liquidated by the collector. The long window accommodates long-lived commitments (quarterly prediction markets, sealed-bid auctions). Under normal use, users execute within the protocol's window and get stakes back.
</details>

<details>
<summary><strong>What gas overhead should I expect?</strong></summary>

~40-66k gas depending on stake type and access pattern. Typically a few cents on Ethereum, less on other EVM chains.
</details>

<details>
<summary><strong>How do upgrades work?</strong></summary>

Remove a selector from `BondRoute_get_protected_selectors()` and existing bonds targeting it settle gracefully with stake refunded. Enables selector-level pauses, deprecation, and migrations.
</details>

<details>
<summary><strong>Can I use native ETH?</strong></summary>

Yes. Use `address(0)` (or `NATIVE_TOKEN` constant) for stakes or fundings. No wrapping required.
</details>

### For Users

<details>
<summary><strong>Why do I need to create a bond before swapping?</strong></summary>

The bond hides your intent, preventing execution-time value extraction during the swap.
</details>

<details>
<summary><strong>What happens if I miss my execution window?</strong></summary>

You lose your stake. Execute within the protocol's time window to get it back automatically.
</details>

<details>
<summary><strong>What happens if I forget my salt?</strong></summary>

With a 32-bit salt (~4 billion combinations), you can brute-force recover it in minutes if you know your other parameters. With a 256-bit salt, recovery is impossible — store it safely.
</details>

<details>
<summary><strong>Is my approval to BondRoute safe?</strong></summary>

Yes. Funds stay in your wallet. BondRoute only enforces the limits you declare in each bond — it never holds your funds beyond the stake.
</details>

---

## Start Building

Don't settle for unfair markets.

1. Copy `BondRouteProtected.sol`
2. Inherit from `BondRouteProtected`
3. Implement `BondRoute_quote_call()` and `BondRoute_get_protected_selectors()`
4. Call `BondRoute_initialize()` at function start
5. Done

**Read the code:**
- Contracts are the documentation
- Tests show real usage patterns

**Deploy and forget:**
- Immutable forever
- Works the same in 10 years as it does today
- No dependency on our team, our servers, our anything

---

## License

MIT License. See [LICENSE](LICENSE).
