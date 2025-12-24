
# BondRoute

```
██████╗  ██████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
██████╔╝██║   ██║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║   ██║   ██║   █████╗
██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝
██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗
╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
```

**A cryptographic bond primitive.**
Trustless chain-wide commit-reveal with stakes.

---

**A cryptographic bond is a staked commitment to an action.**

Intent is committed first (bond created), revealed later (bond executed). Abandonment carries explicit cost (stake forfeited).

---

## TL;DR

- **The problem**: Underpriced optionality enables exploitation — frontrunning, multi-optionality abuse, spam
- **The fix**: Commit-reveal hides intent. Stakes makes abandonment costly.
- **Trust model**: Fully on-chain. Immutable. No required intermediaries.
- **For protocols**: One file. Two functions. Your users are protected.
- **For users**: MEV protection by default — no frontrunning or sandwiching. Gasless execution optional.

**Security status:** Public adversarial review in progress.

---

## Quick Start

**5 minutes to protected deposits.**

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "./BondRouteProtected.sol";

string constant PROTOCOL_NAME         =  "YourToken";    // Set to empty string to opt-out of discoverability.
string constant PROTOCOL_DESCRIPTION  =  "Early depositor bonus mints";

contract YourToken is ERC20, BondRouteProtected {
    using FundingsLib for BondContext;

    uint256 public total_deposits;

    constructor() ERC20( PROTOCOL_NAME, "YTOK" ) BondRouteProtected( PROTOCOL_NAME, PROTOCOL_DESCRIPTION ) {}

    function deposit( uint256 amount ) external {
        BondContext memory ctx = BondRoute_initialize();
        ctx.pull( NATIVE_TOKEN, amount );

        uint256 bonus = 100 - ( total_deposits / 1 ether );  // 100% bonus at start, decreasing.
        if ( bonus > 100 ) bonus = 100;
        uint256 mint_amount = amount + ( amount * bonus / 100 );

        total_deposits += amount;
        _mint( ctx.user, mint_amount );
    }

    function BondRoute_get_call_constraints( bytes calldata call, IERC20, TokenAmount[] memory )
    public pure override returns ( BondConstraints memory constraints ) {
        if(  bytes4(call) != this.deposit.selector  ) revert( "Unknown selector" );
        uint256 amount = abi.decode( call[4:], (uint256) );
        constraints.min_stake = TokenAmount({ token: NATIVE_TOKEN, amount: amount / 100 });  // 1% stake.
        constraints.min_fundings = new TokenAmount[](1);
        constraints.min_fundings[0] = TokenAmount({ token: NATIVE_TOKEN, amount: amount });
        constraints.execution_delay  =  Range({ min: 0, max: 3 hours });  // Must execute within 3 hours.
    }

    function BondRoute_get_protected_selectors() external pure override returns ( bytes4[] memory selectors ) {
        selectors = new bytes4[](1);
        selectors[0] = this.deposit.selector;
    }
}
```

**That's it. Early depositors are protected from frontrunning.**

---

## Table of Contents

- [The Problem](#the-problem)
- [How BondRoute Works](#how-bondroute-works)
- [Understanding Constraints](#understanding-constraints)
- [User Flow](#user-flow)
- [Integration Deep Dive](#integration-deep-dive)
- [Wallet Signing UX](#wallet-signing-ux)
- [Composability](#composability)
- [Architecture](#architecture)
- [Trust Model](#trust-model)
- [Deployment](#deployment)
- [Security](#security)
- [FAQ](#faq)
- [Start Building](#start-building)
- [License](#license)

---

## The Problem

MEV isn't a bug. It's a fundamental property of how blockchain works.

Every transaction leaks information. Bots are watching. Value gets extracted.
Private mempools and relayers don't solve this — they shift trust assumptions and socialize the extraction.

The result: systematic adverse selection against honest users and protocols.

### Two Failure Modes

Public execution environments suffer from two independent vulnerabilities:

**1. Intent exposed too early**

- **Frontrunning** — bots see pending actions and act first.

**2. Underpriced optionality**

- **Costless probing** — try many routes, prices, or venues; reverts cost almost nothing.

"Try 100 transactions, profit from 1" becomes the dominant strategy.

Either vulnerability alone allows exploitation; together they erode value from users, protocols and infrastructure.

### Why Commit-Reveal Alone Doesn't Solve Everything

Hiding intent addresses information leakage but does not make optionality costly.
An attacker could still:

- Create commitments for multiple mutually exclusive outcomes.
- Wait until uncertainty resolves.
- Execute only the profitable ones and abandon the rest at negligible cost.

Optionality must be **properly priced**, not just hidden.

### The Fix: BondRoute

BondRoute addresses both failure modes:

**1. Intent exposed too early**
- → Commit-reveal hides intent until execution.
- → Protected contracts reject non-bond calls.

**2. Underpriced optionality**
- → Stakes + timing constraints price every attempt.
- → Abandoned or expired bonds forfeit their stake.
- → "Try 100, profit from 1" becomes "profit from 1, forfeit 99."

Legitimate users execute and recover stakes; attackers pay for optionality.
Suspected bond farming (timing violations, missing approvals, out-of-gas) reverts the transaction, allowing legitimate users to retry.

### Pricing Optionality Is an Information Problem

Infrastructure-level mitigations can reduce information leakage, but they cannot know the value of a specific execution or its valid time window. Any infrastructure-level deterrent must therefore be generic; any generic deterrent is mispriced.

- A stake sufficient for a $10 swap may be dangerously low for a $10M bid.
- Execution windows safe for one application may be exploitable in another.

Optionality can only be safely priced **at the application level**, where the economics are known.

BondRoute provides a primitive for enforcing binding commitments — the application defines what "binding" means.

---

## How BondRoute Works

### The Three-Step Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  1. COMMIT                                                                  │
│     create_bond( commitment_hash, stake, deadline )                         │
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
│  create_bond( 0x7a3f...commitment_hash, stake, deadline )                   │
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

Protocols define execution requirements via `BondConstraints`:

```solidity
struct BondConstraints {
    TokenAmount min_stake;        // Required stake (token + amount)
    TokenAmount[] min_fundings;   // Required funding tokens (max 4)
    Range execution_delay;        // Relative: seconds after bond creation
    Range creation_time;          // Absolute: unix timestamp window for bond creation
    Range execution_time;         // Absolute: unix timestamp window for bond execution
}

struct Range {
    uint256 min;  // 0 = no minimum constraint
    uint256 max;  // 0 = no maximum constraint
}
```

### Field Reference

| Field | Purpose | Zero means |
|-------|---------|------------|
| `min_stake` | Attach cost to abandonment | No stake required |
| `min_fundings` | Tokens user must provide | No funding required |
| `execution_delay` | Relative timing after creation | No delay constraint |
| `creation_time` | Absolute creation window | No creation constraint |
| `execution_time` | Absolute execution window | No execution constraint |

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
constraints.min_stake = TokenAmount({ token: NATIVE_TOKEN, amount: 0.1 ether });  // Fixed stake.
constraints.execution_delay = Range({ min: 1 minutes, max: 1 hours });  // Ensure finality of bond creation.
```

**Simple swap** — stake + fundings:
```solidity
constraints.min_stake = TokenAmount({ token: USDC, amount: amount / 100 });  // 1% stake.
constraints.min_fundings = new TokenAmount[](1);
constraints.min_fundings[0] = TokenAmount({ token: USDC, amount: amount });  // Pulled from user during execution.
constraints.execution_delay = Range({ min: 0, max: 3 hours });  // Must execute within 3 hours.
```

**Blind auction** — absolute time windows:
```solidity
constraints.min_stake = TokenAmount({ token: WETH, amount: bid_amount / 10 });  // 10% stake.
constraints.min_fundings = new TokenAmount[](1);
constraints.min_fundings[0] = TokenAmount({ token: WETH, amount: bid_amount });  // Pulled from user during execution.
constraints.creation_time = Range({ min: auction_start, max: auction_end });  // Bidding window.
constraints.execution_time = Range({ min: reveal_start, max: reveal_end });  // Reveal window.
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
const calldata = encodeFunctionCall( "swap", [amount] );

const constraints = await protocol.BondRoute_get_call_constraints(
    calldata,
    USDC_ADDRESS,              // Preferred stake token
    [{ token: USDC, amount }]  // Preferred fundings
);
```

### 3. Create Bond

```javascript
// Salt: prevents brute-force guessing of commitment.
// Range 0 to ~4 billion — recoverable by user in minutes if forgotten,
// but infeasible for bots who must also guess protocol, call, amounts, tokens, etc.
const salt = random_uint32();

const execution_data = {
    fundings: [{ token: USDC, amount: parseUnits( "1000", 6 ) }],
    stake: { token: USDC, amount: parseUnits( "10", 6 ) },
    salt: salt,
    protocol: protocol_address,
    call: encoded_call
};

const commitment_hash = await BondRoute.__OFF_CHAIN__calc_commitment_hash(
    user_address,
    execution_data
);

// Create bond (wait for tx to be mined)
const tx = await BondRoute.create_bond( commitment_hash, stake, deadline );
await tx.wait();
```

### 4. Execute Bond

```javascript
// Wait for minimum delay (if any)
await wait_for_delay( constraints.execution_delay.min );

// Execute
const { status, output } = await BondRoute.execute_bond( execution_data );
// Stake refunded on execution (success or graceful revert)
```

### 5. Gasless Option

For users who don't hold gas tokens:

```javascript
// User signs once off-chain
const { domain, type_string } = await BondRoute.__OFF_CHAIN__get_signing_info( execution_data );
const types = parse_eip712_types( type_string );
const signature = await user.signTypedData( domain, types, execution_data );

// Relayer submits both transactions
await BondRoute.create_bond( commitment_hash, stake, deadline );      // Relayer pays gas
await BondRoute.execute_bond_as( execution_data, user, signature );   // Relayer pays gas
// Stake and native ETH returned to USER, not relayer
```

**One off-chain signature. Zero gas required from user.**

---

## Integration Deep Dive

### Protocol-Defined Constraints

You control the security model:

```solidity
function BondRoute_get_call_constraints( bytes calldata call, IERC20 preferred_stake_token, TokenAmount[] memory preferred_fundings )
public pure override returns ( BondConstraints memory constraints )
{
    if(  bytes4(call) != this.swap.selector  )  revert( "Unknown selector" );

    uint256 amount  =  abi.decode( call[4:], (uint256) );

    // Honor user's preferred stake token if accepted (could use oracle for cross-token normalization).
    IERC20 stake_token      =  _is_accepted_token( preferred_stake_token )  ?  preferred_stake_token  :  USDC;
    constraints.min_stake   =  TokenAmount({ token: stake_token, amount: amount / 100 });  // 1%

    // Honor user's preferred funding token.
    constraints.min_fundings        =   new TokenAmount[]( 1 );
    constraints.min_fundings[ 0 ]   =   ( preferred_fundings.length > 0 )
                                        ? preferred_fundings[ 0 ]
                                        : TokenAmount({ token: USDC, amount: amount });
}
```

### Validation Behavior

| Outcome | What happens |
|---------|--------------|
| Execution succeeds | Stake refunded |
| Protocol reverts with custom error | Stake refunded |
| `PossiblyBondFarming` revert | Transaction reverts, stake locked, user can retry |
| Bond expires without execution | Stake forfeited |

**Why `PossiblyBondFarming` locks stake:**

Certain failures suggest selective execution — creating bonds for multiple outcomes and executing only the profitable one. These include timing violations, transfer failures (missing approval, insufficient balance), and out-of-gas conditions. Locking the stake (rather than forfeiting immediately) allows legitimate users to fix the issue and retry within their execution window.

### Tipping Model

BondRoute is a free public good. Tips are optional.

Protocols typically share 10% of their fee:
- 1% protocol fee → 0.9% kept, 0.1% tipped
- Tips sustain SDKs and off-chain tooling protecting users from MEV

Use the `tip()` function to send tips with an optional message (max 280 chars):

```solidity
// ERC20 tip (requires prior approval)
BondRoute.tip( USDC, tip_amount, "Thanks from MyProtocol" );

// Native token tip
BondRoute.tip{ value: tip_amount }( NATIVE_TOKEN, tip_amount, "" );
```

Tips can be sent during bond execution or batched separately during off-peak times.

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

## Architecture

### Contract Inheritance

```
Storage
   ↓
Core          ← EIP-712 signing, bond execution logic
   ↓
User          ← create_bond(), execute_bond(), off-chain helpers
   ↓
Provider      ← transfer_funding(), announce_protocol()
   ↓
Sweeper       ← Expired bond liquidation, tip claiming
   ↓
BondRoute     ← Main entry point
```

### Core Contracts

| Contract | Purpose |
|----------|---------|
| `BondRoute.sol` | Main singleton entry point |
| `Sweeper.sol` | Expired bond cleanup, tip management |
| `Provider.sol` | Fund access for protocols, discoverability |
| `User.sol` | Bond creation and execution |
| `Core.sol` | Internal logic, EIP-712 |
| `Storage.sol` | State management |
| `BondRouteProtected.sol` | Single-file integration library |

### Technical Details

- **Storage**: One slot per bond
- **EIP-1153**: Transient storage with automatic fallback for chains without support
- **Deterministic deployment**: Same address on all EVM chains

---

## Trust Model

**Immutable contract.** No upgrades. No governance. Completely trustless.

**Free core primitive.** No fees. No rent. No gatekeepers.

**We get one shot.** Once deployed, it's permanent:
- ✓ No admin keys
- ✓ No upgrade patterns
- ✓ No fee switches
- ✓ Minimal sweeper role (expired bonds + tip collection only)
- ✓ Same deterministic address across all EVM chains

You don't need to trust us. You don't need to trust anyone. The code is immutable and verifiable on-chain.

**What you see is what you get. Forever.**

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

**What's the business case for integrating?**

It prevents execution-time value extraction, turning a known user risk into a competitive advantage.

**Does this lock us into a vendor relationship?**

No. BondRoute is immutable infrastructure with no admin keys. It can't be turned off, paywalled, or changed. Zero vendor risk.

**What's the regulatory profile?**

BondRoute is a commit-reveal primitive. No custody, no intermediaries, no orderflow. Same regulatory profile as any other on-chain library.

### For Devs

**Can I integrate if my contract is already deployed?**

- **Upgradeable**: Yes — add `BondRouteProtected` to your implementation
- **Immutable**: Deploy a new protected version

**Do I have to protect all functions?**

No. Only functions returned by `BondRoute_get_protected_selectors()` are protected. Other functions work normally.

**What if my function reverts?**

The bond settles gracefully and stake is refunded. Suspected bond farming reverts the transaction — legit users can fix the issue and retry.

**What happens to forfeited stakes?**

After 111 days, unexecuted bonds can be liquidated by the sweeper. The goal of stakes is deterrence, not revenue — users execute and get their stakes back.

**Why 111 days?**

Because BondRoute is immutable. The sweep window is set conservatively long to safely accommodate long-lived commitments (quarterly prediction markets, sealed-bid auctions, delayed execution) without risking accidental stake loss.

**What gas overhead should I expect?**

~45k gas for the full bond lifecycle. For context: a single storage write costs ~20k. That's less than $0.01 on Ethereum at 0.06 gwei with ETH at $3k.

**How do upgrades work?**

If a selector is removed from `BondRoute_get_protected_selectors()`, bonds targeting it settle gracefully with stake refunded. This enables selector-level pauses, function deprecation, and clean migrations.

**What about flash loans?**

Flash loans work perfectly. Execute bonds inside flash loan callbacks — borrowed capital funds executions, atomicity preserved.

**Can I use native ETH for stakes or fundings?**

Yes. Use `address(0)` (or `NATIVE_TOKEN` constant) for native ETH. No wrapping required.

### For Users

**Why do I need to create a bond before swapping?**

The bond hides your intent, preventing execution-time value extraction during the swap.

**What happens if I miss my execution window?**

You lose your stake. Execute within the protocol's time window to get it back automatically.

**What happens if I forget my salt?**

With a 32-bit salt (~4 billion combinations), you can brute-force recover it in minutes if you know your other parameters. With a 256-bit salt, recovery is impossible — store it safely.

**Is my approval to BondRoute safe?**

Yes. Funds stay in your wallet. BondRoute only enforces the limits you declare in each bond — it never holds your funds beyond the stake.

---

## Start Building

Don't settle for unfair markets.

1. Copy `BondRouteProtected.sol`
2. Inherit from `BondRouteProtected`
3. Implement `BondRoute_get_call_constraints()` and `BondRoute_get_protected_selectors()`
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

MIT License. See [LICENSE.md](LICENSE.md).

---

```
██████╗  ██████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
██████╔╝██║   ██║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║   ██║   ██║   █████╗
██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝
██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗
╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
                    CREATE • EXECUTE • OR GET REKT
```
