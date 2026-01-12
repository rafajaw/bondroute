# BondRoute Mechanism Deep Dive

This document explains how BondRoute actually works — the game theory, the trap mechanism, and why speculation is unprofitable.

Read this if you want to understand the mechanism beyond the README overview.

---

## Core Mental Model

**The defense is NOT primarily about hiding intent.**

Traditional commit-reveal schemes hide intent during the commit phase, but at reveal time attackers can still frontrun. Critics say "commit-reveal doesn't prevent MEV."

**BondRoute is different.** At reveal time, attackers cannot frontrun because:

1. Protected functions reject naked (unbonded) calls
2. Attackers couldn't have created bonds — they didn't know what to bond for
3. Even if they bonded speculatively, the economics trap them

**The two pillars:**

| Pillar | What it does |
|--------|--------------|
| **Reserved Execution** | Protected functions reject naked calls. You MUST have a bond to execute. |
| **Binding Economics** | Fixed parameters + stake = no free optionality. Bonds that "succeed" at unfavorable terms trap you. |

---

## The Trap Mechanism

This is the key insight that makes BondRoute work.

### What Most People Think

> "If you don't execute, you lose stake."

### What Actually Happens

> "If your bond's parameters 'succeed' but the outcome is unfavorable, you're trapped — execute a bad trade OR forfeit stake."

The bonds that FAIL (slippage exceeded, bid too low) return stake gracefully.

The bonds that "SUCCEED" at bad terms are the trap.

---

## Example 1: Swaps

### Setup

- User wants to swap 1,000 USDC → ETH
- Creates bond with: `amountIn: 1000 USDC`, `amountOutMin: 0.50 ETH` (implies ~$2000/ETH)
- Stake: 1% = 10 USDC

### Honest User Flow

1. Create bond at current market price with reasonable slippage (2-5%)
2. Wait 1 block
3. Execute — get ETH, stake returned
4. If market moved beyond slippage → graceful failure, stake returned

### Attacker Tries to Speculate

Bot creates 10 bonds covering different price scenarios:

| Bond | amountOutMin | Strategy |
|------|--------------|----------|
| 1 | 0.50 ETH | Tight (~$2000) |
| 2 | 0.48 ETH | |
| 3 | 0.46 ETH | |
| ... | ... | |
| 10 | 0.30 ETH | Very loose (~$3333) |

**Price moves UP ($2000 → $2100):**

For 1,000 USDC, bot now gets ~0.476 ETH.

| Bond | amountOutMin | Result |
|------|--------------|--------|
| 1 | 0.50 ETH | FAILS — 0.476 < 0.50, slippage exceeded, **stake returned** |
| 2 | 0.48 ETH | FAILS — 0.476 < 0.48, slippage exceeded, **stake returned** |
| 3 | 0.46 ETH | SUCCEEDS — 0.476 ≥ 0.46 ✓ |
| 4-10 | lower | SUCCEEDS — all pass ✓ |

### The Trap

Bonds 3-10 all "succeed" — they pass the slippage check. But the bot wanted price to go DOWN (more ETH). Price went UP (less ETH).

Now the bot must choose for each of bonds 3-10:

| Choice | Outcome |
|--------|---------|
| **Execute** | Get stake back, BUT execute swap at unfavorable price |
| **Don't execute** | Forfeit stake |

**Either way, the bot loses.** The bonds that "succeed" are the trap, not the ones that fail.

### Why Slippage Becomes a Double-Edged Sword

**For honest users:** Slippage protects from bad fills. Set reasonable tolerance, execute, done.

**For speculators:**

| Slippage | What happens |
|----------|--------------|
| Tight | Fails on small moves, stake returned (free exit, but no upside) |
| Loose | "Succeeds" even on bad moves, trapped into executing or forfeiting |

You can't have free optionality. Tight = free exit but no opportunity. Loose = trapped.

---

## Example 2: Blind Auctions

### Setup

- Auction for an item
- Attacker creates bonds for bids: $100, $200, $300... $900
- Each bond requires stake (10% of bid)
- Winning price turns out to be $500

### What Happens to Each Bid

| Bid | vs Winning ($500) | Result |
|-----|-------------------|--------|
| $100-$400 | Below | Execute → Lose auction → **stake returned** |
| $500 | Equal | Execute → WIN at fair price → **stake returned** |
| $600-$900 | Above | **TRAPPED** |

### The Trap (Overbids $600-$900)

These "overbids" are above the winning price. If executed, you WIN the auction but PAY your bid amount — overpaying for something that sold at $500.

| Choice | Outcome |
|--------|---------|
| **Execute overbid** | Win but overpay (bad outcome), stake returned |
| **Don't execute** | Forfeit stake |

**Either way, the bot loses on overbids.**

The bids below winning price gracefully "lose" and recover stake. The overbids are the trap.

---

## The Universal Pattern

In ANY protocol using BondRoute:

| Category | What happens |
|----------|--------------|
| **Below threshold** | Slippage exceeded, bid too low, etc. → Graceful failure, stake returned |
| **Above threshold** | Within slippage, bid wins, etc. → Must execute or forfeit |

The trap is always in category 2: bonds that "succeed" at unfavorable terms.

**For honest users:** Set reasonable params, execute intended action, done.

**For speculators:** Can't cover all scenarios without getting trapped on the "successful" but unfavorable bonds.

---

## Why This Works

### The Economics of Speculation

To speculate profitably, an attacker needs:

1. **Multiple positions** covering different outcomes
2. **Ability to abandon** unprofitable positions cheaply
3. **Ability to execute** only the profitable one

BondRoute breaks requirement #2. You can't abandon bonds that "succeed" for free.

### The Math

If an attacker creates N bonds covering a range of outcomes:

- Some bonds will fail validation → stake returned (no cost, no gain)
- Some bonds will "succeed" at unfavorable terms → **trapped**
- At most one bond will succeed at favorable terms → profit

For speculation to pay, the profit from the one winning bond must exceed the losses from all the trapped bonds. As stake requirements increase relative to potential profit, speculation becomes unprofitable.

---

## Common Misconceptions

### "Commit-reveal doesn't prevent MEV"

Traditional commit-reveal: At reveal, attackers see and frontrun.

BondRoute: At reveal, attackers can't frontrun because protected functions reject unbonded calls. No bond = rejected. And attackers couldn't have bonded in advance — they didn't know what to bond for.

### "Just abandon the bad bonds"

You can't abandon bonds that "succeed" for free. If your params pass validation, you either execute (bad outcome) or forfeit stake.

### "The defense is hiding intent"

Hiding helps, but the real defense is:
1. Requiring bonds (reserved execution)
2. Making speculation unprofitable (the trap mechanism)

### "Each attempt costs real money"

Imprecise. Failed attempts (slippage exceeded, bid too low) return stake. The cost is in the TRAP — bonds that succeed at bad terms force bad outcomes or forfeit.

---

## Key Terminology

| Term | Meaning |
|------|---------|
| **Naked call** | A call to a protected function without a bond. Rejected. |
| **Bond farming** | Creating multiple bonds to speculate on different outcomes, executing only profitable ones. Unprofitable because trapped bonds force losses. |
| **Reserved execution** | Protected functions require a bond to execute. |
| **Binding economics** | Fixed params + stake = no free optionality. |
| **The trap** | Bonds that "succeed" at unfavorable terms force you to execute a bad outcome or forfeit stake. |

---

## Summary

BondRoute doesn't just hide intent. It makes speculation unprofitable.

1. **Reserved execution** — Can't frontrun without a bond
2. **Binding economics** — Can't speculate without getting trapped

The trap isn't losing stake on abandoned bonds. The trap is being forced to choose between executing a bad trade or forfeiting stake on bonds that technically "succeed."

Honest users are unaffected — they create one bond, execute it, get stake back.

Speculators can't win — covering multiple outcomes means getting trapped on the ones that "succeed" at bad terms.
