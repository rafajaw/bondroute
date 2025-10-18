# BondRoute

Every transaction you send is naked in the mempool. Visible. Vulnerable. Exploitable.

The cypherpunks dreamed of privacy. The blockchain delivered transparency. 
Someone fucked up.

**BondRoute fixes what got left behind.**

## Execute or Get Rekt

We built the commit-reveal primitive that should have shipped with Ethereum. Hide your intent. Stake your conviction. Reveal when ready.

No committees. No governance. No "we'll fix it in v2."  
Just immutable code that works.

## Why Everyone Pretends This Is Fine

You know that feeling when your swap gets sandwiched? When your bid gets front-run? When your vote gets gamed?

That's not MEV. That's the mempool working as designed.

**Every blockchain application leaks information:**
- 🎮 **Games** leak your moves
- 💰 **DeFi** leaks your trades  
- 🗳️ **DAOs** leak your votes
- 🎲 **Prediction markets** leak your alpha
- 🎨 **NFT drops** leak your intent
- 🔮 **Everything** leaks everything

We're the plumbers. We fixed the leak.

## The Technical Truth

```solidity
// The old way: broadcast your sins
function swap(uint256 amount) external {
    // "Hey MEV bots, here's exactly what I'm doing!"
    transfer(amount);
    doSwap();
    // *gets sandwiched*
    // *cries*
}

// The BondRoute way: commit in shadows, execute in light
contract YourDEX is BondRouteProtected {
    function swap(uint256 amount) external onlyBondRoute {
        BondRouteContext memory ctx = BondRoute_initialize();
        
        BondRoute_pull(USDC, amount);       // Pull from virtual escrow
        uint256 output = _performSwap();    // Your secret sauce
        BondRoute_push(WETH, output);       // Push to escrow for next call
    }
}
```

**The Flow:**
1. **COMMIT** - User creates a bond with `create_bond()`
   - Hash your `ExecutionData` (calls + funding + secret)
   - Stake multiple tokens as collateral (up to 9 different tokens)
   - Commitment visible, intent hidden

2. **REVEAL** - User executes with `execute_bond()`
   - Reveal your `ExecutionData` 
   - BondRoute validates commitment match
   - Calls your contracts atomically via `BondRoute_entry_point()`

3. **SETTLE** - Everything resolves or reverts
   - Virtual escrow handles all transfers (LIFO)
   - Negligible 0.01% fee on funds pulled/sent from virtual escrow
   - Unused stake returns, or gets lost if you don't execute

## Why Simple Commit-Reveal Isn't Enough

**The Naive Attack:**
Basic commit-reveal stops simple front-running. But sophisticated attackers can pre-commit multiple bonds and selectively execute only profitable ones.

**Example: Auction Attack**
1. Attacker creates 4 bonds for a blind auction
2. Each bond bids: 100, 200, 300, and 400 ETH
3. During reveal window, attacker sees highest bid is 290 ETH
4. Attacker executes only the 300 ETH bond - wins without overpaying
5. Other bonds expire harmlessly, attacker pays nothing

**The Bond-Picking Problem:**
Without consequences, attackers create unlimited bonds and cherry-pick execution. This breaks the economic game theory that makes commit-reveal work.

## BondRoute's Solution: Economic Deterrence

**Stake-to-Play:**
Each bond requires tokens staked as collateral. Non-executed bonds forfeit their stakes.

**Example: Auction Defense**
1. Blind auction contract requires 10% stake of bid amount
2. Attacker wants to bid 100, 200, 300, 400 ETH
3. Must stake: 10, 20, 30, 40 ETH respectively  
4. Executes only 300 ETH bond, loses stakes from others
5. **Loss: 10 + 20 + 40 = 70 ETH forfeited**
6. Attack becomes economically irrational

**Application-Level Security:**
Each `BondRouteProtected` contract defines its own requirements:
- Minimum delay between commit and reveal
- Required stake token and amount
- Execution time windows
- Bond creation constraints

```solidity
function BondRoute_get_execution_constraints(
    bytes calldata target_calldata,
    IERC20 preferred_stake_token, 
    TokenAmount[] memory preferred_fundings
) external view override returns (ExecutionConstraints memory) {
    // Decode target_calldata to see what function is being called
    bytes4 selector = bytes4(target_calldata);
    
    if (selector == this.bid.selector) {
        uint256 bid_amount = abi.decode(target_calldata[4:], (uint256));
        return ExecutionConstraints({
            stake: TokenAmount({
                token: WETH,                        // Require WETH stake
                amount: bid_amount / 10             // 10% of bid amount
            }),
            max_bond_execution_time: auction_end,  // Must execute before auction ends
            // ... other constraints
        });
    }
    
    // Different function might have different requirements
    return ExecutionConstraints(/* ... */);
}
```

**Architecture that matters:**
- **IBondRoute**: The singleton everyone talks to
- **IUser**: Create and execute bonds with multi-token staking
- **IProvider**: Pull/push/send funds in virtual escrow
- **IBondRouteProtected**: What your contracts inherit
- **No proxies, no upgrades, no bullshit**

## Virtual Escrow

Forget holding tokens. We track intentions.

```solidity
// Alice's contract pushes 1000 USDC (no fee, full 1000 available)
BondRoute_push(USDC, 1000);

// Bob's contract pushes 500 USDC (no fee, full 500 available)
BondRoute_push(USDC, 500);

// Charlie pulls 800 USDC (pays 0.08 USDC fee, receives 799.92 USDC)
BondRoute_pull(USDC, 800);
// NOW transfers happen: 500 from Bob + 300 from Alice (LIFO)
// Fee charged on pull, Charlie pays 800 but receives 799.92
```

**Critical**: Approve BondRoute before pushing. We'll `transferFrom` when someone pulls.

## For Builders Who Give a Damn

Copy `BondRouteProtected.sol` into your project. No dependencies. No npm packages. No centralized anything.

Then inherit and implement one function:

```solidity
contract YourProtocol is BondRouteProtected {
    
    // The ONLY function you must implement
    function BondRoute_get_execution_constraints(
        bytes calldata target_calldata,
        IERC20 preferred_stake_token, 
        TokenAmount[] memory preferred_fundings
    ) external view override returns (ExecutionConstraints memory) {
        // Decode the calldata, check what function is being called
        // Return your requirements: timing, stake, funding
        // Or return empty constraints if you're feeling brave
    }
    
    // Your actual functions, now MEV-protected
    function trade(uint256 amount) external onlyBondRoute {
        BondRouteContext memory ctx = BondRoute_initialize();
        // Pull, swap, push. Simple.
    }
}
```

**Security by Design:**
- Prevents bond-picking (can't create 100 bonds, execute only profitable)
- Validates contracts implement `BondRoute_is_BondRouteProtected()`
- Out-of-gas detection prevents selective execution
- Stakes forfeit after 101 days. No mercy.

## For Users Who Want Fair Markets

Stop feeding the bots. Start using BondRoute.

1. **Commit your intent** (hidden from MEV)
   - Stake tokens as required by the target contracts
   - Fund with whatever tokens your strategy needs
   - Fees are only charged when pulling/sending funds (0.01%)

2. **Wait 1+ blocks** (as target contracts require)  

3. **Execute your bond** (atomic, protected)
   - Stakes become funding when tokens match (capital efficiency)
   - Fees collected when funds are pulled/sent during execution

4. **Get what you deserve** (not what bots leave you)

**Deployed everywhere:**
- **Mainnet**: `0x...` (see deployment artifacts)
- **Arbitrum**: `0x...` (same address)
- **Base**: `0x...` (same address)
- Same deterministic address across all chains.

## Multi-Call Bonds

Execute multiple protected operations atomically.

```solidity
// Example: Unstake then trade - different stake requirements per call
ExecutionData memory execution_data = ExecutionData({
    fundings: fundings_array,
    calls: [
        CallEntry({
            _contract: staking_pool,
            _calldata: abi.encodeWithSelector(IStaking.withdraw.selector, 1000e18),
            stake: TokenAmount(STAKING_TOKEN, 50e18)  // Staking pool requires their token
        }),
        CallEntry({
            _contract: dex_contract, 
            _calldata: abi.encodeWithSelector(IDEX.swap.selector, withdrawn_amount),
            stake: TokenAmount(DEX_TOKEN, 10e18)      // DEX requires their governance token
        })
    ],
    secret: keccak256("my_secret")
});

// Create bond with all required stakes
TokenAmount[] memory stakes = new TokenAmount[](2);
stakes[0] = TokenAmount(STAKING_TOKEN, 50e18);  // For staking pool withdrawal
stakes[1] = TokenAmount(DEX_TOKEN, 10e18);      // For DEX trade
bondroute.create_bond(commitment_proof, stakes, block.timestamp + 300);
```

**How Stake Requirements Work:**
- Each contract call specifies its own stake token and amount
- User must stake enough of each required token across all calls
- When stake token matches funding token, stakes become funding
- Stakes consumed first (LIFO), maximize your trading power

## The Uncomfortable Truth

We had one shot at deployment. No mulligans. No "DAO proposals."

**We committed to:**
- ✓ Immutable contracts forever
- ✓ 0.01% fee forever (not 1%, not 0.1%, only 0.01%)
- ✓ Minimal admin functions (treasury management, expired bond cleanup)
- ✓ No upgrades ever
- ✓ Execute or get rekt

**Pull $10,000. Pay $1.**

How much is MEV protection worth to you? We think it's worth a buck.

Don't wanna pay even our tiny 0.01% fee for your MEV protection? FFS, fine!
Create and execute bonds for free. Just don't touch our push/pull escrow system. Zero fees, zero hand-holding.

## Join the Revolution

The mempool dark age is ending. You're either building the solution or funding the problem.

**Everything you need is in this repository:**
- **Integration**: See `src/integrations/BondRouteProtected.sol`
- **Examples**: Check `test/` directory for real usage patterns
- **Security**: Read the contracts - code is the spec

**Immutable. Unstoppable. No governance. No upgrades.**

---

*"In a world of infinite forks, we chose immutability."*

### Start Building → Import `BondRouteProtected.sol`
### Start Using → Call `create_bond()` then `execute_bond()`
### Read More → The contracts are the documentation

---

```
██████╗  ██████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
██████╔╝██║   ██║██╔██╗ ██║██║  ██║██████╔╝██║   ██║██║   ██║   ██║   █████╗  
██╔══██╗██║   ██║██║╚██╗██║██║  ██║██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  
██████╔╝╚██████╔╝██║ ╚████║██████╔╝██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗
╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝

                    COMMIT • REVEAL • EXECUTE • OR GET REKT
```