# Claw Wallet

Secure token swaps via Aerodrome on **Base Mainnet**, powered by Safe + Zodiac Roles.

> **Network: Base Mainnet (Chain ID: 8453)**

## Overview

This skill enables autonomous token swaps through a Gnosis Safe. The agent operates through Zodiac Roles which restricts operations to:
- Swapping tokens via Aerodrome Router
- Approving tokens only for the Aerodrome Router
- Sending swapped tokens only back to the Safe (no draining)

## Capabilities

| Action | Autonomous | Notes |
|--------|------------|-------|
| Check balances | ✅ | ETH and any ERC20 on Base Mainnet |
| Get swap quote | ✅ | Via Aerodrome Router |
| Swap tokens | ✅ | Any pair with liquidity |
| Approve tokens | ✅ | Only for Aerodrome Router |
| Transfer funds | ❌ | Blocked by Roles |

## Token Safety

Protected tokens can ONLY resolve to verified Base Mainnet addresses:

| Token | Verified Address |
|-------|-----------------|
| ETH | Native ETH (use `0x0000000000000000000000000000000000000000` for swaps) |
| WETH | `0x4200000000000000000000000000000000000006` |
| USDC | `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913` |
| USDT | `0xfde4C96c8593536E31F229EA8f37b2ADa2699bb2` |
| DAI | `0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb` |
| AERO | `0x940181a94A35A4569E4529A3CDfB74e38FD98631` |
| cbBTC | `0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf` |
| BID | `0xa1832f7F4e534aE557f9B5AB76dE54B1873e498B` |

If a scam token impersonates these symbols, the agent will detect and warn.

## Setup

1. Owner provides their wallet address
2. Agent generates keypair → **Owner sends 0.001 ETH on Base Mainnet** to agent for gas
3. Agent deploys Safe on Base Mainnet (owner as sole owner)
4. Agent deploys Zodiac Roles with Aerodrome permissions
5. Agent removes itself as Safe owner (keeps Roles access)
6. **Owner funds Safe on Base Mainnet** with tokens to trade

## Usage

### Initialize
```
Initialize my wallet with owner 0x123...
```

### Check Balance
```
What's my balance?
How much USDC do I have?
```

### Swap Tokens
```
Swap 0.1 ETH for USDC
Swap 100 USDC for ETH
Exchange 50 DAI to AERO
Trade my DEGEN for BRETT
```

**Example confirmation prompt:**
```
Swap Details (Base Mainnet)
─────────────────────────────
From:     0.1 ETH
          0x4200000000000000000000000000000000000006 (WETH)

To:       ~250.45 USDC
          0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 (USDC)

Rate:     1 ETH = 2,504.50 USDC
Minimum:  237.93 USDC (after 5% slippage)
Impact:   <0.01%

Proceed with swap? (yes/no)
```

The agent will:
1. Resolve token symbols (with scam protection)
2. Get quote from Aerodrome
3. **Display swap details for confirmation:**
   - Token symbols (e.g., ETH → USDC)
   - Token addresses (verified Base Mainnet contracts)
   - Input amount (what you're selling)
   - Output amount (estimated amount you'll receive)
   - Minimum output (after slippage)
   - Slippage tolerance (default: 5%, range 0-50% via 0-0.5)
   - Exchange rate
   - Price impact (if significant)
4. Ask for explicit user confirmation
5. Execute via Safe + Roles

## Scripts

| Script | Description |
|--------|-------------|
| `initialize.js` | Deploy Safe + Roles with Aerodrome permissions |
| `swap.js` | Swap tokens via Aerodrome |
| `balance.js` | Check ETH and token balances |

### Examples

```bash
# Initialize
node skills/wallet/scripts/initialize.js --owner 0x123...

# Check balance
node skills/wallet/scripts/balance.js
node skills/wallet/scripts/balance.js --token USDC

# Get swap quote
node skills/wallet/scripts/swap.js --from ETH --to USDC --amount 0.1

# Execute swap
node skills/wallet/scripts/swap.js --from ETH --to USDC --amount 0.1 --execute

# With custom slippage (0-0.5 range, e.g., 0.05 = 5%)
node skills/wallet/scripts/swap.js --from ETH --to USDC --amount 0.1 --slippage 0.03 --execute
```

## Configuration

Scripts read from `config/wallet.json` (configured for Base Mainnet):

```json
{
  "chainId": 8453,  // Base Mainnet
  "owner": "0x...",
  "agent": "0x...",
  "safe": "0x...",
  "roles": "0x...",
  "roleKey": "0x..."
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_RPC_URL` | `https://mainnet.base.org` | Base Mainnet RPC endpoint |
| `WALLET_CONFIG_DIR` | `skills/wallet/config` | Config directory |

## Contracts (Base Mainnet)

| Contract | Address | Description |
|----------|---------|-------------|
| Aerodrome Universal Router | `0x6Df1c91424F79E40E33B1A48F0687B666bE71075` | All swaps (V2 + CL) |
| ZodiacHelpers | `0xc235D2475E4424F277B53D19724E2453a8686C54` | Token approvals + swaps via delegatecall |
| Safe Singleton | `0x3E5c63644E683549055b9Be8653de26E0B4CD36E` | Safe L2 impl |
| Safe Factory | `0xa6B71E26C5e0845f74c812102Ca7114b6a896AB2` | Safe deployer |
| Roles Singleton | `0x9646fDAD06d3e24444381f44362a3B0eB343D337` | Zodiac Roles |
| Module Factory | `0x000000000000aDdB49795b0f9bA5BC298cDda236` | Module deployer |

## Security Model

1. **Safe holds all funds** - Agent wallet only has gas
2. **Zodiac Roles restricts operations**:
   - Can only call Aerodrome Universal Router
   - Swap `to` parameter scoped to Safe address only
   - Can only approve tokens for Aerodrome Router
3. **No transfer/withdraw** - Agent cannot move funds out
4. **Scam protection** - Common tokens resolve to verified addresses only
