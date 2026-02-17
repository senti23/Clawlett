#!/usr/bin/env node

/**
 * Swap tokens via Uniswap V3 (via Safe + Zodiac Roles)
 *
 * Direct on-chain swaps through Uniswap V3 SwapRouter02 on Base.
 * The agent executes swaps through Zodiac Roles permissions.
 *
 * Features:
 * - Queries QuoterV2 across all fee tiers for best price
 * - Handles ETH wrapping via ZodiacHelpers (same as swap.js)
 * - Deadline protection via SwapRouter02 multicall
 * - Executes via Zodiac Roles (same security model as swap.js)
 * - Slippage protection with configurable tolerance
 *
 * Usage:
 *   node swap-uniswap.js --from ETH --to USDC --amount 0.1
 *   node swap-uniswap.js --from USDC --to ETH --amount 100 --execute
 *   node swap-uniswap.js --from USDC --to AERO --amount 50 --execute --slippage 1
 *
 * Requires: Uniswap permissions via initialize.js (v2+)
 */

import { ethers } from 'ethers'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { VERIFIED_TOKENS, ERC20_ABI, resolveToken } from './tokens.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

// ============================================================
//  Constants
// ============================================================

const WETH = '0x4200000000000000000000000000000000000006'
const UNISWAP_SWAP_ROUTER_02 = '0x2626664c2603336E57B271c5C0b26F421741e481'
const UNISWAP_QUOTER_V2 = '0x3d4e44Eb1374240CE5F1B871ab261CD16335B76a'
const FEE_TIERS = [100, 500, 3000, 10000]

const QUOTER_ABI = [
    'function quoteExactInputSingle((address tokenIn, address tokenOut, uint256 amountIn, uint24 fee, uint160 sqrtPriceLimitX96)) external returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate)',
]

// SwapRouter02 ABI — exactInputSingle struct does NOT include deadline
// Deadline is enforced via multicall(deadline, data[]) wrapper
const SWAP_ROUTER_ABI = [
    'function exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96)) external payable returns (uint256 amountOut)',
    'function multicall(uint256 deadline, bytes[] calldata data) external payable returns (bytes[] memory)',
]

const ROLES_ABI = [
    'function execTransactionWithRole(address to, uint256 value, bytes data, uint8 operation, bytes32 roleKey, bool shouldRevert) returns (bool)',
]

const ZODIAC_HELPERS_ABI = [
    'function wrapETH(uint256 amount) external',
    'function unwrapWETH(uint256 amount) external',
]

const APPROVAL_ABI = [
    'function approve(address spender, uint256 amount) returns (bool)',
    'function allowance(address owner, address spender) view returns (uint256)',
    'function balanceOf(address) view returns (uint256)',
]

// ============================================================
//  Config
// ============================================================

function loadConfig(configDir) {
    const configPath = path.join(configDir, 'wallet.json')
    if (!fs.existsSync(configPath)) {
        throw new Error(`Config not found: ${configPath}\nRun initialize.js first.`)
    }
    return JSON.parse(fs.readFileSync(configPath, 'utf8'))
}

function parseArgs() {
    const result = {
        from: null,
        to: null,
        amount: null,
        execute: false,
        slippage: 0.5, // 0.5% default
        timeout: 1800,  // 30 minutes deadline
        configDir: process.env.WALLET_CONFIG_DIR || path.join(__dirname, '..', 'config'),
        rpc: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
    }

    const args = process.argv.slice(2)
    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--from': case '-f': result.from = args[++i]; break
            case '--to': case '-t': result.to = args[++i]; break
            case '--amount': case '-a': result.amount = args[++i]; break
            case '--execute': case '-x': result.execute = true; break
            case '--slippage': case '-s': result.slippage = parseFloat(args[++i]); break
            case '--timeout': result.timeout = parseInt(args[++i]); break
            case '--config-dir': case '-c': result.configDir = args[++i]; break
            case '--rpc': case '-r': result.rpc = args[++i]; break
            case '--help': case '-h': printHelp(); process.exit(0)
        }
    }
    return result
}

function printHelp() {
    console.log(`
Usage: node swap-uniswap.js --from <TOKEN> --to <TOKEN> --amount <AMOUNT> [--execute]

Swap tokens via Uniswap V3 on Base (through Safe + Zodiac Roles).

Options:
  --from, -f      Source token (symbol or address)
  --to, -t        Destination token (symbol or address)
  --amount, -a    Amount of source token to swap
  --execute, -x   Execute swap (default: quote only)
  --slippage, -s  Slippage tolerance in % (default: 0.5)
  --timeout       Deadline in seconds (default: 1800 = 30 min)
  --config-dir    Config directory (default: ../config)
  --rpc           RPC URL (default: https://mainnet.base.org)

Notes:
  - ETH is auto-wrapped to WETH via ZodiacHelpers before swapping.
  - When buying ETH, you receive WETH (unwrap manually if needed).
  - Requires Uniswap permissions — wallets initialized with v2+ have these.

Examples:
  node swap-uniswap.js --from ETH --to USDC --amount 0.1
  node swap-uniswap.js --from USDC --to AERO --amount 50 --execute
  node swap-uniswap.js --from ETH --to USDC --amount 0.01 --execute --slippage 1
`)
}

function formatAmount(amount, decimals, symbol) {
    return `${ethers.formatUnits(amount, decimals)} ${symbol}`
}

// ============================================================
//  Quote
// ============================================================

async function getBestQuote(tokenIn, tokenOut, amountIn, provider) {
    const quoter = new ethers.Contract(UNISWAP_QUOTER_V2, QUOTER_ABI, provider)

    let bestAmountOut = 0n
    let bestFee = null
    let bestGasEstimate = null

    for (const fee of FEE_TIERS) {
        try {
            const result = await quoter.quoteExactInputSingle.staticCall({
                tokenIn: tokenIn.address === ethers.ZeroAddress ? WETH : tokenIn.address,
                tokenOut: tokenOut.address === ethers.ZeroAddress ? WETH : tokenOut.address,
                amountIn,
                fee,
                sqrtPriceLimitX96: 0,
            })

            const amountOut = result[0]
            if (amountOut > bestAmountOut) {
                bestAmountOut = amountOut
                bestFee = fee
                bestGasEstimate = result[3] ? Number(result[3]) : null
            }
        } catch (e) {
            // No pool for this fee tier — skip
            continue
        }
    }

    if (!bestFee) {
        throw new Error('No Uniswap V3 liquidity found for this pair on any fee tier')
    }

    return {
        amountOut: bestAmountOut,
        fee: bestFee,
        feeLabel: (bestFee / 10000).toFixed(2) + '%',
        gasEstimate: bestGasEstimate,
    }
}

// ============================================================
//  Swap Execution
// ============================================================

async function executeSwap(config, tokenIn, tokenOut, amountIn, wrapAmount, quote, slippage, timeout, wallet, provider) {
    const roles = new ethers.Contract(config.roles, ROLES_ABI, wallet)
    const routerInterface = new ethers.Interface(SWAP_ROUTER_ABI)
    const approvalInterface = new ethers.Interface(APPROVAL_ABI)

    const isETHIn = tokenIn.symbol === 'ETH' || tokenIn.address === ethers.ZeroAddress
    const isETHOut = tokenOut.symbol === 'ETH' || tokenOut.address === ethers.ZeroAddress

    const actualTokenIn = isETHIn ? WETH : tokenIn.address
    const actualTokenOut = isETHOut ? WETH : tokenOut.address

    // Calculate minimum output with slippage
    const slippageBps = BigInt(Math.floor(slippage * 100))
    const amountOutMinimum = quote.amountOut - (quote.amountOut * slippageBps / 10000n)

    const safeAddress = config.safe

    // Step 1: Wrap ETH → WETH if needed (via ZodiacHelpers, same as swap.js)
    if (wrapAmount > 0n) {
        const zodiacHelpersAddress = config.contracts?.ZodiacHelpers
        if (!zodiacHelpersAddress) {
            throw new Error('ZodiacHelpers address not found in config. Re-run initialize.js.')
        }

        console.log(`   Wrapping ${formatAmount(wrapAmount, 18, 'ETH')} → WETH...`)
        const zodiacHelpers = new ethers.Interface(ZODIAC_HELPERS_ABI)
        const wrapData = zodiacHelpers.encodeFunctionData('wrapETH', [wrapAmount])

        const wrapTx = await roles.execTransactionWithRole(
            zodiacHelpersAddress,
            0n,
            wrapData,
            1, // delegatecall (same as swap.js)
            config.roleKey,
            true
        )
        console.log(`   Wrap TX: ${wrapTx.hash}`)
        await wrapTx.wait()
    }

    // Step 2: Approve token for router (if needed)
    console.log('   Checking approval...')
    const tokenContract = new ethers.Contract(actualTokenIn, APPROVAL_ABI, provider)
    const currentAllowance = await tokenContract.allowance(safeAddress, UNISWAP_SWAP_ROUTER_02)

    if (currentAllowance < amountIn) {
        console.log('   Approving router for ' + (isETHIn ? 'WETH' : tokenIn.symbol) + '...')
        const approveData = approvalInterface.encodeFunctionData('approve', [
            UNISWAP_SWAP_ROUTER_02, amountIn
        ])

        const approveTx = await roles.execTransactionWithRole(
            actualTokenIn,
            0n,
            approveData,
            0, // call
            config.roleKey,
            true
        )
        console.log(`   Approval TX: ${approveTx.hash}`)
        await approveTx.wait()
    } else {
        console.log('   Already approved')
    }

    // Step 3: Execute swap via multicall (enforces deadline)
    console.log('   Executing swap...')
    const deadline = Math.floor(Date.now() / 1000) + timeout

    const swapParams = {
        tokenIn: actualTokenIn,
        tokenOut: actualTokenOut,
        fee: quote.fee,
        recipient: safeAddress,
        amountIn,
        amountOutMinimum,
        sqrtPriceLimitX96: 0,
    }

    // Encode exactInputSingle, then wrap in multicall for deadline protection
    const swapCalldata = routerInterface.encodeFunctionData('exactInputSingle', [swapParams])
    const multicallData = routerInterface.encodeFunctionData('multicall', [deadline, [swapCalldata]])

    const swapTx = await roles.execTransactionWithRole(
        UNISWAP_SWAP_ROUTER_02,
        0n,
        multicallData,
        0, // call
        config.roleKey,
        true
    )

    console.log(`   Swap TX: ${swapTx.hash}`)
    const receipt = await swapTx.wait()

    return {
        hash: swapTx.hash,
        receipt,
    }
}

// ============================================================
//  Main
// ============================================================

async function main() {
    const args = parseArgs()

    if (!args.from || !args.to || !args.amount) {
        console.error('Error: --from, --to, and --amount are required')
        printHelp()
        process.exit(1)
    }

    const config = loadConfig(args.configDir)
    const provider = new ethers.JsonRpcProvider(args.rpc)

    // Resolve tokens
    console.log('\nResolving tokens...')
    let tokenIn = await resolveToken(args.from, provider)
    let tokenOut = await resolveToken(args.to, provider)

    const isETHIn = tokenIn.symbol === 'ETH' || tokenIn.address === ethers.ZeroAddress
    const isETHOut = tokenOut.symbol === 'ETH' || tokenOut.address === ethers.ZeroAddress

    console.log(`From: ${tokenIn.symbol} ${tokenIn.verified ? '(verified)' : '(unverified)'}`)
    console.log(`      ${tokenIn.address}`)
    console.log(`To:   ${tokenOut.symbol} ${tokenOut.verified ? '(verified)' : '(unverified)'}`)
    console.log(`      ${tokenOut.address}`)

    if (isETHIn) console.log('Note: Will wrap ETH → WETH via ZodiacHelpers before swapping.')
    if (isETHOut) console.log('Note: Will receive WETH. Use unwrapWETH if you need native ETH.')

    // Parse amount
    const amountIn = ethers.parseUnits(args.amount, tokenIn.decimals)
    const safeAddress = config.safe

    // Check balance & calculate wrap amount (same logic as swap.js)
    let wrapAmount = 0n
    if (isETHIn) {
        const ethBal = await provider.getBalance(safeAddress)
        const wethContract = new ethers.Contract(WETH, APPROVAL_ABI, provider)
        const wethBal = await wethContract.balanceOf(safeAddress)

        console.log(`\nSafe ETH balance:  ${formatAmount(ethBal, 18, 'ETH')}`)
        console.log(`Safe WETH balance: ${formatAmount(wethBal, 18, 'WETH')}`)

        if (wethBal >= amountIn) {
            // Have enough WETH already, no wrapping needed
            wrapAmount = 0n
        } else if (wethBal + ethBal >= amountIn) {
            // Wrap only what's needed
            wrapAmount = amountIn - wethBal
            console.log(`Will wrap ${formatAmount(wrapAmount, 18, 'ETH')} → WETH`)
        } else {
            console.error('\nInsufficient ETH + WETH balance')
            console.error(`Need ${formatAmount(amountIn, 18, 'WETH')}, have ${formatAmount(wethBal, 18, 'WETH')} + ${formatAmount(ethBal, 18, 'ETH')}`)
            process.exit(1)
        }
    } else {
        const tokenContract = new ethers.Contract(tokenIn.address, ERC20_ABI, provider)
        const balance = await tokenContract.balanceOf(safeAddress)
        console.log(`\nSafe ${tokenIn.symbol} balance: ${formatAmount(balance, tokenIn.decimals, tokenIn.symbol)}`)
        if (balance < amountIn) {
            console.error(`\nInsufficient ${tokenIn.symbol} balance`)
            process.exit(1)
        }
    }

    // Get quote
    console.log('\nGetting Uniswap V3 quote...')
    const quote = await getBestQuote(tokenIn, tokenOut, amountIn, provider)

    const amountOutFormatted = ethers.formatUnits(quote.amountOut, tokenOut.decimals)
    const slippageBps = BigInt(Math.floor(args.slippage * 100))
    const minOut = quote.amountOut - (quote.amountOut * slippageBps / 10000n)
    const minOutFormatted = ethers.formatUnits(minOut, tokenOut.decimals)

    console.log()
    console.log('=======================================================')
    console.log('              UNISWAP V3 SWAP SUMMARY')
    console.log('=======================================================')
    console.log(`  You pay:      ${args.amount} ${tokenIn.symbol}`)
    console.log(`  You receive:  ~${amountOutFormatted} ${tokenOut.symbol}`)
    console.log(`  Min receive:  ${minOutFormatted} ${tokenOut.symbol} (${args.slippage}% slippage)`)
    console.log(`  Pool fee:     ${quote.feeLabel}`)
    if (quote.gasEstimate) console.log(`  Est. gas:     ${quote.gasEstimate.toLocaleString()}`)
    console.log(`  Deadline:     ${args.timeout}s`)
    console.log(`  Router:       Uniswap V3 SwapRouter02`)

    if (!args.execute) {
        console.log()
        console.log('  Add --execute to perform this swap')
        console.log('=======================================================')
        process.exit(0)
    }

    // Execute
    console.log()
    console.log('  EXECUTING...')
    console.log()

    // Load agent wallet
    const agentPkPath = path.join(args.configDir, 'agent.pk')
    if (!fs.existsSync(agentPkPath)) {
        throw new Error(`Agent key not found: ${agentPkPath}`)
    }
    const agentPk = fs.readFileSync(agentPkPath, 'utf8').trim()
    const wallet = new ethers.Wallet(agentPk, provider)

    const result = await executeSwap(config, tokenIn, tokenOut, amountIn, wrapAmount, quote, args.slippage, args.timeout, wallet, provider)

    // Check new balance
    let newBalance
    if (isETHOut) {
        const wethContract = new ethers.Contract(WETH, APPROVAL_ABI, provider)
        newBalance = formatAmount(await wethContract.balanceOf(safeAddress), 18, 'WETH')
    } else {
        const outContract = new ethers.Contract(tokenOut.address, ERC20_ABI, provider)
        const bal = await outContract.balanceOf(safeAddress)
        newBalance = formatAmount(bal, tokenOut.decimals, tokenOut.symbol)
    }

    console.log('  SWAP COMPLETE')
    console.log(`   Sold: ${args.amount} ${tokenIn.symbol}`)
    console.log(`   Received: ~${amountOutFormatted} ${tokenOut.symbol}`)
    console.log(`   New ${tokenOut.symbol} balance: ${newBalance}`)
    console.log(`   Explorer: https://basescan.org/tx/${result.hash}`)
    console.log('=======================================================')
}

main().catch(e => {
    console.error('Error:', e.message)
    process.exit(1)
})
