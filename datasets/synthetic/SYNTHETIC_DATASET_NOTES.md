# Synthetic Dataset — Source Notes

## Directory Structure

Contracts are organized into per-vulnerability subdirectories:

```
datasets/synthetic/
  reentrancy/positive/   negative/
  dos/positive/          negative/   edge/
  delegatecall/positive/ negative/
  nuanced_access_control/positive/  negative/
  asset_locking/positive/           negative/
  logic_validation/positive/        negative/
```

Each subdirectory contains either original synthetic contracts or adapted public examples (see below).

---

## Track A (Structural)

### Reentrancy

| File | Pattern source |
|------|---------------|
| `reentrancy/positive/reentrancy_01.sol` | Synthetic — CEI violation pattern from SWC-107 |
| `reentrancy/positive/simple_dao.sol` | **Public** — SimpleDAO from [SmartBugs](https://github.com/smartbugs/smartbugs) (`reentrancy/simple_dao.sol`) and [SWC-107](https://swcregistry.io/docs/SWC-107) |
| `reentrancy/negative/reentrancy_02.sol` | Synthetic — ReentrancyGuard negative control |
| `reentrancy/negative/reentrancy_cei_safe.sol` | Synthetic — Correct CEI negative control for simple_dao |

### DoS

| File | Pattern source |
|------|---------------|
| `dos/positive/dos_01_real_auction.sol` | Synthetic — DoS via inline external call with require |
| `dos/positive/dos_02_refund_required.sol` | Synthetic — DoS via require(success) |
| `dos/positive/king_of_ether.sol` | **Public** — KingOfTheEtherThrone from [SmartBugs](https://github.com/smartbugs/smartbugs) (`denial_of_service/king_of_ether.sol`) and [SWC-113](https://swcregistry.io/docs/SWC-113) |
| `dos/negative/dos_03_pull_payment_safe.sol` | Synthetic — pull-payment pattern |
| `dos/negative/dos_04_external_noncritical.sol` | Synthetic — non-critical external call |
| `dos/edge/dos_05_call_ignored.sol` | Synthetic — ignored return value edge case |

### Delegatecall

| File | Pattern source |
|------|---------------|
| `delegatecall/positive/delegatecall_01.sol` | Synthetic — unguarded delegatecall, SWC-112 |
| `delegatecall/positive/proxy_unguarded.sol` | **Public** — Parity Multisig Wallet pattern; adapted from [Trail of Bits not-so-smart-contracts](https://github.com/trailofbits/not-so-smart-contracts/tree/master/unprotected_function) and [SWC-112](https://swcregistry.io/docs/SWC-112) |
| `delegatecall/negative/delegatecall_02.sol` | Synthetic — delegatecall with owner guard |

---

## Track B (Contextual)

No public benchmark exists for contextual vulnerability categories (Nuanced Access Control, Asset Locking, Logic/Validation). These contracts were written specifically for this evaluation based on vulnerability classes documented in public audit reports from Code4rena, Sherlock, and Immunefi. Each contract captures the minimal structure needed to exhibit the pattern; they are representative rather than copies of specific audited codebases.

### Nuanced Access Control

| File | Pattern source |
|------|---------------|
| `nuanced_access_control/positive/nuac_02_reinit.sol` | Missing initialization guard on upgradeable contracts — recurring finding across multiple C4 and Sherlock reports (2022–2024) |
| `nuanced_access_control/positive/nuac_03_accept_bypass.sol` | Two-step ownership transfer with wrong caller check — documented in several protocol governance audits |
| `nuanced_access_control/positive/nuanced_access_01.sol` | Synthetic — general nuanced access control positive case |
| `nuanced_access_control/positive/access_01.sol` | Synthetic — vault with missing access guard |
| `nuanced_access_control/negative/nuac_02_safe_twostep.sol` | Correct two-step ownership (OZ `Ownable2Step` semantics) |
| `nuanced_access_control/negative/nuanced_access_01_safe.sol` | Synthetic — nuanced access control negative control |
| `nuanced_access_control/negative/access_02.sol` | Synthetic — safe vault negative control |

### Asset Locking

| File | Pattern source |
|------|---------------|
| `asset_locking/positive/locking_03_burn_redeem.sol` | Burn/debit before external transfer — class of findings in DeFi vault redeem paths |
| `asset_locking/positive/locking_04_renounced_admin.sol` | Irrevocable admin renouncement before claim gate is opened — documented in reward distribution contracts |
| `asset_locking/positive/locking_access_01.sol` | Synthetic — withdrawal gate permanently disabled |
| `asset_locking/negative/locking_03_safe_redeem.sol` | Transfer-before-debit (safe ordering) |
| `asset_locking/negative/locking_access_02.sol` | Synthetic — properly managed withdrawal flag |

### Logic / Validation

| File | Pattern source |
|------|---------------|
| `logic_validation/positive/logic_05_phase_skip.sol` | Missing phase enforcement on settlement — common finding in auction and escrow contracts |
| `logic_validation/positive/logic_06_vesting_reinit.sol` | Vesting schedule overwritable after claims begin — found in token grant contracts |
| `logic_validation/positive/logic_01.sol` | Synthetic — missing zero-address check |
| `logic_validation/positive/logic_03.sol` | Synthetic — missing amount validation |
| `logic_validation/negative/logic_05_safe_auction.sol` | Correct phase enforcement on all state transitions |
| `logic_validation/negative/logic_02.sol` | Synthetic — zero-address check present |
| `logic_validation/negative/logic_04.sol` | Synthetic — amount validation present |

---

## Real Contracts (Track A and B)

Real contracts used in the evaluation are sourced from verified on-chain deployments or referenced repositories and are identified by their original source in file-level comments. See `datasets/real/` for the full set.
