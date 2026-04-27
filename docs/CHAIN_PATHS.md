# Multi-chain support — BIP-44 / SLIP-0044 path map

The Lux Ledger app is one binary that signs for every chain in the
Lux / Hanzo / Zoo / Pars family. Chain selection happens in two
places:

1. The Go client (`github.com/luxfi/ledger`) picks the BIP-44
   derivation path — see `chains.go` and `chain_paths.go`.
2. The on-device firmware routes by APDU CLA: `0x80` for Lux native
   instructions, `0xE0` for EIP-155 EVM transactions.

That split is deliberate. Every Hanzo / Zoo / Pars chain runs an EVM
that signs identically to Ethereum at the device level — the network
is identified by `chain_id` inside the EIP-155 payload, not by a
device-side mode change. A single Ledger Nano serves the whole family.

## SLIP-0044 coin types

| Chain | SLIP-0044 | EIP-155 chain_id | HRP   | CLA  |
|-------|-----------|------------------|-------|------|
| Lux   | 9000      | 96369            | lux   | 0x80 |
| Hanzo | 60        | 36963            | —     | 0xE0 |
| Zoo   | 60        | 200200           | —     | 0xE0 |
| Pars  | 60        | 7777             | —     | 0xE0 |

`9000` is registered to Lux in
[satoshilabs/slips#44](https://github.com/satoshilabs/slips/blob/master/slip-0044.md).
The EVM-compat chains share `60` (Ethereum) so existing Ledger Live
flows discover them without a SLIP-0044 application — the same key
roams across every EVM in the family. EIP-155 prevents replay across
networks via `chain_id`.

## Derivation paths

```
Lux native (P/X chains, validator/delegator ops):
    m/44'/9000'/<account>'/<change>/<index>

EVM-compat (Hanzo, Zoo, Pars, Lux C-Chain):
    m/44'/60'/<account>'/<change>/<index>
```

The EVM-compat path is intentionally identical across siblings. A user
who derives `m/44'/60'/0'/0/0` once gets the same `0x…` address on
Hanzo, Zoo, Pars, and Lux C-Chain. The signed `chain_id` decides which
network accepts the transaction.

## Liquid family chains

Liquid EVM / Liquid DEX networks are addressed identically — they are
EIP-155 EVM chains, signed via CLA `0xE0` with their published
`chain_id`. They have no special code in this repository; routing is
the responsibility of the consuming application's chain registry.

## Per-chain UI badge (firmware v0.2.0)

The current firmware shows the standard Ethereum-app review screen for
every CLA `0xE0` transaction. The screen surfaces the integer
`chain_id` plus `to`, `value`, and `data` — enough to verify the
transaction unambiguously, but not labelled with a friendly chain name.

The follow-on firmware change (v0.2.0) inserts a "[Chain] Operation"
badge based on a chain-id table compiled into the binary. The change
is purely UX — the wire protocol stays the same and existing wallets
remain compatible.

This is documented in `APDUSPEC.md` under
`INS_ETH_GET_APP_CONFIGURATION` extensions.

## Sibling integrations

- **luxfi/hsm** — `signer_ledger.go` (online signer) takes a
  `LedgerConfig.DerivationPath`. Multi-chain callers compute it via
  `ledger.BIP44PathForName(chainName, account, change, index)`.
- **lux/mpc/pkg/approval** — `provider_ledger_device.go` resolves the
  same path and signs the canonical-intent digest via the host-side
  `ledgerctl` tool (no in-process USB/HID dependency).
