// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"errors"
	"fmt"
	"strings"
)

// Chain is a single network the Ledger client knows how to address.
//
// One Ledger app, many chains. The on-device firmware ships two CLAs:
//
//   CLA = 0x80  — Lux native instructions (P/X/C/Q/Z/A/B/M/F-chain ops,
//                 Bech32 + cb58 addresses, validator/delegator flows)
//   CLA = 0xE0  — Ethereum-compatible instructions (any EVM chain;
//                 EIP-155 tx body carries the chain_id; firmware shows
//                 the integer chain_id alongside the recipient + value)
//
// Every Hanzo / Lux / Zoo / Pars chain that exposes an EVM is reachable
// today through CLA=0xE0. The Go client picks the correct BIP44
// derivation path from this registry; the device firmware does not
// have to change.
//
// The on-device "[Hanzo] Transfer" badge UX (chain-aware label above
// the EVM summary) is a v0.2.0 firmware enhancement — see
// docs/CHAIN_PATHS.md. Until that ships, the user sees the standard
// Ethereum-app review screen with chain_id + to + value + data.
type Chain struct {
	// Name is the canonical short name ("lux", "hanzo", "zoo", "pars").
	// Used as the dictionary key — lower-case, no spaces.
	Name string

	// SLIP44 is the BIP-44 / SLIP-0044 coin type for native-coin paths.
	//
	// Lux owns 9000. EVM-compatible siblings reuse 60 (Ethereum) so
	// existing wallets discover them without a SLIP-0044 application.
	// A chain that wants its own SLIP-0044 must register via
	// satoshilabs/slips#44; until then they ride 60 with chain_id
	// disambiguation in the tx body.
	SLIP44 uint32

	// EVMChainID is the EIP-155 numeric chain_id for the chain's EVM.
	// Zero if the chain has no EVM (Lux P/X chains use SLIP44=9000 and
	// the native CLA=0x80 path; this field stays 0 for those).
	EVMChainID uint64

	// HRP is the Bech32 human-readable prefix for native-format
	// addresses ("lux" → "P-lux1...", "hanzo" → "P-hanzo1...", etc.).
	// Empty if the chain only addresses via 0x.
	HRP string

	// CLA is the device APDU class byte. CLAEVM (0xE0) routes through
	// the Ethereum-compat instruction set; CLALux (0x80) routes through
	// the Lux native-chain instruction set.
	CLA uint8

	// AddressFormat documents the on-chain address shape so callers
	// (operator scripts, audit tools) don't have to grep for it.
	//
	//   "bech32"  → P-lux1tlq..., X-lux1...
	//   "evm"     → 0x...
	//   "both"    → either, depending on path coin type
	AddressFormat string
}

// SLIP-0044 / BIP-44 coin types referenced from this package.
//
//   60   — Ethereum (and every EVM-compat chain ridden through it)
//   9000 — Lux  (registered)
const (
	SLIP44Ethereum uint32 = 60
	SLIP44Lux      uint32 = 9000
)

// Reserved EIP-155 chain IDs for Lux-family EVMs.
//
// Sources: chain registries published in their own repos. These are
// documentation-only constants — the Ledger client passes them through
// to the device unmodified inside the EIP-155 tx body. Mainnets only;
// testnets/devnets follow the +1/+2 convention each chain publishes.
const (
	EVMChainIDLuxMainnet   uint64 = 96369
	EVMChainIDHanzoMainnet uint64 = 36963
	EVMChainIDZooMainnet   uint64 = 200200
	EVMChainIDParsMainnet  uint64 = 7777 // placeholder until Pars publishes registry
)

// CLA bytes routed by the Lux Ledger app firmware.
const (
	CLALux uint8 = 0x80
	CLAEVM uint8 = 0xE0
)

// chainRegistry is the single source of truth for chain metadata. One
// and only one place to add or change a chain.
//
// The map is intentionally not exported. Callers go through Lookup so
// the package can validate inputs and refuse unknown names without
// every caller re-implementing that check.
var chainRegistry = map[string]Chain{
	"lux": {
		Name:          "lux",
		SLIP44:        SLIP44Lux,
		EVMChainID:    EVMChainIDLuxMainnet,
		HRP:           "lux",
		CLA:           CLALux,
		AddressFormat: "both",
	},
	"hanzo": {
		Name:          "hanzo",
		SLIP44:        SLIP44Ethereum,
		EVMChainID:    EVMChainIDHanzoMainnet,
		HRP:           "",
		CLA:           CLAEVM,
		AddressFormat: "evm",
	},
	"zoo": {
		Name:          "zoo",
		SLIP44:        SLIP44Ethereum,
		EVMChainID:    EVMChainIDZooMainnet,
		HRP:           "",
		CLA:           CLAEVM,
		AddressFormat: "evm",
	},
	"pars": {
		Name:          "pars",
		SLIP44:        SLIP44Ethereum,
		EVMChainID:    EVMChainIDParsMainnet,
		HRP:           "",
		CLA:           CLAEVM,
		AddressFormat: "evm",
	},
}

// Chains returns the canonical list of supported chains, sorted by name.
// The slice is a fresh copy; callers may not mutate the registry.
func Chains() []Chain {
	out := make([]Chain, 0, len(chainRegistry))
	for _, c := range chainRegistry {
		out = append(out, c)
	}
	// Sort to make the output deterministic for tests + audits.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Name > out[j].Name; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Lookup returns the chain metadata for the given name. Names are
// matched case-insensitively. Unknown names produce an explicit error
// — callers MUST NOT default to "lux" silently.
func Lookup(name string) (Chain, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return Chain{}, errors.New("ledger: chain name empty")
	}
	c, ok := chainRegistry[key]
	if !ok {
		return Chain{}, fmt.Errorf("ledger: unknown chain %q (supported: %v)", name, supportedNames())
	}
	return c, nil
}

func supportedNames() []string {
	names := make([]string, 0, len(chainRegistry))
	for n := range chainRegistry {
		names = append(names, n)
	}
	for i := 1; i < len(names); i++ {
		for j := i; j > 0 && names[j-1] > names[j]; j-- {
			names[j-1], names[j] = names[j], names[j-1]
		}
	}
	return names
}
