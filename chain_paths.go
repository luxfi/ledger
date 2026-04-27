// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"errors"
	"fmt"
)

// BIP44Path returns the BIP-44 derivation path for the given chain at
// the given account / change / index. Hardened components are appended
// where BIP-44 requires them.
//
// The path shape is:
//
//   m/44'/<slip44>'/<account>'/<change>/<index>
//
// where slip44 is the chain's SLIP44 field (60 for EVM-compat, 9000 for
// Lux native). EVM-compat chains share coin type 60 — the EIP-155
// chain_id in the tx body distinguishes which network the signature
// applies to. This is the same convention MetaMask, Ledger Live, and
// every multi-EVM wallet uses.
//
// The function never returns an internal-format error: any non-nil
// error is a caller bug (unknown chain). Callers typically construct
// once at startup and reuse the string.
func BIP44Path(chain Chain, account, change, index uint32) string {
	if chain.SLIP44 == 0 {
		// Defensive: a Chain with SLIP44=0 came from somewhere not in
		// the registry. We refuse to derive — better an empty string
		// the caller will reject than a wrong key path.
		return ""
	}
	return fmt.Sprintf("m/44'/%d'/%d'/%d/%d", chain.SLIP44, account, change, index)
}

// BIP44PathForName is the convenience wrapper most callers want: pass a
// chain name + indices, get a path back. Unknown chain → explicit
// error. Used by mpcd / mpc CLI / KMS bridge for path selection.
func BIP44PathForName(name string, account, change, index uint32) (string, error) {
	c, err := Lookup(name)
	if err != nil {
		return "", err
	}
	p := BIP44Path(c, account, change, index)
	if p == "" {
		return "", errors.New("ledger: derived empty BIP44 path (registry corruption)")
	}
	return p, nil
}

// LuxNativePath returns the native Lux P/X-Chain prefix path
//
//   m/44'/9000'/<account>'
//
// suitable as the rootPath argument to LedgerLux.SignFull /
// LedgerLux.SignHashFull. The signing API expects a 3-element prefix
// with hardened account; the suffix paths (change / index) are passed
// separately as signers/changePaths.
//
// This helper is the one and only way to derive that prefix — call
// sites must NOT format the string themselves.
func LuxNativePath(account uint32) string {
	return fmt.Sprintf("m/44'/%d'/%d'", SLIP44Lux, account)
}

// EVMPath returns the standard 5-element BIP-44 path for an EVM-compat
// chain. Chain ID is captured separately (in the EIP-155 tx body); the
// derivation path itself is identical across EVM-compat siblings, so
// the same Ledger key signs for Hanzo / Zoo / Pars / Lux C-Chain.
//
//   m/44'/60'/<account>'/<change>/<index>
//
// This is intentional: a single hardware key roams across every EVM
// chain in the family. Replay protection comes from chain_id in the
// signed payload, not from a different derivation path per chain.
func EVMPath(account, change, index uint32) string {
	return fmt.Sprintf("m/44'/%d'/%d'/%d/%d", SLIP44Ethereum, account, change, index)
}
