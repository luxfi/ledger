// Copyright (C) 2019-2025, Lux Industries, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package ledger

import (
	"fmt"

	"github.com/luxfi/ids"
)

// LedgerAdapter wraps LedgerLux to implement the keychain.Ledger interface
// from github.com/luxfi/keychain
type LedgerAdapter struct {
	ledger *LedgerLux
}

const (
	rootPath       = "m/44'/9000'/0'" // Standard Lux derivation path
	defaultHRP     = "lux"
	defaultChainID = "2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5"
)

// NewLedgerAdapter creates a new LedgerAdapter that wraps LedgerLux
// and implements the keychain.Ledger interface.
func NewLedgerAdapter() (*LedgerAdapter, error) {
	ledger, err := FindLedgerLuxApp()
	if err != nil {
		return nil, err
	}
	return &LedgerAdapter{ledger: ledger}, nil
}

// Address returns the address at the given index
func (l *LedgerAdapter) Address(displayHRP string, addressIndex uint32) (ids.ShortID, error) {
	path := fmt.Sprintf("%s/%d'", rootPath, addressIndex)

	hrp := displayHRP
	if hrp == "" {
		hrp = defaultHRP
	}

	resp, err := l.ledger.GetPubKey(path, false, hrp, defaultChainID)
	if err != nil {
		return ids.ShortID{}, err
	}

	var shortID ids.ShortID
	copy(shortID[:], resp.Hash)
	return shortID, nil
}

// GetAddresses returns the addresses for multiple indices
func (l *LedgerAdapter) GetAddresses(addressIndices []uint32) ([]ids.ShortID, error) {
	addresses := make([]ids.ShortID, len(addressIndices))
	for i, idx := range addressIndices {
		addr, err := l.Address(defaultHRP, idx)
		if err != nil {
			return nil, err
		}
		addresses[i] = addr
	}
	return addresses, nil
}

// SignHash signs a hash at the given address index
func (l *LedgerAdapter) SignHash(hash []byte, addressIndex uint32) ([]byte, error) {
	path := fmt.Sprintf("%d'", addressIndex)
	resp, err := l.ledger.SignHash(rootPath, []string{path}, hash)
	if err != nil {
		return nil, err
	}
	sig, ok := resp.Signature[path]
	if !ok {
		return nil, fmt.Errorf("no signature returned for path %s", path)
	}
	return sig, nil
}

// Sign signs a message at the given address index
func (l *LedgerAdapter) Sign(message []byte, addressIndex uint32) ([]byte, error) {
	path := fmt.Sprintf("%d'", addressIndex)
	resp, err := l.ledger.Sign(rootPath, []string{path}, message, nil)
	if err != nil {
		return nil, err
	}
	sig, ok := resp.Signature[path]
	if !ok {
		return nil, fmt.Errorf("no signature returned for path %s", path)
	}
	return sig, nil
}

// SignTransaction signs a transaction hash with multiple addresses
func (l *LedgerAdapter) SignTransaction(rawUnsignedHash []byte, addressIndices []uint32) ([][]byte, error) {
	signingPaths := make([]string, len(addressIndices))
	for i, idx := range addressIndices {
		signingPaths[i] = fmt.Sprintf("%d'", idx)
	}

	resp, err := l.ledger.SignHash(rootPath, signingPaths, rawUnsignedHash)
	if err != nil {
		return nil, err
	}

	// Convert map to ordered slice matching input indices
	sigs := make([][]byte, len(addressIndices))
	for i, path := range signingPaths {
		sig, ok := resp.Signature[path]
		if !ok {
			return nil, fmt.Errorf("no signature returned for path %s", path)
		}
		sigs[i] = sig
	}
	return sigs, nil
}

// Disconnect closes the ledger connection
func (l *LedgerAdapter) Disconnect() error {
	return l.ledger.Close()
}
