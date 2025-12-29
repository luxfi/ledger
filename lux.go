/*******************************************************************************
*   (c) 2018 - 2023 Zondax AG
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
// ********************************************************************************/

package ledger

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/luxfi/ids"
)

// FindLedgerLuxApp FindLedgerLuxUserApp finds a Lux user app running in a ledger device
func FindLedgerLuxApp() (_ *LedgerLux, rerr error) {
	ledgerAdmin := NewLedgerAdmin()
	ledgerAPI, err := ledgerAdmin.Connect(0)
	if err != nil {
		return nil, err
	}

	defer func() {
		if rerr != nil {
			ledgerAPI.Close()
		}
	}()

	app := &LedgerLux{ledgerAPI, VersionInfo{}}
	appVersion, err := app.GetVersion()
	if err != nil {
		if err.Error() == "[APDU_CODE_CLA_NOT_SUPPORTED] CLA not supported" {
			err = errors.New("are you sure the Lux app is open?")
		}
		return nil, err
	}

	if err := app.CheckVersion(*appVersion); err != nil {
		return nil, err
	}

	return app, err
}

// NewLedger creates a new LedgerLux that implements the keychain.Ledger interface.
// This is the recommended way to get a Ledger for use with the keychain package.
func NewLedger() (*LedgerLux, error) {
	return FindLedgerLuxApp()
}

// Close closes a connection with the Lux user app
func (ledger *LedgerLux) Close() error {
	return ledger.api.Close()
}

// CheckVersion returns true if the App version is supported by this library
func (ledger *LedgerLux) CheckVersion(ver VersionInfo) error {
	version, err := ledger.GetVersion()
	if err != nil {
		return err
	}

	return CheckVersion(*version, ver)
}

// GetVersion returns the current version of the Lux user app
func (ledger *LedgerLux) GetVersion() (*VersionInfo, error) {
	message := []byte{CLA, INS_GET_VERSION, 0, 0, 0}
	response, err := ledger.api.Exchange(message)

	if err != nil {
		return nil, err
	}

	if len(response) < 4 {
		return nil, errors.New("invalid response")
	}

	ledger.version = VersionInfo{
		AppMode: response[0],
		Major:   response[1],
		Minor:   response[2],
		Patch:   response[3],
	}

	return &ledger.version, nil
}

// GetPubKey returns the pubkey and hash
func (ledger *LedgerLux) GetPubKey(path string, show bool, hrp string, chainid string) (*ResponseAddr, error) {
	if len(hrp) > 83 {
		return nil, errors.New("hrp len should be < 83 chars")
	}

	serializedHRP, err := SerializeHrp(hrp)
	if err != nil {
		return nil, err
	}

	serializedPath, err := SerializePath(path)
	if err != nil {
		return nil, err
	}

	serializedChainID, err := SerializeChainID(chainid)
	if err != nil {
		return nil, err
	}

	p1 := byte(P1_ONLY_RETRIEVE)
	if show {
		p1 = byte(P1_SHOW_ADDRESS_IN_DEVICE)
	}

	// Prepare message
	header := []byte{CLA, INS_GET_ADDR, p1, 0, 0}
	message := append(header, serializedHRP...)
	message = append(message, serializedChainID...)
	message = append(message, serializedPath...)
	message[4] = byte(len(message) - len(header)) // update length

	response, err := ledger.api.Exchange(message)
	if err != nil {
		return nil, err
	}

	if len(response) < 35+len(hrp) {
		return nil, errors.New("Invalid response")
	}

	// [publicKeyLen | publicKey | hash | address | errorCode]
	publicKeyLen := response[0]
	publicKey := response[1 : publicKeyLen+1]
	hash := response[publicKeyLen+1 : publicKeyLen+1+20]
	address := string(response[publicKeyLen+1+20:])

	return &ResponseAddr{PublicKey: publicKey, Hash: hash, Address: address}, nil
}

func (ledger *LedgerLux) SignFull(pathPrefix string, signingPaths []string, message []byte, changePaths []string) (*ResponseSign, error) {
	paths := signingPaths
	if changePaths != nil {
		paths = append(paths, changePaths...)
		paths = RemoveDuplicates(paths)
	}

	serializedPath, err := SerializePath(pathPrefix)
	if err != nil {
		return nil, err
	}

	payloadType := PAYLOAD_INIT
	p2 := FIRST_MESSAGE
	header := []byte{CLA, INS_SIGN, byte(payloadType), byte(p2), byte(len(serializedPath))}
	bytesToSend := append(header, serializedPath...)
	_, err = ledger.api.Exchange(bytesToSend)
	if err != nil {
		return nil, errors.New("command rejected")
	}

	msg := ConcatMessageAndChangePath(message, paths)

	for i := 0; i < len(msg); i += CHUNK_SIZE {
		end := i + CHUNK_SIZE
		payloadType := PAYLOAD_ADD
		p2 := 0

		if end > len(msg) {
			end = len(msg)
			payloadType = PAYLOAD_LAST
		}
		chunk := msg[i:end]
		chunkSize := end - i

		header := []byte{CLA, INS_SIGN, byte(payloadType), byte(p2), byte(chunkSize)}
		bytesToSend := append(header, chunk...)
		response, err := ledger.api.Exchange(bytesToSend)
		if err != nil {
			if err.Error() == "[APDU_CODE_BAD_KEY_HANDLE] The parameters in the data field are incorrect" {
				// In this special case, we can extract additional info
				errorMsg := string(response)
				return nil, errors.New(errorMsg)
			}
			if err.Error() == "[APDU_CODE_DATA_INVALID] Referenced data reversibly blocked (invalidated)" {
				errorMsg := string(response)
				return nil, errors.New(errorMsg)
			}
			return nil, err
		}
	}

	// Transaction was approved so start iterating over signing_paths to sign
	// and collect each signature
	return SignAndCollect(signingPaths, ledger)
}

func (ledger *LedgerLux) SignHashFull(pathPrefix string, signingPaths []string, hash []byte) (*ResponseSign, error) {
	if len(hash) != HASH_LEN {
		return nil, errors.New("wrong hash size")
	}

	serializedPath, err := SerializePath(pathPrefix)
	if err != nil {
		return nil, err
	}

	header := []byte{CLA, INS_SIGN_HASH, FIRST_MESSAGE, byte(0x00), byte(len(serializedPath) + len(hash))}
	bytesToSend := append(header, serializedPath...)
	bytesToSend = append(bytesToSend, hash...)
	firstResponse, err := ledger.api.Exchange(bytesToSend)

	if err != nil {
		return nil, errors.New("command rejected")
	}
	if len(firstResponse) != 0 {
		return nil, errors.New("wrong response")
	}

	return SignAndCollect(signingPaths, ledger)
}

func SignAndCollect(signingPaths []string, ledger *LedgerLux) (*ResponseSign, error) {
	// Where each pair path_suffix, signature are stored
	signatures := make(map[string][]byte)

	for idx, suffix := range signingPaths {
		pathBuf, err := SerializePathSuffix(suffix)
		if err != nil {
			return nil, err
		}

		p1 := LAST_MESSAGE
		if idx < len(signingPaths)-1 {
			p1 = NEXT_MESSAGE
		}

		// Send path to sign hash that should be in device's ram memory
		header := []byte{CLA, INS_SIGN_HASH, byte(p1), byte(0x00), byte(len(pathBuf))}
		bytesToSend := append(header, pathBuf...)
		response, err := ledger.api.Exchange(bytesToSend)

		if err != nil {
			return nil, err
		}
		signatures[suffix] = response
	}

	return &ResponseSign{nil, signatures}, nil
}

func (ledger *LedgerLux) VerifyMultipleSignatures(response ResponseSign, messageHash []byte, rootPath string, signingPaths []string, hrp string, chainID string) error {
	if len(response.Signature) != len(signingPaths) {
		return errors.New("sizes of signatures and paths don't match")
	}

	for _, suffix := range signingPaths {
		path := fmt.Sprintf("%s/%s", rootPath, suffix)

		addr, err := ledger.GetPubKey(path, false, hrp, chainID)
		if err != nil {
			return errors.New("error getting the pubkey")
		}

		hexString := fmt.Sprintf("%x", addr.PublicKey)
		fmt.Println(hexString)

		sigLen := len(response.Signature[suffix])
		verified := VerifySignature(addr.PublicKey, messageHash, response.Signature[suffix][:sigLen-1])

		if !verified {
			return errors.New("[VerifySig] Error verifying signature: ")
		}
	}
	return nil
}

// VerifySignature checks that the given public key created signature over hash.
// The public key should be in compressed (33 bytes) or uncompressed (65 bytes) format.
// The signature should have the 64 byte [R || S] format.
func VerifySignature(pubkey, hash, signature []byte) bool {
	if len(signature) != 64 {
		return false
	}
	var r, s btcec.ModNScalar
	if r.SetByteSlice(signature[:32]) {
		return false // overflow
	}
	if s.SetByteSlice(signature[32:]) {
		return false
	}
	sig := ecdsa.NewSignature(&r, &s)
	key, err := btcec.ParsePubKey(pubkey)
	if err != nil {
		return false
	}
	// Reject malleable signatures. libsecp256k1 does this check but btcec doesn't.
	if s.IsOverHalfOrder() {
		return false
	}
	return sig.Verify(hash, key)
}

// ============================================================================
// keychain.Ledger interface implementation
// These methods provide a simple interface for the keychain package.
// ============================================================================

const (
	rootPath       = "m/44'/60'/0'" // Ethereum derivation path (used by Lux)
	defaultHRP     = "lux"
	defaultChainID = "2q9e4r6Mu3U68nU1fYjgbR6JvwrRx36CohpAX5UQxse55x1Q5"
)

// Address returns the address at the given index (implements keychain.Ledger)
func (l *LedgerLux) Address(displayHRP string, addressIndex uint32) (ids.ShortID, error) {
	path := fmt.Sprintf("%s/%d'", rootPath, addressIndex)
	hrp := displayHRP
	if hrp == "" {
		hrp = defaultHRP
	}
	resp, err := l.GetPubKey(path, false, hrp, defaultChainID)
	if err != nil {
		return ids.ShortID{}, err
	}
	var shortID ids.ShortID
	copy(shortID[:], resp.Hash)
	return shortID, nil
}

// GetAddresses returns the addresses for multiple indices (implements keychain.Ledger)
func (l *LedgerLux) GetAddresses(addressIndices []uint32) ([]ids.ShortID, error) {
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

// SignHash signs a hash at the given address index (implements keychain.Ledger)
func (l *LedgerLux) SignHash(hash []byte, addressIndex uint32) ([]byte, error) {
	path := fmt.Sprintf("%d'", addressIndex)
	resp, err := l.SignHashFull(rootPath, []string{path}, hash)
	if err != nil {
		return nil, err
	}
	if sig, ok := resp.Signature[path]; ok {
		return sig, nil
	}
	return nil, fmt.Errorf("no signature returned for path %s", path)
}

// Sign signs a message at the given address index (implements keychain.Ledger)
func (l *LedgerLux) Sign(message []byte, addressIndex uint32) ([]byte, error) {
	path := fmt.Sprintf("%d'", addressIndex)
	resp, err := l.SignFull(rootPath, []string{path}, message, nil)
	if err != nil {
		return nil, err
	}
	if sig, ok := resp.Signature[path]; ok {
		return sig, nil
	}
	return nil, fmt.Errorf("no signature returned for path %s", path)
}

// SignTransaction signs a transaction hash with multiple addresses (implements keychain.Ledger)
func (l *LedgerLux) SignTransaction(rawUnsignedHash []byte, addressIndices []uint32) ([][]byte, error) {
	signingPaths := make([]string, len(addressIndices))
	for i, idx := range addressIndices {
		signingPaths[i] = fmt.Sprintf("%d'", idx)
	}
	resp, err := l.SignHashFull(rootPath, signingPaths, rawUnsignedHash)
	if err != nil {
		return nil, err
	}
	sigs := make([][]byte, len(addressIndices))
	for i, path := range signingPaths {
		if sig, ok := resp.Signature[path]; ok {
			sigs[i] = sig
		} else {
			return nil, fmt.Errorf("no signature for path %s", path)
		}
	}
	return sigs, nil
}

// Disconnect closes the ledger connection (implements keychain.Ledger)
func (l *LedgerLux) Disconnect() error {
	return l.Close()
}
