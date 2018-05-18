// Copyright (c) 2013-2016 The btcsuite developers
// Copyright (c) 2015-2016 The Decred developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package shachain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const (
	// HashSize of array used to store hashes.  See ShaHash.
	HashSize = sha256.Size

	// MaxHashStringSize is the maximum length of a ShaHash hash string.
	MaxHashStringSize = HashSize * 2
)

// ErrHashStrSize describes an error that indicates the caller specified a hash
// string that has too many characters.
var ErrHashStrSize = fmt.Errorf("max hash string length is %v bytes",
	MaxHashStringSize)

// ShaHash represents a sha256 hash that is used when working with shachains.
type ShaHash [HashSize]byte

// String returns the ShaHash as a hexadecimal string.
func (hash ShaHash) String() string {
	return hex.EncodeToString(hash[:])
}

// NewHash returns a new ShaHash from a byte slice.  An error is returned if
// the number of bytes passed in is not HashSize.
func NewHash(newHash []byte) (*ShaHash, error) {
	nhlen := len(newHash)
	if nhlen != HashSize {
		return nil, fmt.Errorf("invalid hash length of %v, want %v", nhlen,
			HashSize)
	}

	var hash ShaHash
	copy(hash[:], newHash)
	return &hash, nil
}

// NewHashFromStr creates a ShaHash from a hexadeimal hash string.  Unlike most
// hashes used in cryptocurrencies, this function does not perform any byte
// reversals.
func NewHashFromStr(hash string) (*ShaHash, error) {
	// Return an error if hash string is too long.
	if len(hash) > MaxHashStringSize {
		return nil, ErrHashStrSize
	}

	// Hex decoder expects the hash to be a multiple of two.
	if len(hash)%2 != 0 {
		hash = "0" + hash
	}

	// Convert string hash to bytes.
	buf, err := hex.DecodeString(hash)
	if err != nil {
		return nil, err
	}

	return NewHash(buf)
}
