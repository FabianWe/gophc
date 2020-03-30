// Copyright 2020 Fabian Wenzelmann <fabianwen@posteo.eu>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gophc

import (
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// scryptPHCRegexString is the regex used to decode an scrypt phc string.
const scryptPHCRegexString = `^\$scrypt\$ln=` + phcPositiveDecimalRegexString +
	`,r=` + phcPositiveDecimalRegexString + `,p=` + phcPositiveDecimalRegexString + // prefix + options
	`(?:\$(` + base64String + `))?` + // salt
	`(?:\$(` + base64String + `))?$` // hash

// scryptPHCRx is the compiled form of scryptPHCRegexString.
var scryptPHCRx = regexp.MustCompile(scryptPHCRegexString)

// ScryptPHC contains all information to encode the data to a phc string.
//
// Cost is the log2 of the N parameter of scrypt.
// BlockSize and Parallelism are the r and p parameters.
// Salt and Has are the base64 encoded strings of the salt and hash, not the raw bytes!
// Note that according to the specification they're both optional.
type ScryptPHC struct {
	Cost        int
	BlockSize   int
	Parallelism int
	Salt        string
	Hash        string
}

// Equals tests if two phc instances describe the exact same configuration.
func (phc *ScryptPHC) Equals(other *ScryptPHC) bool {
	return phc.Cost == other.Cost &&
		phc.BlockSize == other.BlockSize &&
		phc.Parallelism == other.Parallelism &&
		phc.Salt == other.Salt &&
		phc.Hash == other.Hash
}

// WithSaltAndHash returns a copy of a phc with salt and hash set.
//
// This method takes the raw salt and hash bytes (not the base64 encoded string).
// Salt and hash will be encoded to base64 with EncodeSaltAndHash.
//
// This way you can easily encode multiple instances with the same configuration.
func (phc *ScryptPHC) WithSaltAndHash(salt, hash []byte) *ScryptPHC {
	encodedSalt, encodedHash := EncodeSaltAndHash(salt, hash)
	return &ScryptPHC{
		Cost:        phc.Cost,
		BlockSize:   phc.BlockSize,
		Parallelism: phc.Parallelism,
		Salt:        encodedSalt,
		Hash:        encodedHash,
	}
}

// ValidateParameters verifies that the parameters used are valid for scrypt.
//
// This function will however not test the salt and hash directly, i.e. it will not try to decode the salt
// and hash.
// Some validation only happens when this happens.
// Use DecodeSaltAndHash or DecodeSaltAndHashNotStrict for this.
// Only some basic validation takes place, i.e. that BlockSize and Parallelism are in the valid range
// for scrypt.
func (phc *ScryptPHC) ValidateParameters() error {
	if phc.BlockSize < 1 || phc.BlockSize > math.MaxUint32 {
		return fmt.Errorf("scrypt validation error: blocksize must be in range 1 <= blocksize <= %d, got %d",
			math.MaxUint32, phc.BlockSize)
	}
	if uint64(phc.BlockSize)*uint64(phc.Parallelism) >= 1<<30 || phc.BlockSize > maxInt/128/phc.Parallelism || phc.BlockSize > maxInt/256 {
		return errors.New("scrypt validation error: parameters too large")
	}
	return nil
}

// Encode generates the string encoding in the form $scrypt$ln=<COST>,r=<BLOCKSIZE>p=<Parallelism>$<SALT>$<HASH>.
//
// The result is written to the writer w.
// It returns the number of bytes written and any error that occurred.
//
// Note that this method does not validate the values of the parameters (if they're valid for scrypt).
// Use ValidateParameters for that.
//
// It also assumes that the hash and salt string are the representation of the bytes in base64 (no
// encoding / decoding hashes takes place here, see base64 functionality for that).
func (phc *ScryptPHC) Encode(w io.Writer) (int, error) {
	res := 0
	write, writeErr := fmt.Fprintf(w, "$scrypt$ln=%d,r=%d,p=%d", phc.Cost, phc.BlockSize, phc.Parallelism)
	res += write
	if writeErr != nil {
		return res, writeErr
	}
	// write hash and salt
	write, writeErr = writeSaltAndHash(w, phc.Salt, phc.Hash)
	res += write
	return res, writeErr
}

// EncodeString generates the encoding in the form $scrypt$ln=<COST>,r=<BLOCKSIZE>p=<Parallelism>$<SALT>$<HASH>.
//
// See Encode for more details.
func (phc *ScryptPHC) EncodeString() (string, error) {
	var builder strings.Builder
	_, err := phc.Encode(&builder)
	if err != nil {
		return "", err
	}
	return builder.String(), nil
}

// DecodeScryptPHC reads a scrypt phc string and returns it as a ScryptPHC.
//
// This method will not validate the parameters, use ValidateParameters for that.
// The Salt and Hash parts of the result are the strings taken from the input and not decoded with base64,
// see base64 functions for that.
//
// Also note that both Hash and Salt are optional according to the phc definition.
func DecodeScryptPHC(input string) (*ScryptPHC, error) {
	match := scryptPHCRx.FindStringSubmatch(input)
	if len(match) == 0 {
		return nil, errors.New("input does not match scrypt format")
	}
	cost, costErr := strconv.Atoi(match[1])
	if costErr != nil {
		return nil, costErr
	}
	blockSize, blockSizeErr := strconv.Atoi(match[2])
	if blockSizeErr != nil {
		return nil, blockSizeErr
	}
	parallelism, parallelismErr := strconv.Atoi(match[3])
	if parallelismErr != nil {
		return nil, parallelismErr
	}
	salt, hash := match[4], match[5]
	res := ScryptPHC{
		Cost:        cost,
		BlockSize:   blockSize,
		Parallelism: parallelism,
		Salt:        salt,
		Hash:        hash,
	}
	return &res, nil
}
