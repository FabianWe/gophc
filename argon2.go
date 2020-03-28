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
	"regexp"
	"strconv"
	"strings"
)

const defaultVersion uint64 = 0x10 // 1.0 (16)

var Argon2Versions = []uint64{
	0x10, // 1.0 (16)
	0x13, // 1.3 (19)
}

var Argon2Variants = []string{
	"argon2id",
	"argon2i",
	"argon2d",
}

var argon2PHCRegexString string
var argon2PHCRx *regexp.Regexp

func init() {
	// argon2PHCRegexString is the regex used to decode an argon2 phc string
	argon2PHCRegexString = `^\$(` + strings.Join(Argon2Variants, "|") + `)\$` + // variant
		// version, this parameter is not required
		`(?:v=` + getPHCPositiveDecimalRegexString(10) + `,)?` +
		`m=` + getPHCPositiveDecimalRegexString(10) + `,t=` + getPHCPositiveDecimalRegexString(10) +
		`,p=` + getPHCPositiveDecimalRegexString(3) + // required parameters
		`(?:\$(` + getPHCBase64Regex(11, 64) + `))?` + // salt
		`(?:\$(` + getPHCBase64Regex(16, 86) + `))?$` // hash
	// argon2PHCRx 	is the compiled form of argon2PHCRegexString.
	argon2PHCRx = regexp.MustCompile(argon2PHCRegexString)
}

// Argon2PHC contains all information to encode the data to a phc string.
//
// Variant must be either argon2id, argon2i or argon2d. I'm not quite sure why the specification says
// argon2ds and not argon2id, but because argon2id is used nearly everywhere that should be fine.
// All other arguments (Memory, Iterations, Parallelism, KeyId, Data) are the configuration parameters
// for argon2, see argon2 phc specification
// https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md#argon2-encoding.
// KeyId and Data re optional parameters.
// Salt and Has are the base64 encoded strings of the salt and hash, not the raw bytes!
// Note that according to the specification they're both optional.
type Argon2PHC struct {
	Variant     string
	Version     uint64
	Memory      int
	Iterations  int
	Parallelism int
	Salt        string
	Hash        string
}

// Equals tests if two phc instances describe the exact same configuration.
func (phc *Argon2PHC) Equals(other *Argon2PHC) bool {
	return phc.Variant == other.Variant &&
		phc.Version == other.Version &&
		phc.Memory == other.Memory &&
		phc.Iterations == other.Iterations &&
		phc.Parallelism == other.Parallelism &&
		phc.Salt == other.Salt &&
		phc.Hash == other.Hash
}

func (phc *Argon2PHC) WithSaltAndHash(salt, hash []byte) *Argon2PHC {
	encodedSalt, encodedHash := EncodeSaltAndHash(salt, hash)
	return &Argon2PHC{
		Variant:     phc.Variant,
		Version:     phc.Version,
		Memory:      phc.Memory,
		Iterations:  phc.Iterations,
		Parallelism: phc.Parallelism,
		Salt:        encodedSalt,
		Hash:        encodedHash,
	}
}

// ValidateParameters verifies that the parameters used are valid for argon2.
func (phc *Argon2PHC) ValidateParameters() error {
	// look for valid variant
	variantIndex := -1
	for i, candidate := range Argon2Variants {
		if phc.Variant == candidate {
			variantIndex = i
			break
		}
	}
	if variantIndex < 0 {
		return fmt.Errorf("argon2 validation error: variant must be in [%s]",
			strings.Join(Argon2Variants, ", "))
	}

	// look for version
	versionIndex := -1
	for i, candidate := range Argon2Versions {
		if phc.Version == candidate {
			versionIndex = i
			break
		}
	}
	if versionIndex < 0 {
		versionStrings := make([]string, len(Argon2Versions))
		for i, versionCandidate := range Argon2Versions {
			formatted := fmt.Sprintf("%d (0x%s)", versionCandidate, strconv.FormatUint(versionCandidate, 16))
			versionStrings[i] = formatted
		}
		return fmt.Errorf("argon2 validation error: invalid version %d, must be one of [%s]",
			phc.Version, strings.Join(versionStrings, ", "))
	}

	if phc.Memory < 1 || uint64(phc.Memory) > argon2MaxSize {
		return fmt.Errorf("argon2 validation error: memory must be in range 1 <= memory <= %d",
			argon2MaxSize)
	}
	if phc.Iterations < 1 || uint64(phc.Iterations) > argon2MaxSize {
		return fmt.Errorf("argon2 validation error: iterations must be in range 1 <= iterations <= %d",
			argon2MaxSize)
	}
	if phc.Parallelism < 1 || uint64(phc.Parallelism) > 255 {
		return fmt.Errorf("argon2 validation error: parallelism must be in range 1 <= 255 <= 255")
	}
	// The memory cost parameter, expressed in kilobytes, must be at least 8 times the value of p
	if phc.Memory < 8*phc.Parallelism {
		return fmt.Errorf("argon2 validation error: memory must be at least 8 * parallelism, got m=%d, p=%d",
			phc.Memory, phc.Parallelism)
	}
	if base64Err := validateBase64Len(phc.Salt); base64Err != nil {
		return base64Err
	}
	if base64Err := validateBase64Len(phc.Hash); base64Err != nil {
		return base64Err
	}
	return nil
}

// Encode generates the string encoding in the form
// $<VARIANT>$m=<MEMOR>,t=<ITERATIONS>,p=<Parallelism>$<Salt>$<Hash>.
//
// The result is written to writer w.
// It returns the number of bytes written and any error that occurred.
//
// Note that this method does not validate the values of the parameters (if they're valid for argon2).
// Use ValidateParameters for that.
//
// It also assumes that the hash and salt string are the representation of the bytes in base64 (no
// encoding / decoding hashes takes place here, see base64 functionality for that).
func (phc *Argon2PHC) Encode(w io.Writer) (int, error) {
	res := 0
	write, writeErr := fmt.Fprintf(w, "$%s$v=%d,m=%d,t=%d,p=%d",
		phc.Variant, phc.Version, phc.Memory, phc.Iterations, phc.Parallelism)
	res += write
	if writeErr != nil {
		return res, writeErr
	}
	write, writeErr = writeSaltAndHash(w, phc.Salt, phc.Hash)
	res += write
	return res, writeErr
}

// EncodeString generates the encoding in the form
// $<VARIANT>$m=<MEMOR>,t=<ITERATIONS>,p=<Parallelism>$<Salt>$<Hash>.
//
// See Encode for more details.
func (phc *Argon2PHC) EncodeString() (string, error) {
	var builder strings.Builder
	_, err := phc.Encode(&builder)
	if err != nil {
		return "", err
	}
	return builder.String(), nil
}

// DecodeArgon2PHC reads a scrypt phc string and returns it as a ScryptPHC.
//
// This method will not validate the parameters, use ValidateParameters for that.
// The Salt and Hash parts of the result are the strings taken from the input and not decoded with base64,
// see base64 functions for that.
//
// Also note that both Hash and Salt are optional according to the phc definition.
func DecodeArgon2PHC(input string) (*Argon2PHC, error) {
	match := argon2PHCRx.FindStringSubmatch(input)
	if len(match) == 0 {
		return nil, errors.New("input does not match argon2 format")
	}
	variant := match[1]
	versionStr := match[2]
	var version uint64
	if versionStr == "" {
		// old argon2 without version, use default version
		version = defaultVersion
	} else {
		var versionErr error
		version, versionErr = strconv.ParseUint(versionStr, 10, 64)
		if versionErr != nil {
			return nil, versionErr
		}
	}
	memory, memoryErr := strconv.Atoi(match[3])
	if memoryErr != nil {
		return nil, memoryErr
	}
	iterations, iterationsErr := strconv.Atoi(match[4])
	if iterationsErr != nil {
		return nil, iterationsErr
	}
	parallelism, parallelismErr := strconv.Atoi(match[5])
	if parallelismErr != nil {
		return nil, parallelismErr
	}
	salt, hash := match[6], match[7]
	res := Argon2PHC{
		Variant:     variant,
		Version:     version,
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		Salt:        salt,
		Hash:        hash,
	}
	return &res, nil
}
