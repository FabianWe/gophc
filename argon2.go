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

var argon2PHCRegexString string
var argon2PHCRx *regexp.Regexp

func init() {
	// argon2PHCRegexString is the regex used to decode an argon2 phc string
	argon2PHCRegexString = `^\$(argon2id|argon2i|argon2d)` + // variant
		`\$m=` + getPHCPositiveDecimalRegexString(10) + `,t=` + getPHCPositiveDecimalRegexString(10) +
		`,p=` + getPHCPositiveDecimalRegexString(3) + // required parameters
		`(?:,keyid=(` + getPHCBase64Regex(0, 11) + `))?` + // optional keyid
		`(?:,data=(` + getPHCBase64Regex(0, 43) + `))?` +
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
	Memory      int
	Iterations  int
	Parallelism int
	KeyId       string
	Data        string
	Salt        string
	Hash        string
}

// Equals tests if two phc instances describe the exact same configuration.
func (phc *Argon2PHC) Equals(other *Argon2PHC) bool {
	return phc.Variant == other.Variant &&
		phc.Memory == other.Memory &&
		phc.Iterations == other.Iterations &&
		phc.Parallelism == other.Parallelism &&
		phc.KeyId == other.KeyId &&
		phc.Data == other.Data &&
		phc.Salt == other.Salt &&
		phc.Hash == other.Hash
}

// ValidateParameters verifies that the parameters used are valid for argon2.
func (phc *Argon2PHC) ValidateParameters() error {
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
	if base64Err := validateBase64Len(phc.KeyId); base64Err != nil {
		return base64Err
	}
	if base64Err := validateBase64Len(phc.Data); base64Err != nil {
		return base64Err
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
	write, writeErr := fmt.Fprintf(w, "$%s$m=%d,t=%d,p=%d",
		phc.Variant, phc.Memory, phc.Iterations, phc.Parallelism)
	res += write
	if writeErr != nil {
		return res, writeErr
	}
	if phc.KeyId != "" {
		write, writeErr = fmt.Fprintf(w, ",keyid=%s", phc.KeyId)
		res += write
		if writeErr != nil {
			return res, writeErr
		}
	}
	if phc.Data != "" {
		write, writeErr = fmt.Fprintf(w, ",data=%s", phc.Data)
		res += write
		if writeErr != nil {
			return res, writeErr
		}
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
	memory, memoryErr := strconv.Atoi(match[2])
	if memoryErr != nil {
		return nil, memoryErr
	}
	iterations, iterationsErr := strconv.Atoi(match[3])
	if iterationsErr != nil {
		return nil, iterationsErr
	}
	parallelism, parallelismErr := strconv.Atoi(match[4])
	if parallelismErr != nil {
		return nil, parallelismErr
	}
	keyID, data := match[5], match[6]
	salt, hash := match[7], match[8]
	res := Argon2PHC{
		Variant:     variant,
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		KeyId:       keyID,
		Data:        data,
		Salt:        salt,
		Hash:        hash,
	}
	return &res, nil
}
