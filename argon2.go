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

type Argon2PHC struct {
	Variant string
	Memory int
	Iterations int
	Parallelism int
	KeyId string
	Data string
	Salt string
	Hash string
}

const argon2PHCRegexString = `^\$(argon2id|argon2i|argon2d)` + // variant
	`\$m=` + phcPositiveDecimalRegexString + `,t=` + phcPositiveDecimalRegexString +
	`,p=` + phcPositiveDecimalRegexString + // required parameters
	`(?:,keyid=(` + base64String + `))?` + // optional keyid
	`(?:,data=(` + base64String + `))?` +
	`\$(` + base64String + `)` + // salt
	`\$(` + base64String + `)$` // hash

var argon2PHCRx = regexp.MustCompile(argon2PHCRegexString)

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
	write, writeErr = fmt.Fprintf(w, "$%s$%s", phc.Salt, phc.Hash)
	res += write
	if writeErr != nil {
		return res, writeErr
	}
	return res, nil
}

func (phc *Argon2PHC) EncodeString() (string, error) {
	var builder strings.Builder
	_, err := phc.Encode(&builder)
	if err != nil {
		return "", err
	}
	return builder.String(), nil
}

func DecodeArgon2PHC(input string) (*Argon2PHC, error) {
	fmt.Println(argon2PHCRegexString)
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
