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
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const scryptPHCRegexString = `\$scrypt\$ln=(\d+),r=(\d+),p=(\d+)` + // prefix + options
	`\$(` + base64String + `)` + // salt
	`\$(` + base64String + `)` // hash

var scryptPHCRx = regexp.MustCompile(scryptPHCRegexString)

type ScryptPHC struct {
	Cost int
	BlockSize int
	Parallelism int
	Salt string
	Hash string
}

func (phc *ScryptPHC) Encode(w io.Writer) (int, error) {
	return fmt.Fprintf(w, "$scrypt$ln=%d,r=%d,p=%d$%s$%s", phc.Cost, phc.BlockSize, phc.Parallelism,
		phc.Salt, phc.Hash)
}

func (phc *ScryptPHC) EncodeString() (string, error) {
	var builder strings.Builder
	_, err := phc.Encode(&builder)
	if err != nil {
		return "", err
	}
	return builder.String(), nil
}

func DecodeScryptPHC(input string) (*ScryptPHC, error) {
	match := scryptPHCRx.FindStringSubmatch(input)
	if len(match) == 0 {
		// error
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
