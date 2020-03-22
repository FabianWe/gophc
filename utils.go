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
)

const base64Char = `[A-Za-z0-9+/]`
const base64String = base64Char + `+`

const phcDecimalRegexString = `(0|-[1-9]\d*|[1-9]\d*)`
const phcDecimalRegex = `^` + phcDecimalRegexString + `$`

var phcDecimalRx = regexp.MustCompile(phcDecimalRegex)

const phcPositiveDecimalRegexString = `(0|[1-9]\d*)`
const phcPositiveDecimalRegex = `^` + phcPositiveDecimalRegexString + `$`

var phcPositiveDecimalRx = regexp.MustCompile(phcPositiveDecimalRegex)

const maxInt = int(^uint(0) >> 1)

const argon2MaxSize uint64 = 4294967295

func ParsePHCDecimal(input string) (int, error) {
	match := phcDecimalRx.FindStringSubmatch(input)
	if len(match) == 0 {
		return 0, fmt.Errorf("input \"%s\" isn't a valid decimal", input)
	}
	return strconv.Atoi(match[1])
}

func ParsePHCPositiveDecimal(input string) (int, error) {
	match := phcPositiveDecimalRx.FindStringSubmatch(input)
	if len(match) == 0 {
		return 0, fmt.Errorf("input \"%s\" isn't a valid positive decimal", input)
	}
	return strconv.Atoi(match[1])
}

func writeSaltAndHash(w io.Writer, salt, hash string) (int, error) {
	if salt == "" {
		// no need to write salt, but hash is not allowed to be not empty
		if hash != "" {
			return 0, errors.New("got empty salt but non-empty hash, this is not allowed")
		}
		return 0, nil
	}
	// write salt
	res := 0
	write, err := fmt.Fprint(w, "$", salt)
	res += write
	if err != nil {
		return res, err
	}
	// write hash if required
	if hash != "" {
		write, err = fmt.Fprint(w, "$", hash)
		res += write
	}
	return res, err
}
