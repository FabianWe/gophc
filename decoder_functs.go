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
	"strconv"
	"strings"
)

var (
	NonMinimalDecimalEncoding = errors.New("not the minimal decimal encoding")
)

func decodeDecimalStringStrict(s string, bitSize int) (int64, error) {
	// first check if s starts with 0, this is only allowed if it does not contain any other characters
	if strings.HasPrefix(s, "0") {
		if len(s) > 1 {
			return -1, fmt.Errorf("too many leading zeroes: %w", NonMinimalDecimalEncoding)
		}
		return 0, nil
	}
	// next check if there is a '-' sign
	// in this case the second character is not allowed to be a 0 or another -
	if strings.HasPrefix(s, "-") {
		switch {
		case len(s) == 1:
			return -1, errors.New("invalid decimal encoding: consists only of '-'")
		case strings.HasPrefix(s[1:], "0"):
			return -1, fmt.Errorf("if string starts with '-' it is not allowed to contain zeroes immediately after '-', got \"%s\": %w", s, NonMinimalDecimalEncoding)
		default:
			return strconv.ParseInt(s, 10, bitSize)
		}
	}
	return strconv.ParseInt(s, 10, bitSize)
}

func DecodeDecimalString(s string, strict bool, bitSize int) (int64, error) {
	if strict {
		return decodeDecimalStringStrict(s, bitSize)
	}
	return strconv.ParseInt(s, 10, bitSize)
}

func decodeUnsignedStringStrict(s string, bitSize int) (uint64, error) {
	// nearly the same as decodeDecimalStringStrict
	if strings.HasPrefix(s, "0") {
		if len(s) > 1 {
			return 0, fmt.Errorf("too many leading zeroes: %w", NonMinimalDecimalEncoding)
		}
		return 0, nil
	}
	// next check if there is a '-' sign
	// in this case the second character is not allowed to be a 0 or another -
	if strings.HasPrefix(s, "-") {
		switch {
		case len(s) == 1:
			return 0, errors.New("invalid decimal encoding: consists only of '-'")
		case strings.HasPrefix(s[1:], "0"):
			return 0, fmt.Errorf("if string starts with '-' it is not allowed to contain zeroes immediately after '-', got \"%s\": %w", s, NonMinimalDecimalEncoding)
		default:
			return strconv.ParseUint(s, 10, bitSize)
		}
	}
	return strconv.ParseUint(s, 10, bitSize)
}

func DecodeUnsignedString(s string, strict bool, bitSize int) (uint64, error) {
	if strict {
		return decodeUnsignedStringStrict(s, bitSize)
	}
	return strconv.ParseUint(s, 10, bitSize)
}
