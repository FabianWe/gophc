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

const defaultArgon2Version uint32 = 0x10 // 1.0 (16)

var Argon2Versions = []uint32{
	0x10, // 1.0 (16)
	0x13, // 1.3 (19)
}

func isValidArgon2Version(v uint32) bool {
	for _, candidate := range Argon2Versions {
		if candidate == v {
			return true
		}
	}
	return false
}

func formatValidArgon2VersionStrings() string {
	var buffer strings.Builder
	buffer.WriteRune('[')
	// each version is matched to: the value with base 10 and base 8 (hex)
	// example: 19 (0x13)
	first := true
	for _, v := range Argon2Versions {
		if first {
			first = false
		} else {
			buffer.WriteString(", ")
		}
		// ignore write errors (there are non for builder)
		_, _ = fmt.Fprintf(&buffer, "%d (0x%x)", v, v)
	}
	buffer.WriteRune(']')
	return buffer.String()
}

var Argon2Variants = []string{
	"argon2id",
	"argon2i",
	"argon2d",
}

func isValidArgon2Variant(v string) bool {
	for _, candidate := range Argon2Variants {
		if candidate == v {
			return true
		}
	}
	return false
}

var (
	ErrInvalidArgon2Version = errors.New("invalid argon2 version")
)

type Argon2PHC struct {
	Variant string
	Version uint32
	M       uint32
	T       uint32
	P       uint8
}

func (phc *Argon2PHC) ValidateParameters() error {
	if !isValidArgon2Variant(phc.Variant) {
		return NewMismatchedFunctionNameError(phc.Variant, Argon2Variants...)
	}
	if !isValidArgon2Version(phc.Version) {
		errMsg := "argon 2version must be in " + formatValidArgon2VersionStrings() + " got " + strconv.FormatUint(uint64(phc.Version), 10)
		return wrapParameterValueErrorToPHCError(errMsg, "v", ErrInvalidArgon2Version)
	}
	if phc.M < 1 {
		return wrapParameterValueErrorToPHCError("must be > 0", "m", nil)
	}
	if phc.T < 1 {
		return wrapParameterValueErrorToPHCError("must be > 0", "t", nil)
	}
	if phc.P < 1 {
		return wrapParameterValueErrorToPHCError("must be > 0", "p", nil)
	}
	return nil
}

var Argon2Schema = &PHCSchema{
	FunctionNames: Argon2Variants,
	ParameterDescriptions: []*PHCParameterDescription{
		{
			Name:          "v",
			Default:       strconv.FormatUint(uint64(defaultArgon2Version), 10),
			Optional:      true,
			ValidateValue: NoValueValidator,
		},
		{
			Name:          "m",
			Default:       "",
			Optional:      false,
			ValidateValue: NoValueValidator,
		},
		{
			Name:          "t",
			Default:       "",
			Optional:      false,
			ValidateValue: NoValueValidator,
		},
		{
			Name:          "p",
			Default:       "",
			Optional:      false,
			ValidateValue: NoValueValidator,
		},
	},
	Decoder: DefaultBase64,
}

func argon2FromStringParams(variant string, versionParam, mParam, tParam, pParam ParameterValuePair, salt, hash []byte, saltString, hashString string) (*Argon2PHC, error) {
	if !isValidArgon2Variant(variant) {
		return nil, NewMismatchedFunctionNameError(variant, Argon2Variants...)
	}

	var version, m, t uint32
	var p uint8

	if version64, versionErr := decodeNoneZeroUnsignedString(versionParam.Value, false, 32); versionErr == nil {
		version = uint32(version64)
	} else {
		return nil, wrapParameterValueErrorToPHCError("can't parse as integer", versionParam.Name, versionErr)
	}

	if m64, mErr := decodeNoneZeroUnsignedString(mParam.Value, false, 32); mErr == nil {
		m = uint32(m64)
	} else {
		return nil, wrapParameterValueErrorToPHCError("can't parse as integer", mParam.Name, mErr)
	}

	if t64, tErr := decodeNoneZeroUnsignedString(tParam.Value, false, 32); tErr == nil {
		t = uint32(t64)
	} else {
		return nil, wrapParameterValueErrorToPHCError("can't parse as integer", tParam.Name, tErr)
	}

	if p64, pErr := decodeNoneZeroUnsignedString(pParam.Value, false, 8); pErr == nil {
		p = uint8(p64)
	} else {
		return nil, wrapParameterValueErrorToPHCError("can't parse as integer", pParam.Name, pErr)
	}

	res := &Argon2PHC{
		Variant: variant,
		Version: version,
		M:       m,
		T:       t,
		P:       p,
	}
	return res, nil
}

func DecodeArgon2(phcString string) (*Argon2PHC, error) {
	instance, err := Argon2Schema.Decode(phcString)
	if err != nil {
		return nil, err
	}
	// just an assertion, should never happen
	if len(instance.Parameters) != 4 {
		return nil, fmt.Errorf("internal error: expected exactly threeparameters, got %d instead", len(instance.Parameters))
	}
	vParam := instance.Parameters[0]
	mParam := instance.Parameters[1]
	tParam := instance.Parameters[2]
	pParam := instance.Parameters[3]
	variant := instance.Function
	return argon2FromStringParams(
		variant, vParam, mParam, tParam, pParam, instance.Salt, instance.Hash,
		instance.SaltString, instance.HashString)
}
