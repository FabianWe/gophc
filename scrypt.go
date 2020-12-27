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
	"math"
	"strconv"
)

type ScryptPHC struct {
	// The cost parameter N
	Cost int
	// Block size parameter r
	BlockSize int
	// The parallelism parameter p
	Parallelism int
	Salt        []byte
	SaltString  string
	Hash        []byte
	HashString  string
}

func (phc *ScryptPHC) ValidateParameters() error {
	cost := phc.Cost
	r := phc.BlockSize
	p := phc.Parallelism
	// exactly the same as in go scrypt package: https://github.com/golang/crypto/blob/eec23a3978ad/scrypt/scrypt.gos
	if cost <= 1 || cost&(cost-1) != 0 {
		return wrapParameterValueErrorToPHCError("must be > 1 and a power of 2", "N", nil)
	}
	// check some limits
	if r < 1 || uint64(r) > uint64(math.MaxUint32) {
		return wrapParameterValueErrorToPHCError(fmt.Sprintf("must be between 1 <= r <= %d, got %d", uint64(math.MaxUint32), r),
			"r", nil)
	}
	if p < 1 {
		return wrapParameterValueErrorToPHCError("must be >= 1", "p", nil)
	}
	if uint64(r)*uint64(p) >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || cost > maxInt/128/r {
		return wrapMultipleParametersValueErrorToPHCError("parameters are too large", nil,
			"N", "p", "r")
	}

	return nil
}

var ScryptPHCSchema *PHCSchema = &PHCSchema{
	FunctionNames: []string{"scrypt"},
	ParameterDescriptions: []*PHCParameterDescription{
		{
			Name:          "ln",
			Default:       "",
			Optional:      false,
			ValidateValue: NoValueValidator,
		},
		{
			Name:          "r",
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

func scryptFromStringParams(lnParam, rParam, pParam ParameterValuePair, salt, hash []byte, saltString, hashString string) (*ScryptPHC, error) {
	ln, lnErr := strconv.Atoi(lnParam.Value)
	if lnErr != nil {
		return nil, wrapParameterValueErrorToPHCError("can't parse as integer", lnParam.Name, lnErr)
	}
	if ln <= 0 {
		return nil, wrapParameterValueErrorToPHCError("must be positive", lnParam.Name, nil)
	}
	// now compute N (cost)
	// this is 2^ln
	// compute 2^ln and check if result is <= 0 (overflow)
	cost := 1 << ln
	// check for overflow here, cost should always be <= 0 for overflow, we're just extra careful
	if ln > (strconv.IntSize-2) || cost <= 0 {
		return nil, wrapParameterValueErrorToPHCError(fmt.Sprintf("parameter overflows int: 2^(%d) is not a valid int (int size %d)", ln, strconv.IntSize),
			lnParam.Name,
			nil)
	}
	// parse block size r
	r, rErr := strconv.Atoi(rParam.Value)
	if rErr != nil {
		return nil, wrapParameterValueErrorToPHCError("can't parse as integer", rParam.Name, rErr)
	}

	p, pErr := strconv.Atoi(pParam.Value)
	if pErr != nil {
		return nil, wrapParameterValueErrorToPHCError("can't parse as integer", pParam.Name, pErr)
	}

	res := &ScryptPHC{
		Cost:        cost,
		BlockSize:   r,
		Parallelism: p,
		Salt:        salt,
		SaltString:  saltString,
		Hash:        hash,
		HashString:  hashString,
	}

	return res, nil
}

func DecodeScrypt(phcString string) (*ScryptPHC, error) {
	instance, err := ScryptPHCSchema.Decode(phcString)
	if err != nil {
		return nil, err
	}
	// just an assertion, should never happen
	if len(instance.Parameters) != 3 {
		return nil, fmt.Errorf("internal error: expected exactly 3 variables, got %d instead", len(instance.Parameters))
	}
	lnParam := instance.Parameters[0]
	rParam := instance.Parameters[1]
	pParam := instance.Parameters[2]
	return scryptFromStringParams(lnParam, rParam, pParam, instance.Salt, instance.Hash, instance.SaltString, instance.HashString)
}
