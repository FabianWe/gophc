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
	"strings"
)

func validateRuneFunc(f func(r rune) bool, s string) (bool, rune) {
	for _, r := range s {
		if !f(r) {
			return false, r
		}
	}
	return true, 0
}

func isValidFuncNameRune(r rune) bool {
	return ('a' <= r && r <= 'z') || ('0' <= r && r <= '9') || r == '-'
}

type ParameterValuePair struct {
	Name  string
	Value string
	IsSet bool
}

type PHCInstance struct {
	Function   string
	Salt       []byte
	SaltString string
	Hash       []byte
	HashString string
	Parameters []ParameterValuePair
}

type PHCError struct {
	Message    string
	WrappedErr error
}

func NewPHCError(message string, wrapped error) *PHCError {
	return &PHCError{
		Message:    message,
		WrappedErr: wrapped,
	}
}

func (err *PHCError) Error() string {
	if err.WrappedErr == nil {
		return fmt.Sprintf("invalid phc format: %s", err.Message)
	} else {
		return fmt.Sprintf("invalid phc format: %s: %s", err.Message, err.WrappedErr.Error())
	}
}

func (err *PHCError) Unwrap() error {
	return err.WrappedErr
}

var (
	ErrInvalidPHCStructure         = errors.New("invalid phc syntax")
	ErrInvalidFunctionName         = errors.New("function name must contain 1 to 32 characters in [a-z0-9-]")
	ErrNonOptionalParameterMissing = errors.New("non optional parameter is missing")
)

func newInvalidPHCStructureError(message string) error {
	return NewPHCError(message, ErrInvalidPHCStructure)
}

func newInvalidFunctionNameRuneError(invalidName string, invalidRune rune) error {
	return NewPHCError(fmt.Sprintf("invalid function name \"%s\", found character \"%s\"", invalidName,
		string(invalidRune)), ErrInvalidFunctionName)
}

func newInvalidFunctionLengthError(invalidName string) error {
	return NewPHCError(fmt.Sprintf("invalid function name \"%s\", length=%d", invalidName, len(invalidName)), ErrInvalidFunctionName)
}

func newNonOptionalParameterMissingError(parameterName string) error {
	return NewPHCError(fmt.Sprintf("parameter \"%s\"", parameterName), ErrNonOptionalParameterMissing)
}

type PHCParameterDescription struct {
	Name     string
	Default  string
	Optional bool
}

type PHCParser struct {
	MinFunctionNameLength, MaxFunctionNameLength int
}

func NewPHCParser() *PHCParser {
	return &PHCParser{
		MinFunctionNameLength: 1,
		MaxFunctionNameLength: 32,
	}
}

func (parser *PHCParser) validateFunctionName(name string) error {
	if onlyValidRunes, invalidRune := validateRuneFunc(isValidFuncNameRune, name); !onlyValidRunes {
		return newInvalidFunctionNameRuneError(name, invalidRune)
	}
	// use len here, we only have ascii characters now
	nameLength := len(name)
	// if min length is given test also the length of the string against it
	if parser.MinFunctionNameLength >= 0 && nameLength < parser.MinFunctionNameLength {
		return newInvalidFunctionLengthError(name)
	}
	if parser.MaxFunctionNameLength >= 0 && nameLength > parser.MaxFunctionNameLength {
		return newInvalidFunctionLengthError(name)
	}
	// everything ok
	return nil
}

func (parser *PHCParser) ParsePHCString(s string) (PHCInstance, error) {
	res := PHCInstance{}
	if !strings.HasPrefix(s, "$") {
		return res, newInvalidPHCStructureError("phc string must begin with \"$\"")
	}
	// advance string by 1
	s = s[1:]

	// find next $ (if there is any) to find the end of the name
	var functionName string
	index := strings.IndexRune(s, '$')
	if index < 0 {
		functionName = s
		s = ""
	} else {
		functionName = s[:index]
		s = s[index+1:]
	}

	if functionNameErr := parser.validateFunctionName(functionName); functionNameErr != nil {
		return res, functionNameErr
	}
	res.Function = functionName

	// now the function name is valid, continue to parse the optional parameters
	if s == "" {
		return res, nil
	}
	// note that now we have either the parameters OR the optional salt / hash part directly
	// the phc standard says:
	// "If the function expects no parameter at all, or all parameters are optional and their value happens to match
	// the default, then the complete list, including its starting $ sign, is omitted. Note that the = sign may appear
	// within the complete string only as part of a list of parameters."
	// so if there is a = inside the remaining string we must parse the parameters, otherwise we parse salt / hash
	// directly
	// to simplify the logic we split this into its own function
	return parser.parseParametersOrSaltAndHash(s, res)
}

func (parser *PHCParser) parseParametersOrSaltAndHash(s string, instance PHCInstance) (PHCInstance, error) {
	var err error
	s, instance, err = parser.parseParameters(s, instance)
	if err != nil {
		return instance, err
	}
	// now with the parameters out of the way we can parse the hash and salt
	return instance, nil
}

func (parser *PHCParser) parseParameters(s string, instance PHCInstance) (string, PHCInstance, error) {
	// if there is no '=' in s there are no parameters present
	// in this case we don't have to parse any parameters
	if !strings.ContainsRune(s, '=') {
		return s, instance, nil
	}

	// TODO
	index := strings.IndexRune(s, '$')
	if index < 0 {
		index = len(s)
		s = ""
	} else {
		s = s[index+1:]
	}

	return s, instance, nil
}
