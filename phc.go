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

func isValidParameterNameRune(r rune) bool {
	// actually the same
	return isValidFuncNameRune(r)
}

func isValidParameterValueRune(r rune) bool {
	return ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') || r == '/' || r == '+' || r == '.' || r == '-'
}

type ParameterValuePair struct {
	Name  string
	Value string
	IsSet bool
}

type PHCInstance struct {
	Function   string
	Parameters []ParameterValuePair
	Salt       []byte
	SaltString string
	Hash       []byte
	HashString string
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
	ErrInvalidPHCStructure   = errors.New("invalid phc syntax")
	ErrInvalidFunctionName   = errors.New("invalid function name")
	ErrInvalidParameterName  = errors.New("invalid parameter name")
	ErrInvalidParameterValue = errors.New("invalid parameter value")
	ErrMissingParameterValue = errors.New("no value for parameter given")
	ErrBase64Decode          = errors.New("error decoding base64")
)

func formatIntInterval(min, max int) string {
	switch {
	case min >= 0 && max >= 0:
		return fmt.Sprintf("[%d, %d]", min, max)
	case min >= 0:
		return fmt.Sprintf("[%d, ∞]", min)
	case max >= 0:
		return fmt.Sprintf("[0, %d]", max)
	default:
		// in this case there is no limit
		return "[0, ∞]"
	}
}

func newInvalidPHCStructureError(message string) error {
	return NewPHCError(message, ErrInvalidPHCStructure)
}

func newInvalidFunctionNameRuneError(invalidName string, invalidRune rune) error {
	return NewPHCError(fmt.Sprintf("function \"%s\" contains character \"%s\", only characters in [a-z0-9-] are allowed",
		invalidName, string(invalidRune)), ErrInvalidFunctionName)
}

func newInvalidFunctionLengthError(invalidName string, min, max int) error {
	return NewPHCError(fmt.Sprintf("function name \"%s\", length=%d has an invalid length: must be in %s",
		invalidName, len(invalidName), formatIntInterval(min, max)), ErrInvalidFunctionName)
}

func newInvalidParameterNameRuneError(invalidName string, invalidRune rune) error {
	return NewPHCError(fmt.Sprintf("parameter name \"%s\", contains character \"%s\", only characters in [a-z0-9-] are allowed",
		invalidName, string(invalidRune)), ErrInvalidParameterName)
}

func newInvalidParameterNameLengthError(invalidName string, min, max int) error {
	return NewPHCError(fmt.Sprintf("parameter name \"%s\", length=%d has an invalid length: must be in %s",
		invalidName, len(invalidName), formatIntInterval(min, max)), ErrInvalidParameterName)
}

func newInvalidParameterValueRuneError(invalidValue string, invalidRune rune) error {
	return NewPHCError(fmt.Sprintf("parameter value \"%s\", contains character \"%s\", only characters in [a-zA-Z0-9/+.-] are allowed",
		invalidValue, string(invalidRune)), ErrInvalidParameterValue)
}

func newInvalidParameterValueLengthError(invalidValue string, min, max int) error {
	return NewPHCError(fmt.Sprintf("parameter value \"%s\", length=%d has an invalid length: must be in %s",
		invalidValue, len(invalidValue), formatIntInterval(min, max)), ErrInvalidParameterValue)
}

type base64DecodeErrorWrapper struct {
	err error
}

func newBase64DecodeErrorWrapper(err error) base64DecodeErrorWrapper {
	return base64DecodeErrorWrapper{err}
}

func (err base64DecodeErrorWrapper) Error() string {
	return err.err.Error()
}

func (err base64DecodeErrorWrapper) Unwrap() error {
	return err.err
}

func (err base64DecodeErrorWrapper) Is(target error) bool {
	return target == ErrBase64Decode
}

type PHCParser struct {
	MinFunctionNameLength, MaxFunctionNameLength     int
	MinParameterNameLength, MaxParameterNameLength   int
	MinParameterValueLength, MaxParameterValueLength int
	Decoder                                          Base64Decoder
}

func NewPHCParser() *PHCParser {
	return &PHCParser{
		MinFunctionNameLength:   1,
		MaxFunctionNameLength:   32,
		MinParameterNameLength:  1,
		MaxParameterNameLength:  32,
		MinParameterValueLength: -1,
		MaxParameterValueLength: -1,
		Decoder:                 DefaultBase64,
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
		return newInvalidFunctionLengthError(name, parser.MinFunctionNameLength, parser.MaxFunctionNameLength)
	}
	if parser.MaxFunctionNameLength >= 0 && nameLength > parser.MaxFunctionNameLength {
		return newInvalidFunctionLengthError(name, parser.MinFunctionNameLength, parser.MaxFunctionNameLength)
	}
	// everything ok
	return nil
}

func (parser *PHCParser) validateParameter(name, value string) error {
	if onlyValidRunes, invalidRune := validateRuneFunc(isValidParameterNameRune, name); !onlyValidRunes {
		return newInvalidParameterNameRuneError(name, invalidRune)
	}
	// use len here, we only have ascii characters now
	nameLength := len(name)
	if parser.MinParameterNameLength >= 0 && nameLength < parser.MinParameterNameLength {
		return newInvalidParameterNameLengthError(name, parser.MinParameterNameLength, parser.MaxParameterNameLength)
	}
	if parser.MaxParameterNameLength >= 0 && nameLength > parser.MaxParameterNameLength {
		return newInvalidParameterNameLengthError(name, parser.MinParameterNameLength, parser.MaxParameterNameLength)
	}

	if onlyValidRunes, invalidRune := validateRuneFunc(isValidParameterValueRune, name); !onlyValidRunes {
		return newInvalidParameterValueRuneError(value, invalidRune)
	}
	valueLength := len(value)
	if parser.MinParameterValueLength >= 0 && valueLength < parser.MinParameterValueLength {
		return newInvalidParameterValueLengthError(value, parser.MinParameterValueLength, parser.MaxParameterValueLength)
	}
	if parser.MaxParameterValueLength >= 0 && valueLength > parser.MaxParameterValueLength {
		return newInvalidParameterValueLengthError(value, parser.MinParameterValueLength, parser.MaxParameterValueLength)
	}

	// everything ok
	return nil
}

func (parser *PHCParser) parseParameter(s string) (ParameterValuePair, error) {
	res := ParameterValuePair{}
	index := strings.IndexRune(s, '=')
	if index < 0 {
		err := NewPHCError(fmt.Sprintf("parameter \"%s\"", s), ErrMissingParameterValue)
		return res, err
	}
	// now validate name and value
	name := s[:index]
	value := s[index+1:]
	if validationErr := parser.validateParameter(name, value); validationErr != nil {
		return res, validationErr
	}
	res.IsSet = true
	res.Name = name
	res.Value = value
	return res, nil
}

func (parser *PHCParser) parseParameters(s string) ([]ParameterValuePair, error) {
	// split s on ','
	split := strings.Split(s, ",")
	res := make([]ParameterValuePair, len(split))
	for i, subString := range split {
		nextPair, pairErr := parser.parseParameter(subString)
		if pairErr != nil {
			return nil, pairErr
		}
		res[i] = nextPair
	}
	return res, nil
}

func (parser *PHCParser) decodeBase64(s string) ([]byte, error) {
	res, base64Err := parser.Decoder.Base64Decode([]byte(s))
	if base64Err != nil {
		return nil, newBase64DecodeErrorWrapper(base64Err)
	}
	return res, nil
}

func (parser *PHCParser) Parse(s string) (PHCInstance, error) {
	res := PHCInstance{}
	// split strings on "$" sign
	// the string must start with a "$", so we do that here already
	if !strings.HasPrefix(s, "$") {
		return res, newInvalidPHCStructureError("phc string must begin with \"$\"")
	}
	// advance s by 1
	s = s[1:]
	split := strings.Split(s, "$")
	// note that split is never empty
	functionName := split[0]
	if functionNameErr := parser.validateFunctionName(functionName); functionNameErr != nil {
		return res, functionNameErr
	}
	res.Function = functionName
	// advance split by one
	split = split[1:]
	if len(split) == 0 {
		// done parsing
		return res, nil
	}
	// now split[0] may contain the parameter description or salt / hash
	// if split[0] contains '=' it is a parameter description, from the phc description:
	// "If the function expects no parameter at all, or all parameters are optional and their value happens to match
	// the default, then the complete list, including its starting $ sign, is omitted. Note that the = sign may appear
	// within the complete string only as part of a list of parameters."
	if strings.ContainsRune(split[0], '=') {
		parameters, parametersErr := parser.parseParameters(split[0])
		if parametersErr != nil {
			return res, parametersErr
		}
		res.Parameters = parameters
		split = split[1:]
	}

	if len(split) == 0 {
		return res, nil
	}
	// now parse the salt
	salt := split[0]
	res.SaltString = salt
	saltDecoded, saltDecodeErr := parser.decodeBase64(salt)
	if saltDecodeErr != nil {
		return res, NewPHCError("error decoding salt from base64 string", saltDecodeErr)
	}
	res.Salt = saltDecoded
	split = split[1:]

	if len(split) == 0 {
		return res, nil
	}

	// now parse the hash
	hash := split[0]
	res.HashString = hash
	hashDecoded, hashErr := parser.decodeBase64(hash)
	if hashErr != nil {
		return res, NewPHCError("error decoding hash from base64", hashErr)
	}
	res.Hash = hashDecoded
	split = split[1:]

	// now everything is fine... but if we still have something left in the split result this means that something
	// is wrong in the syntax
	if len(split) != 0 {
		return res, NewPHCError("to many '$' in input string", ErrInvalidPHCStructure)
	}

	return res, nil
}
