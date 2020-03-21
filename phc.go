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
	"strings"
	"unicode"
)

type PHCParameterDescription struct {
	Param string
	MaxLength int
	Default string
}

func (pd *PHCParameterDescription) IsOptional() bool {
	return len(pd.Default) > 0
}

type PHCDescription struct {
	Function string
	Parameters []*PHCParameterDescription
}

type PHCParameterValuePair struct {
	Parameter, Value string
}

type PHC struct {
	Function string
	Parameters []*PHCParameterValuePair
	Salt, Hash string
}

type PHCError string

func NewPHCError(message string, a ...interface{}) PHCError {
	return PHCError(fmt.Sprintf(message, a...))
}

func (err PHCError) Error() string {
	return string(err)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func alphanumericOrDigit(r byte) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func isValidValueByte(r byte) bool {
	return alphanumericOrDigit(r) || r == '/' || r == '+' || r == '.' || r == '-'
}


func isValidValue(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !isValidValueByte(b) {
			return false
		}
	}
	return true
}

func isValidSaltChar(r byte) bool {
	return alphanumericOrDigit(r) || r == '/' || r == '+' || r == '.' || r == '-'
}

func isValidSalt(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !isValidSaltChar(b) {
			return false
		}
	}
	return true
}

func isValidBase64Char(r byte) bool {
	return alphanumericOrDigit(r) || r == '+' || r == '/'
}

func IsValidBase64String(s string) bool {
	// check for mod 4: not allowed to be 1
	if len(s) % 4 == 1 {
		return false
	}
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !isValidBase64Char(b) {
			return false
		}
	}
	return true
}

func assertDollar(input string) (consumed int, has bool) {
	if strings.HasPrefix(input, "$") {
		consumed = 1
		has = true
	}
	return
}

func readFunction(input, function string) (consumed int, has bool) {
	if strings.HasPrefix(input, function) {
		has = true
		consumed = len(function)
	}
	return
}

func readParameter(input, parameter string) (consumed int, has bool) {
	if !strings.HasPrefix(input, parameter) {
		return
	}
	paramLen := len(parameter)
	input = input[paramLen:]
	if !strings.HasPrefix(input, "=") {
		return
	}
	consumed = paramLen + 1
	has = true
	return
}

func readParameterValuePairs(input string, descriptions []*PHCParameterDescription) (res []*PHCParameterValuePair, consumed int, hasParameters bool, err error) {
	// set to true by default
	hasParameters = true
	// find the parameters end, this is either $ or end of string
	parametersEnd := strings.IndexRune(input, '$')
	if parametersEnd < 0 {
		parametersEnd = len(input)
	}
	// now all parameters must be in input[:parameterEnd]
	relevantString := input[:parametersEnd]
	fmt.Printf("Caled with \"%s\", relevant substring is \"%s\"\n", input, relevantString)
	// split on comma
	split := strings.Split(relevantString, ",")
	// if split consists of only one element and this does not contain an = sign there is no parameter part
	if len(split) == 1 && strings.IndexRune(split[0], '=') < 0 {
		consumed = 0
		split = nil
		hasParameters = false
	} else {
		consumed = len(relevantString)
	}
	// if there are too many parameter/value pairs that's an error
	if len(split) > len(descriptions) {
		consumed = 0
		err = NewPHCError("found %d parameters, expected at most %d",
			len(split), len(descriptions))
		return
	}
	// now we must match each parameter description
	nextEntryIndex := 0
	nextParamIndex := 0
	res = make([]*PHCParameterValuePair, 0, len(descriptions))
	for nextEntryIndex < len(split) && nextParamIndex < len(descriptions) {
		nextEntry := split[nextEntryIndex]
		nextDescription := descriptions[nextParamIndex]
		// now try to match them
		paramConsumed, isParam := readParameter(nextEntry, nextDescription.Param)
		if isParam {
			// if it is the parameter we can add it
			value := nextEntry[paramConsumed:]
			if !isValidValue(value) {
				res = nil
				err = NewPHCError("value for parameter %s (%s) is invalid",
					nextDescription.Param, value)
				consumed = 0
				return
			}
			// it is valid ==> add it
			pair := &PHCParameterValuePair{
				Parameter: nextDescription.Param,
				Value:     value,
			}
			res = append(res, pair)
			// entry was consumed
			nextEntryIndex++
		} else {
			// if it is another parameter this parameter must be optional, otherwise there is an error
			if !nextDescription.IsOptional() {
				res = nil
				consumed = 0
				err = NewPHCError("expected parameter %s but instead got %s",
					nextDescription.Param, nextEntry)
				return
			}
			// it is optional, add to result
			pair := &PHCParameterValuePair{
				Parameter: nextDescription.Param,
				Value: "",
			}
			res = append(res, pair)
		}
		nextParamIndex++
	}

	if nextEntryIndex < len(split) {
		res = nil
		err =  NewPHCError("got additional (invalid parameters) in input string")
		consumed = 0
		return
	}


	if nextParamIndex < len(descriptions) {
		// all remaining parameters must be optional
		for ; nextParamIndex < len(descriptions); nextParamIndex++ {
			next := descriptions[nextParamIndex]
			if !next.IsOptional() {
				res = nil
				err = NewPHCError("required parameter %s not found", next.Param)
				consumed = 0
				return
			}
			// optional, append to res
			pair := &PHCParameterValuePair{
				Parameter: next.Param,
				Value:     "",
			}
			res = append(res, pair)
		}
	}

	if len(res) != len(descriptions) {
		res = nil
		err = NewPHCError("internal error: not matched all parameter descriptions with input! BUG")
		consumed = 0
		return
	}

	return
}

func (desc *PHCDescription) Parse(input string) (*PHC, error) {
	if !isASCII(input) {
		return nil, NewPHCError("input string contains non ascii-characters. Input was %s", input)
	}
	// now we can simply work on the string (bytes) because each byte is exactly one rune
	original := input
	// make sure that only ascii characters are in the string
	index := 0
	// these variables are frequently used later
	// consumed: how many bytes did a command consume?
	// has: used to signal if a dollar sign (or whatever) has been found by a command

	consumed := 0
	has := false

	consume := func() {
		index += consumed
		input = input[consumed:]
	}

	// this function can be called whenever a function consumes something, i.e. a new value has been assigned
	// it will increase the index as well as move forward in the input string

	// first expect a $ sign
	consumed, has = assertDollar(input)
	if !has {
		return nil, NewPHCError("expected $ sign at beginning of string, got %s", original)
	}
	consume()
	// next we must parse the identifier (function)
	consumed, has = readFunction(input, desc.Function)
	if !has {
		return nil, NewPHCError("expected function name %s on position %d in input string %s",
			desc.Function, index, original)
	}
	consume()
	res := &PHC{
		Function: desc.Function,
		Parameters: make([]*PHCParameterValuePair, 0, len(desc.Parameters)),
	}
	// next consume all parameters (if any)
	// first test if there the string is empty now, this means all parameters must be optional (error otherwise)
	if len(input) == 0 {
		// no parameters in input, they must all be optional in the description
		for _, parameterDesc := range desc.Parameters {
			if !parameterDesc.IsOptional() {
				return nil, NewPHCError("expected parameter %s to be contained in input string %s",
					parameterDesc.Param, original)
			}
			// parameter is optional, append to result
			pair := &PHCParameterValuePair{
				Parameter: parameterDesc.Param,
				Value: "",
			}
			res.Parameters = append(res.Parameters, pair)
		}
		// are parameters are optional, return
		return res, nil
	}
	// consume dollar sign
	consumed, has = assertDollar(input)
	if !has {
		return nil, NewPHCError("expected $ sign at beginning parameters (position %d) in %s",
			index, original)
	}
	consume()
	// now parse all parameters
	// they must appear exactly in the order as in the description
	pairs, paramsConsumed, hasParameters, paramsErr := readParameterValuePairs(input, desc.Parameters)
	if paramsErr != nil {
		return nil, paramsErr
	} else {
		res.Parameters = pairs
		consumed = paramsConsumed
		consume()
	}
	if len(input) == 0 {
		if !hasParameters {
			return nil, NewPHCError("Expected parameters or salt after $, string ended here in %s", original)
		}
		return res, nil
	}
	// the remainder must be starting with a $ sign if parameters were found
	// if no parameters have been found the $ sign was already consumed
	if hasParameters {
		consumed, has = assertDollar(input)
		if !has {
			return nil, NewPHCError("expected $ sign at beginning of hash (position %d) in %s",
				index, original)
		}
		consume()
	}

	// just split the remainder, at most one dollar is allowed now
	dollarSplit := strings.Split(input, "$")
	if len(dollarSplit) == 0 {
		return nil, NewPHCError("salt string is empty in %s", original)
	}
	if len(dollarSplit) > 2 {
		return nil, NewPHCError("too many parts (separated by $) in %s", original)
	}

	salt := dollarSplit[0]
	if !isValidSalt(salt) {
		return nil, NewPHCError("invalid salt string in %s", original)
	}

	hash := ""
	if len(dollarSplit) == 2 {
		hash = dollarSplit[1]
		if !IsValidBase64String(hash) {
			return nil, NewPHCError("invalid base64 encoded hash in %s", original)
		}
	}

	res.Salt = salt
	res.Hash = hash
	return res, nil
}
