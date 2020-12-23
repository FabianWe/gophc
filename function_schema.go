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

var (
	ErrNonOptionalParameterMissing = errors.New("non optional parameter is missing")
	ErrParameterValueValidation    = errors.New("validation of parameter failed")
	ErrMismatchedFunctionName      = errors.New("invalid function name")
	ErrUnmatchedParameterName      = errors.New("unmatched parameter parsed")
)

type parameterValueErrorWrapper struct {
	parameterName string
	err           error
}

func (err parameterValueErrorWrapper) Error() string {
	return fmt.Sprintf("validation of parameter \"%s\" failed: %s", err.parameterName, err.err.Error())
}

func (err parameterValueErrorWrapper) Unwrap() error {
	return err.err
}

func (err parameterValueErrorWrapper) Is(target error) bool {
	return target == ErrParameterValueValidation
}

type ValueValidatorFunc func(value string) error

func ValueCharacterValidator(value string) error {
	if onlyValidRunes, invalidRune := validateRuneFunc(isValidParameterValueRune, value); !onlyValidRunes {
		return fmt.Errorf("parameter value contains invalid character \"%s\": %w", string(invalidRune), ErrInvalidParameterValue)
	}
	return nil
}

type PHCParameterDescription struct {
	Name          string
	Default       string
	Optional      bool
	ValidateValue ValueValidatorFunc
}

func (description *PHCParameterDescription) GetValueValidatorFunc() ValueValidatorFunc {
	if description.ValidateValue == nil {
		return ValueCharacterValidator
	}
	return description.ValidateValue
}

type PHCSchema struct {
	FunctionName          string
	ParameterDescriptions []*PHCParameterDescription
}

// parseParameter parses a parameter from a string of the form "name=value".
// Note that no validation is done on name and value, they could for example be empty or contain
// illegal characters.
func parseParameter(s string) (ParameterValuePair, error) {
	res := ParameterValuePair{}
	index := strings.IndexRune(s, '=')
	if index < 0 {
		return res, NewPHCError(fmt.Sprintf("parameter \"%s\"", s), ErrMissingParameterValue)
	}
	name, value := s[:index], s[index+1:]
	res.IsSet = true
	res.Name = name
	res.Value = value
	return res, nil
}

func parseParameters(s string) ([]ParameterValuePair, error) {
	// split on ','
	split := strings.Split(s, ",")
	res := make([]ParameterValuePair, len(split))
	for i, subString := range split {
		nextPair, pairErr := parseParameter(subString)
		if pairErr != nil {
			return nil, pairErr
		}
		res[i] = nextPair
	}
	return res, nil
}

// TODO: check if PHCError is used correctly everywhere
func (schema PHCSchema) matchParameters(parsedParameters []ParameterValuePair) ([]ParameterValuePair, error) {
	descriptionIndex, parsedIndex := 0, 0
	n, m := len(schema.ParameterDescriptions), len(parsedParameters)
	res := make([]ParameterValuePair, n)
	for descriptionIndex < n && parsedIndex < m {
		nextDescription := schema.ParameterDescriptions[descriptionIndex]
		nextParsed := parsedParameters[parsedIndex]
		// now we expect the next description
		// if it is not this parameter name, we have to check if the next description
		// is optional, if yes we only continue in the descriptions, but not the parsed
		if nextDescription.Name == nextParsed.Name {
			// in case of a match: validate the value
			validatorFunc := nextDescription.GetValueValidatorFunc()
			if validationErr := validatorFunc(nextParsed.Value); validationErr != nil {
				wrappedErr := parameterValueErrorWrapper{
					parameterName: nextDescription.Name,
					err:           validationErr,
				}
				return nil, NewPHCError("value validation failed", wrappedErr)
			}
			// add to result
			// parsed parameter always have IsSet = true
			res[descriptionIndex] = nextParsed
			// continue in both
			descriptionIndex++
			parsedIndex++
		} else {
			// now next description must be optional
			if !nextDescription.Optional {
				return nil, NewPHCError(fmt.Sprintf("parameter \"%s\"", nextDescription.Name), ErrNonOptionalParameterMissing)
			}
			// add it with the default
			entry := ParameterValuePair{
				Name:  nextDescription.Name,
				Value: nextDescription.Default,
				IsSet: false,
			}
			res[descriptionIndex] = entry
			descriptionIndex++
		}
	}
	// now there might still be additional parsed / descriptions (but not both)
	// if parsed parameters are left: return an error (too many parameters)
	if parsedIndex < m {
		nextParsed := parsedParameters[parsedIndex]
		return nil, NewPHCError(fmt.Sprintf("parameter \"%s\"", nextParsed.Name), ErrUnmatchedParameterName)
	}
	for ; descriptionIndex < n; descriptionIndex++ {
		nextDescription := schema.ParameterDescriptions[descriptionIndex]
		// now next description must be optional
		if !nextDescription.Optional {
			return nil, NewPHCError(fmt.Sprintf("parameter \"%s\"", nextDescription.Name), ErrNonOptionalParameterMissing)
		}
		// add it with the default
		entry := ParameterValuePair{
			Name:  nextDescription.Name,
			Value: nextDescription.Default,
			IsSet: false,
		}
		res[descriptionIndex] = entry
	}
	return res, nil
}

func (schema PHCSchema) Decode(s string) (PHCInstance, error) {
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
	// here we also verify that none of the sub-strings is empty
	// we don't need this in phc.go because parsing of the parameters works a bit differently in there
	for _, sub := range split {
		if sub == "" {
			return res, newInvalidPHCStructureError("found two consecutive '$' in string")
		}
	}

	if functionName := split[0]; functionName != schema.FunctionName {
		return res, NewPHCError(fmt.Sprintf("expected function name \"%s\"", schema.FunctionName), ErrMismatchedFunctionName)
	}

	res.Function = schema.FunctionName

	split = split[1:]
	// now split might be empty, so we still want to check the parameters
	var parsedParameters []ParameterValuePair
	// we don't have to check for empty string here, we already did that
	// if string contains '=' it is a parameter string, otherwise it is not and should be parsed
	// as hash / salt
	if len(split) > 0 && strings.ContainsRune(split[0], '=') {
		var parametersParseError error
		parsedParameters, parametersParseError = parseParameters(split[0])
		if parametersParseError != nil {
			return res, parametersParseError
		}
		split = split[1:]
	}
	// now match the parsed parameters against the description
	finalParams, matchErr := schema.matchParameters(parsedParameters)
	if matchErr != nil {
		return res, matchErr
	}
	res.Parameters = finalParams
	// now parse salt / hash (if given)

	return res, nil
}
