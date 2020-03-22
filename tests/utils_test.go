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

package tests

import (
	"errors"
	"github.com/FabianWe/gophc"
	"testing"
)

func TestParsePHCDecimal(t *testing.T) {
	// we only test if err is nil or not
	someErr := errors.New("some dummy error")
	tests := []struct{
		in string
		expected int
		expectedErr error
	}{
		{"0", 0, nil},
		{"1", 1, nil},
		{"-1", -1, nil},
		{"4242", 4242, nil},
		{"-2121", -2121, nil},
		{"-0", 0, someErr},
		{"01", 0, someErr},
		{"001", 0, someErr},
		{"--42", 0, someErr},
		{"foo", 0, someErr},
		{"123bar", 0, someErr},
	}
	for _, tc := range tests {
		got, gotErr := gophc.ParsePHCDecimal(tc.in)
		if tc.expectedErr == nil && gotErr != nil {
			t.Errorf("Expected no error for input %s, but got error %v", tc.in, gotErr)
			continue
		}
		if tc.expectedErr != nil && gotErr == nil {
			t.Errorf("Expected error for input %s, got nil instead", tc.in)
			continue
		}
		if tc.expected != got {
			t.Errorf("Expected output %d for input \"%s\", got %d instead",
				tc.expected, tc.in, got)
		}
	}
}

func TestParsePHCPositiveDecimal(t *testing.T) {
	// we only test if err is nil or not
	someErr := errors.New("some dummy error")
	tests := []struct{
		in string
		expected int
		expectedErr error
	}{
		{"0", 0, nil},
		{"1", 1, nil},
		{"-1", 0, someErr},
		{"4242", 4242, nil},
		{"-2121", 0, someErr},
		{"-0", 0, someErr},
		{"01", 0, someErr},
		{"001", 0, someErr},
		{"--42", 0, someErr},
		{"foo", 0, someErr},
		{"123bar", 0, someErr},
	}
	for _, tc := range tests {
		got, gotErr := gophc.ParsePHCPositiveDecimal(tc.in)
		if tc.expectedErr == nil && gotErr != nil {
			t.Errorf("Expected no error for input %s, but got error %v", tc.in, gotErr)
			continue
		}
		if tc.expectedErr != nil && gotErr == nil {
			t.Errorf("Expected error for input %s, got nil instead", tc.in)
			continue
		}
		if tc.expected != got {
			t.Errorf("Expected output %d for input \"%s\", got %d instead",
				tc.expected, tc.in, got)
		}
	}
}
