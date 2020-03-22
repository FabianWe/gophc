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
	"github.com/FabianWe/gophc"
	"testing"
)

func TestScryptEncode(t *testing.T) {
	tests := []struct {
		phc *gophc.ScryptPHC
		expected string
	}{
		{
			&gophc.ScryptPHC{
				Cost:        15,
				BlockSize:   8,
				Parallelism: 1,
				Salt:        "D/EEcdfcBkj4DQB3zlfsFQ",
				Hash:        "v9Xsag5AySIY78DFKslBzeRXCUfsLKCZ0Xm4Xwoh+J0",
			},
			"$scrypt$ln=15,r=8,p=1$D/EEcdfcBkj4DQB3zlfsFQ$v9Xsag5AySIY78DFKslBzeRXCUfsLKCZ0Xm4Xwoh+J0",
		},
		{
			&gophc.ScryptPHC{
				Cost:        20,
				BlockSize:   16,
				Parallelism: 2,
				Salt:        "abcdef",
				Hash:        "ghijkl",
			},
			"$scrypt$ln=20,r=16,p=2$abcdef$ghijkl",
		},
	}
	for _, tc := range tests {
		encoded, err := tc.phc.EncodeString()
		if err != nil {
			t.Errorf("Expected no error while encoding phc, got error %v instead", err)
			continue
		}
		if encoded != tc.expected {
			t.Errorf("Expected encoding to be \"%s\", got \"%s\" instead",
				tc.expected, encoded)
		}
	}
}

func TestScryptDecode(t *testing.T) {
	tests := []struct {
		in string
		expected *gophc.ScryptPHC
	}{
		{
			"$scrypt$ln=15,r=8,p=1$D/EEcdfcBkj4DQB3zlfsFQ$v9Xsag5AySIY78DFKslBzeRXCUfsLKCZ0Xm4Xwoh+J0",
			&gophc.ScryptPHC{
				Cost:        15,
				BlockSize:   8,
				Parallelism: 1,
				Salt:        "D/EEcdfcBkj4DQB3zlfsFQ",
				Hash:        "v9Xsag5AySIY78DFKslBzeRXCUfsLKCZ0Xm4Xwoh+J0",
			},
		},
		{
			"$scrypt$ln=20,r=16,p=2$abcdef$ghijkl",
			&gophc.ScryptPHC{
				Cost:        20,
				BlockSize:   16,
				Parallelism: 2,
				Salt:        "abcdef",
				Hash:        "ghijkl",
			},
		},
	}
	for _, tc := range tests {
		got, err := gophc.DecodeScryptPHC(tc.in)
		if err != nil {
			t.Errorf("Expected no decoding error for scrypt phc \"%s\", got %v", tc.in, err)
			continue
		}
		if !tc.expected.Equals(got) {
			t.Errorf("For input string \"%s\" expected %v, got %v", tc.in, tc.expected, got)
		}
	}
}
