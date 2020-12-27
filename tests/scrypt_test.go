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

var dummy *gophc.ScryptPHC

const full = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q$nFNh2CVHVjNldFVKDHDlm4CbdRSCdEBsjjJxD+iCs5E"
const onlySalt = "$scrypt$ln=16,r=8,p=1$aM15713r3Xsvxbi31lqr1Q"
const onlyParams = "$scrypt$ln=16,r=8,p=1"

func BenchmarkNormalFull(b *testing.B) {
	var r *gophc.ScryptPHC
	var err error
	for n := 0; n < b.N; n++ {
		r, err = gophc.DecodeScrypt(full)
		if err != nil {
			b.Errorf("error running test: %s", err.Error())
		}
	}
	dummy = r
}

func BenchmarkNormalSalt(b *testing.B) {
	var r *gophc.ScryptPHC
	var err error
	for n := 0; n < b.N; n++ {
		r, err = gophc.DecodeScrypt(onlySalt)
		if err != nil {
			b.Errorf("error running test: %s", err.Error())
		}
	}
	dummy = r
}

func BenchmarkNormalParams(b *testing.B) {
	var r *gophc.ScryptPHC
	var err error
	for n := 0; n < b.N; n++ {
		r, err = gophc.DecodeScrypt(onlyParams)
		if err != nil {
			b.Errorf("error running test: %s", err.Error())
		}
	}
	dummy = r
}
