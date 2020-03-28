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
	"encoding/base64"
)

// base64 provides the internal base64 encoding / decoding.
// The base64 encoding / decoding is inspired by https://github.com/golang/crypto/blob/master/bcrypt/base64.go

// DefaultAlphabet is the alphabet used for phc.
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var bcEncoding = base64.NewEncoding(alphabet).WithPadding(base64.NoPadding).Strict()

// Base64Encode encodes the source to base64 using the alphabet.
func Base64Encode(src []byte) []byte {
	encodeLen := bcEncoding.EncodedLen(len(src))
	dst := make([]byte, encodeLen)
	bcEncoding.Encode(dst, src)
	return dst[:encodeLen]
}

// Base64Decode decodes the source using the alphabet.
func Base64Decode(src []byte) ([]byte, error) {
	dst := make([]byte, bcEncoding.DecodedLen(len(src)))
	n, err := bcEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}
