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

type Base64Encoder interface {
	Base64Encode(src []byte) []byte
}

type Base64Decoder interface {
	Base64Decode(src []byte) ([]byte, error)
}

// base64 provides the internal base64 encoding / decoding.
// The base64 encoding / decoding is inspired by https://github.com/golang/crypto/blob/master/bcrypt/base64.go

// DefaultAlphabet is the alphabet used for phc.
const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

var nonStrictEncoding = base64.NewEncoding(alphabet).WithPadding(base64.NoPadding)
var strictEncoding = nonStrictEncoding.Strict()

// Base64Encode encodes the source to base64 using the alphabet.
func Base64Encode(src []byte) []byte {
	encodeLen := strictEncoding.EncodedLen(len(src))
	dst := make([]byte, encodeLen)
	strictEncoding.Encode(dst, src)
	return dst[:encodeLen]
}

func base64DecodeFromEncoding(enc *base64.Encoding, src []byte) ([]byte, error) {
	dst := make([]byte, enc.DecodedLen(len(src)))
	n, err := enc.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

// Base64Decode decodes the source using the alphabet.
func Base64Decode(src []byte) ([]byte, error) {
	return base64DecodeFromEncoding(strictEncoding, src)
}

// Base64DecodeNotStrict decodes the source using the alphabet.
//
// In contrast to Base64Decode this method also allows non-zero trailing padding bits.
func Base64DecodeNotStrict(src []byte) ([]byte, error) {
	return base64DecodeFromEncoding(nonStrictEncoding, src)
}

type DefaultBase64Handler struct {
	Strict bool
}

func NewDefaultBase64Handler(strict bool) DefaultBase64Handler {
	return DefaultBase64Handler{Strict: strict}
}

func (h DefaultBase64Handler) Base64Encode(src []byte) []byte {
	return Base64Encode(src)
}

func (h DefaultBase64Handler) Base64Decode(src []byte) ([]byte, error) {
	if h.Strict {
		return Base64Decode(src)
	}
	return Base64DecodeNotStrict(src)
}

var DefaultBase64 = NewDefaultBase64Handler(true)
