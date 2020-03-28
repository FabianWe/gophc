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

func TestArgon2Encode(t *testing.T) {
	tests := []struct {
		phc      *gophc.Argon2PHC
		expected string
	}{
		{
			&gophc.Argon2PHC{
				Variant:     "argon2i",
				Version:     16,
				Memory:      120,
				Iterations:  5000,
				Parallelism: 2,
				KeyId:       "",
				Data:        "",
				Salt:        "4fXXG0spB92WPB1NitT8/OH0VKI",
				Hash:        "BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
			},
			"$argon2i$v=16,m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
		},
		{
			&gophc.Argon2PHC{
				Variant:     "argon2id",
				Version:     19,
				Memory:      120,
				Iterations:  5000,
				Parallelism: 2,
				KeyId:       "",
				Data:        "",
				Salt:        "/LtFjH5rVL8",
				Hash:        "",
			},
			"$argon2id$v=19,m=120,t=5000,p=2$/LtFjH5rVL8",
		},
		{
			&gophc.Argon2PHC{
				Variant:     "argon2i",
				Version:     19,
				Memory:      120,
				Iterations:  5000,
				Parallelism: 2,
				KeyId:       "Hj5+dsK0",
				Data:        "sRlHhRmKUGzdOmXn01XmXygd5Kc",
				Salt:        "4fXXG0spB92WPB1NitT8/OH0VKI",
				Hash:        "iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
			},
			"$argon2i$v=19,m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
		},
	}
	for _, tc := range tests {
		got, err := tc.phc.EncodeString()
		if err != nil {
			t.Errorf("Expected no error while encoding phc, got error %v instead", err)
			continue
		}
		if got != tc.expected {
			t.Errorf("Expected encoding to be \"%s\", got \"%s\" instead",
				tc.expected, got)
		}
	}
}

func TestArgon2Decode(t *testing.T) {
	tests := []struct {
		in       string
		expected *gophc.Argon2PHC
	}{
		{
			"$argon2i$v=19,m=120,t=5000,p=2$4fXXG0spB92WPB1NitT8/OH0VKI$BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
			&gophc.Argon2PHC{
				Variant:     "argon2i",
				Version:     19,
				Memory:      120,
				Iterations:  5000,
				Parallelism: 2,
				KeyId:       "",
				Data:        "",
				Salt:        "4fXXG0spB92WPB1NitT8/OH0VKI",
				Hash:        "BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
			},
		},
		{
			"$argon2id$m=120,t=5000,p=2$/LtFjH5rVL8",
			&gophc.Argon2PHC{
				Variant: "argon2id",
				// should use default version
				Version:     16,
				Memory:      120,
				Iterations:  5000,
				Parallelism: 2,
				KeyId:       "",
				Data:        "",
				Salt:        "/LtFjH5rVL8",
				Hash:        "",
			},
		},
		{
			"$argon2i$v=19,m=120,t=5000,p=2,keyid=Hj5+dsK0,data=sRlHhRmKUGzdOmXn01XmXygd5Kc$4fXXG0spB92WPB1NitT8/OH0VKI$iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
			&gophc.Argon2PHC{
				Variant:     "argon2i",
				Version:     19,
				Memory:      120,
				Iterations:  5000,
				Parallelism: 2,
				KeyId:       "Hj5+dsK0",
				Data:        "sRlHhRmKUGzdOmXn01XmXygd5Kc",
				Salt:        "4fXXG0spB92WPB1NitT8/OH0VKI",
				Hash:        "iPBVuORECm5biUsjq33hn9/7BKqy9aPWKhFfK2haEsM",
			},
		},
	}
	for _, tc := range tests {
		got, err := gophc.DecodeArgon2PHC(tc.in)
		if err != nil {
			t.Errorf("Expected no decoding error for argon2 phc \"%s\", got %v", tc.in, err)
			continue
		}
		if !tc.expected.Equals(got) {
			t.Errorf("For input string \"%s\" expected %v, got %v", tc.in, tc.expected, got)
		}
	}
}

//func base64Argon2TestSingle(s string) (string, error) {
//	if s == "" {
//		return s, nil
//	}
//	decoded, decodeErr := gophc.Base64Decode([]byte(s))
//	if decodeErr != nil {
//		return "", decodeErr
//	}
//	// encode back
//	return string(gophc.Base64Encode(decoded)), nil
//}
//
//// decodes the base64 parts, encodes the returned bytes and returns new instance
//func base64Argon2Test(instance *gophc.Argon2PHC) (*gophc.Argon2PHC, error) {
//	keyID, keyIDErr := base64Argon2TestSingle(instance.KeyId)
//	if keyIDErr != nil {
//		return nil, keyIDErr
//	}
//	data, dataErr := base64Argon2TestSingle(instance.Data)
//	if dataErr != nil {
//		return nil, dataErr
//	}
//	salt, saltErr := base64Argon2TestSingle(instance.Salt)
//	if saltErr != nil {
//		return nil, saltErr
//	}
//	hash, hashErr := base64Argon2TestSingle(instance.Hash)
//	if hashErr != nil {
//		return nil, hashErr
//	}
//
//	newInstance := gophc.Argon2PHC{
//		Variant:     instance.Variant,
//		Memory:      instance.Memory,
//		Iterations:  instance.Iterations,
//		Parallelism: instance.Parallelism,
//		KeyId:       keyID,
//		Data:        data,
//		Salt:        salt,
//		Hash:        hash,
//	}
//	return &newInstance, nil
//}
//
//func decodeEncodeTest(tc string) (string, error) {
//	decoded, decodeErr := gophc.DecodeArgon2PHC(tc)
//	if decodeErr != nil {
//		return "", decodeErr
//	}
//	if validateErr := decoded.ValidateParameters(); validateErr != nil {
//		return "", validateErr
//	}
//	// convert new phc back to string
//	withBase64, base64Err := base64Argon2Test(decoded)
//	if base64Err != nil {
//		return "", base64Err
//	}
//	if validateErr := withBase64.ValidateParameters(); validateErr != nil {
//		return "", validateErr
//	}
//	encoded, encodeErr := withBase64.EncodeString()
//	if encodeErr != nil {
//		return "", encodeErr
//	}
//	return encoded, nil
//}
//
//func TestArgon2KatGood(t *testing.T) {
//	for _, tc := range katGood {
//		got, err := decodeEncodeTest(tc)
//		if err != nil {
//			t.Errorf("Error for input \"%s\": %v", tc, err)
//			continue
//		}
//		if got != tc {
//			t.Errorf("Validation error: Decode/encode difference for \"%s\", got \"%s\"",
//				tc, got)
//		}
//	}
//}
//
//func TestArgon2KatBad(t *testing.T) {
//	for _, tc := range katBad {
//		got, err := decodeEncodeTest(tc)
//		if err == nil {
//			t.Errorf("Expected error for \"%s\", but got \"%s\" as a result",
//				tc, got)
//		}
//	}
//}
