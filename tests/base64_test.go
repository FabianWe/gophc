package tests

import (
	"bytes"
	"github.com/FabianWe/gophc"
	"testing"
)

func TestBase64Encode(t *testing.T) {
	// tests: complete groups (len % 3 == 0)
	// and also mod 3 == 1 and 2
	// also tests different trailing bits
	tests := []struct {
		in       []byte
		expected string
	}{
		{
			nil,
			"",
		},
		{
			[]byte{136, 116, 131, 60, 124, 212, 132, 252, 202, 238, 176, 156, 38, 3, 133, 126},
			"iHSDPHzUhPzK7rCcJgOFfg",
		},
		{
			[]byte{7, 5, 32, 36, 113, 208, 107, 41, 196, 249, 174, 39, 102, 182, 17, 204, 233, 101, 25, 40, 227, 198, 236, 77, 95, 28, 141, 69, 75, 72, 232, 57, 112, 255, 57, 91, 183, 163, 243, 56, 191, 14, 157, 250, 172, 233, 55, 6},
			"BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
		},
		{
			[]byte{177, 25, 71, 133, 25, 138, 80, 108, 221, 58, 101, 231, 211, 85, 230, 95, 40, 29, 228, 167},
			"sRlHhRmKUGzdOmXn01XmXygd5Kc",
		},
		{
			[]byte{225, 245, 215, 27, 75, 41, 7, 221, 150, 60, 29, 77, 138, 212, 252, 252, 225, 244, 84, 162},
			"4fXXG0spB92WPB1NitT8/OH0VKI",
		},
		{
			[]byte{30, 62, 126, 118, 194, 180, 101, 0},
			"Hj5+dsK0ZQA",
		},
	}

	for _, tc := range tests {
		encoded := string(gophc.Base64Encode(tc.in))
		if encoded != tc.expected {
			t.Errorf("base64 encoding error for input %v: Expected %s, got %s",
				tc.in, tc.expected, encoded)
		}

	}
}

var base64DecodingTests = []struct {
	in       string
	expected []byte
	strict   bool
}{
	{
		"",
		nil,
		true,
	},
	{
		"iHSDPHzUhPzK7rCcJgOFfg",
		[]byte{136, 116, 131, 60, 124, 212, 132, 252, 202, 238, 176, 156, 38, 3, 133, 126},
		true,
	},
	{
		"BwUgJHHQaynE+a4nZrYRzOllGSjjxuxNXxyNRUtI6Dlw/zlbt6PzOL8Onfqs6TcG",
		[]byte{7, 5, 32, 36, 113, 208, 107, 41, 196, 249, 174, 39, 102, 182, 17, 204, 233, 101, 25, 40, 227, 198, 236, 77, 95, 28, 141, 69, 75, 72, 232, 57, 112, 255, 57, 91, 183, 163, 243, 56, 191, 14, 157, 250, 172, 233, 55, 6},
		true,
	},
	{
		"sRlHhRmKUGzdOmXn01XmXygd5Kc",
		[]byte{177, 25, 71, 133, 25, 138, 80, 108, 221, 58, 101, 231, 211, 85, 230, 95, 40, 29, 228, 167},
		true,
	},
	{
		"4fXXG0spB92WPB1NitT8/OH0VKI",
		[]byte{225, 245, 215, 27, 75, 41, 7, 221, 150, 60, 29, 77, 138, 212, 252, 252, 225, 244, 84, 162},
		true,
	},
	// two invalid ones (they have unprocessed bits that are not zero)
	{
		"Hj5+dsK0ZR",
		[]byte{30, 62, 126, 118, 194, 180, 101},
		false,
	},
	{
		"Hj5+dsK0ZQB",
		[]byte{30, 62, 126, 118, 194, 180, 101, 0},
		false,
	},
}

func TestBase64Decode(t *testing.T) {
	for _, tc := range base64DecodingTests {
		decoded, decodeErr := gophc.Base64Decode([]byte(tc.in))
		if tc.strict {
			// should process without errors
			if decodeErr != nil {
				t.Errorf("unexpected error decoding base64 string: input \"%s\", error was %v",
					tc.in, decodeErr)
				continue
			}
			// now test if we got expected
			if !bytes.Equal(decoded, tc.expected) {
				t.Errorf("base64 decoding failed for input \"%s\": expected %v, got %v",
					tc.in, tc.expected, decoded)
			}
		} else {
			// should give an error
			if decodeErr == nil {
				t.Errorf("base64 decoding should fail in strict mode for input \"%s\", but got %v as result",
					tc.in, decoded)
			}
		}
	}
}

func TestBase64DecodeNotStrict(t *testing.T) {
	for _, tc := range base64DecodingTests {
		// should not fail on any of the inputs
		decoded, decodeErr := gophc.Base64DecodeNotStrict([]byte(tc.in))
		if decodeErr != nil {
			t.Errorf("unexpected error decoding base64 (not strict): input \"%s\", error was %v",
				tc.in, decodeErr)
			continue
		}
		if !bytes.Equal(decoded, tc.expected) {
			t.Errorf("base64 decoding (not strict) failed for input \"%s\": expected %v, got %v",
				tc.in, tc.expected, decoded)
		}
	}
}
