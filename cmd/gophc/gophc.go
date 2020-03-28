package main

import (
	"fmt"
	"github.com/FabianWe/gophc"
)

func process(s string) {
	fmt.Println("Processing", s)
	represents, decodeErr := gophc.Base64Decode([]byte(s))
	if decodeErr != nil {
		panic(decodeErr)
	}
	fmt.Printf("In encodes: len=%d, array=%v\n", len(represents), represents)
	encoded := gophc.Base64Encode(represents)
	fmt.Println("Encoding back to (string):", string(encoded))
}

func main() {
	// should be invalid
	inValid := "Hj5+dsK0ZQA"
	fmt.Println("================")
	process(inValid)

	//fmt.Println("==================")
	//process("Hj5+dsK0ZR")
	process("Hj5+dsK0ZQB")
}
