package main

import (
	"fmt"
	"github.com/FabianWe/gophc"
)

func main() {
	in := "Hj5+dsK0ZR"
	asBytes := gophc.Base64Encode([]byte(in))
	fmt.Println(len(asBytes))
	fmt.Println(asBytes)
	// decode
	decoded, decodeErr := gophc.Base64Decode(asBytes)
	if decodeErr != nil {
		panic(decodeErr)
	}
	decodedString := string(decoded)
	fmt.Println(decodedString)
}
