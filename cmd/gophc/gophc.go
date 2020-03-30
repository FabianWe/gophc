package main

import (
	"fmt"
	"github.com/FabianWe/gophc"
	"os"
	"strings"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, "usage: %s <hsah>\n", os.Args[0])
	os.Exit(1)
}

func main() {
	if len(os.Args) == 1 {
		printUsage()
	}
	phcStr := os.Args[1]
	switch {
	case strings.HasSuffix(phcStr, "$scrypt"):
		scryptPhc, err := gophc.DecodeScryptPHC(phcStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Can't decode input \"%s\", got error %v\n", phcStr, err)
			os.Exit(1)
		}
		fmt.Printf("Decoded the following scrypt conf: %#v\n", scryptPhc)

	case strings.HasSuffix(phcStr, "$argon2"):
	default:
		fmt.Fprintf(os.Stderr, "error: hash must be either a scrypt or argon2 phc encoded string, got \"%s\"\n",
			phcStr)
		printUsage()
	}
}
