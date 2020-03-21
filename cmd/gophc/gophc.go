package main

import (
	"fmt"
	"github.com/FabianWe/gophc"
)

func main() {
	//paramDescription := []*gophc.PHCParameterDescription{
	//	{
	//		Param: "abc",
	//		MaxLength: -1,
	//	},
	//	{
	//		Param: "xyz",
	//		MaxLength: -1,
	//		Default: "b",
	//	},
	//}
	//description := gophc.PHCDescription{
	//	Function:   "scrypt",
	//	Parameters: paramDescription,
	//}
	//res, err := description.Parse("$scrypt$abc=12$123$gh")
	//if err != nil {
	//	panic(err)
	//}
	//fmt.Println("Function:", res.Function)
	//fmt.Println("Parameters:")
	//for _, param := range res.Parameters {
	//	fmt.Printf("  - %s = %s\n", param.Parameter, param.Value)
	//}
	//fmt.Println("Salt:", res.Salt)
	//fmt.Println("Hash:", res.Hash)
	scrypt := gophc.ScryptPHC{
		Cost:        15,
		BlockSize:   8,
		Parallelism: 1,
		Salt:        "D/EEcdfcBkj4DQB3zlfsFQ",
		Hash:        "v9Xsag5AySIY78DFKslBzeRXCUfsLKCZ0Xm4Xwoh+J0",
	}
	s, err := scrypt.EncodeString()
	if err != nil {
		panic(err)
	}
	fmt.Println(s)

	decoded, decodeErr := gophc.DecodeScryptPHC(s)
	if decodeErr != nil {
		panic(decodeErr)
	}
	fmt.Println(*decoded)
}
