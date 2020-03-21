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

	argon2 := gophc.Argon2PHC{
		Variant:     "argon2id",
		Memory:      4096,
		Iterations:  3,
		Parallelism: 1,
		KeyId:       "",
		Data:        "",
		Salt:        "PcEZHj1maR/+ZQynyJHWZg",
		Hash:        "2jEN4xcww7CYp1jakZB1rxbYsZ55XH2HgjYRtdZtubI",
	}
	s2, argonErr := argon2.EncodeString()
	if argonErr != nil {
		panic(argonErr)
	}
	fmt.Println(s2)

	argonDecoded, argonDecodeErr := gophc.DecodeArgon2PHC(s2)
	if argonDecodeErr != nil {
		panic(argonDecodeErr)
	}
	fmt.Println(argonDecoded)

}
