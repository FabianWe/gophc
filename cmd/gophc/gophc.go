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

	hashStr := "4fXXG0spB92WPB1NitT8/OH0VKI"
	decoded, err := gophc.Base64Decode([]byte(hashStr))
	if err != nil {
		panic(err)
	}
	fmt.Println(decoded)
	encoded := gophc.Base64Encode(decoded)
	fmt.Println(string(encoded))
}
