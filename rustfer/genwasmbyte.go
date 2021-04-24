package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/wasmerio/wasmer-go/wasmer"
)

func main() {
	hw := []byte{72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 2, 38}
	s := fmt.Sprintf("%v", hw)
	s = strings.ReplaceAll(s, " ", ", ")
	fmt.Println(s)
	fmt.Println(hw)
	fmt.Println(string(hw))
	hw2 := []byte("Hello World&")
	fmt.Println(hw2)

	wasmBytes, err := ioutil.ReadFile("target/wasm32-wasi/release/rustfer.wasm")
	engine := wasmer.NewEngine()
	store := wasmer.NewStore(engine)
	module, err := wasmer.NewModule(store, wasmBytes)
	check(err)
	bytes, err := module.Serialize()
	check(err)
	fmt.Println(len(bytes))
	bytesStr := fmt.Sprintf("%v", bytes)
	bytesStr = strings.ReplaceAll(bytesStr, " ", ", ")

	wasmFile, err := os.Create("../runsc/wasm/wasm.go")
	check(err)
	defer wasmFile.Close()
	prelude := "package container\n\nvar wasmBytes = [...]byte{"
	_, err = wasmFile.WriteString(prelude)
	check(err)
	_, err = wasmFile.WriteString(bytesStr[1 : len(bytesStr)-1])
	check(err)
	postlude := "}"
	_, err = wasmFile.WriteString(postlude)
	check(err)
	fmt.Println("Successfully constructed runsc/wasm/wasm.go!")
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
