package main

import (
	"io/ioutil"

	"github.com/bytecodealliance/wasmtime-go"
)

func main() {
	wasmFile := "target/wasm32-wasi/release/rustfer.wasm"

	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)
	module, _ := wasmtime.NewModuleFromFile(store.Engine, wasmFile)
	bytes, _ := module.Serialize()
	if err := ioutil.WriteFile("target/wasm32-wasi/release/rustfer.module", bytes, 0777); err != nil {
		panic(err)
	}
}
