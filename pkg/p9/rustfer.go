package p9

// JOETODO: move this file out from package p9.

import (
	"github.com/bytecodealliance/wasmtime-go"
	"gvisor.dev/gvisor/pkg/log"
)

var rustfer *wasmtime.Instance

func initWasm() {
	log.Infof("initWasm called!")
	stdoutPath := "/tmp/runsc/stdout.log"
	wasmFile := "/rustfer/rustfer.wasm"
	check := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)
	linker := wasmtime.NewLinker(store)
	wasiConfig := wasmtime.NewWasiConfig()
	wasiConfig.SetStdoutFile(stdoutPath)

	wasi, err := wasmtime.NewWasiInstance(store, wasiConfig, "wasi_snapshot_preview1")
	check(err)

	err = linker.DefineWasi(wasi)
	check(err)

	module, err := wasmtime.NewModuleFromFile(store.Engine, wasmFile)
	check(err)
	instance, err := linker.Instantiate(module)
	check(err)

	rustfer = instance
	log.Infof("Wasm rustfer initialization done")
}

func callWasmFunc() {
	if rustfer == nil {
		initWasm()
	}
	log.Infof("callWasmFunc called!")
}
