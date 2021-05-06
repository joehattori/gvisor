package p9

// JOETODO: move this file out from package p9.

import (
	"fmt"
	"io/ioutil"

	"github.com/bytecodealliance/wasmtime-go"
	"gvisor.dev/gvisor/pkg/log"
)

var rustfer struct {
	instance *wasmtime.Instance
	memory   *wasmtime.Memory
}

func initWasm() error {
	log.Infof("initWasm called!")
	wasmFile := "/rustfer/rustfer.wasm"

	engine := wasmtime.NewEngine()
	store := wasmtime.NewStore(engine)
	linker := wasmtime.NewLinker(store)
	wasiConfig := wasmtime.NewWasiConfig()
	wasiConfig.InheritStderr()
	wasiConfig.InheritStdout()
	if err := wasiConfig.PreopenDir(".", "."); err != nil {
		return err
	}
	if err := wasiConfig.PreopenDir("/", "/"); err != nil {
		return err
	}

	wasi, err := wasmtime.NewWasiInstance(store, wasiConfig, "wasi_snapshot_preview1")
	if err != nil {
		return err
	}

	if err = linker.DefineWasi(wasi); err != nil {
		return err
	}

	module, err := wasmtime.NewModuleFromFile(store.Engine, wasmFile)
	if err != nil {
		return err
	}
	instance, err := linker.Instantiate(module)
	if err != nil {
		return err
	}

	rustfer.instance = instance
	rustfer.memory = instance.GetExport("memory").Memory()
	log.Infof("Wasm rustfer initialization done")

	nom := instance.GetExport("_start").Func()
	_, err = nom.Call()
	return err
}

const (
	tlopen = iota
)

func callWasmFunc(typ int) error {
	if rustfer.instance == nil {
		if err := initWasm(); err != nil {
			return err
		}
		if err := rustferInit(); err != nil {
			return err
		}
	}
	log.Infof("callWasmFunc called!")
	switch typ {
	case tlopen:
	}
	nom := rustfer.instance.GetExport("healthcheck").Func()
	ret, err := nom.Call()
	if err != nil {
		log.Infof("Wasm healthcheck error: %v", err)
		return err
	}
	log.Infof("Wasm healthcheck ret: %v", ret)
	return nil
}

func rustferInit() error {
	rustferInit := rustfer.instance.GetExport("rustfer_init").Func()
	arrPtr, err := arrayAlloc([]int8{9, 10, 11, 12})
	if err != nil {
		return err
	}
	confBytes, err := ioutil.ReadFile("./config/conf.json")
	if err != nil {
		return fmt.Errorf("rustferInit: reading conf.json failed: %v", err)
	}
	confPtr, err := bytesAlloc(confBytes)
	if err != nil {
		return fmt.Errorf("rustferInit: byte allocation failed: %v", err)
	}
	if _, err = rustferInit.Call(int32(4), arrPtr, 0, 0, confPtr); err != nil {
		return fmt.Errorf("rustfer_init failed: %v", err)
	}
	return nil
}

func arrayAlloc(arr []int8) (ptr int32, err error) {
	alloc := rustfer.instance.GetExport("rustfer_allocate").Func()
	ret, err := alloc.Call(len(arr))
	if err != nil {
		return
	}
	ptr = ret.(int32)
	mem := rustfer.memory.UnsafeData()
	for i, b := range arr {
		mem[ptr+int32(i)] = byte(b)
	}
	return
}

func bytesAlloc(bytes []byte) (ptr int32, err error) {
	alloc := rustfer.instance.GetExport("rustfer_allocate").Func()
	ret, err := alloc.Call(len(bytes))
	if err != nil {
		return
	}
	ptr = ret.(int32)
	mem := rustfer.memory.UnsafeData()
	for i, b := range bytes {
		mem[ptr+int32(i)] = b
	}
	return
}
